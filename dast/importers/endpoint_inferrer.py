"""
AI-powered endpoint inferrer.

Takes a finding from the orchestrator-ai report (file path, title, description,
Stage 2 reasoning) and asks Claude to infer the live HTTP endpoint + an initial
attack request.

Output is an Endpoint object ready for the attack engine, plus an optional
seed AttackPayload derived from the Stage 2 analysis.

Design:
- The inferrer sends the full finding context to Claude.
- Claude returns structured JSON with endpoint URL, HTTP method, parameters
  (name, location, sample value), and a ready-to-send seed payload.
- If Claude cannot infer a concrete endpoint it returns a "not_inferable" flag
  and we skip that finding.
- Errors are logged and the finding is skipped (never crash the verify run).
"""

import json
from typing import Optional, Tuple

from dast.ai import bedrock_client
from dast.models import AttackPayload, Endpoint, EndpointParameter, HttpRequest
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SYSTEM = """\
You are an expert web application penetration tester.
You will receive a security finding from a SAST tool with:
- The vulnerable source file path and line number
- A description of the vulnerability (may include Stage 2 AI reasoning)
- The target application base URL

Your job is to infer the live HTTP endpoint that exercises the vulnerable code
and construct a concrete attack request.

Rules:
- Read the file path carefully: Rails mutations are in app/graphql/mutations/,
  controllers in app/controllers/, workers in app/workers/, lib/ is library code.
- GraphQL apps expose everything at POST /graphql. Use the file/class name to
  derive the operation name (e.g. update_course.rb → updateCourse mutation).
- For REST apps use the controller/action to build the URL path.
- If the vulnerability is in a library/worker/template with no direct HTTP
  entrypoint, trace the call chain described in the finding to the closest
  GraphQL mutation or controller action that reaches it.
- Prefer the concrete attack payload described in the Stage 2 reasoning if present.
- Return not_inferable only if there is truly no way to reach the vulnerability
  over HTTP (e.g. background job with no API trigger, secret leak in Terraform).

Respond ONLY with valid JSON. No markdown, no explanation outside JSON.
"""

_PROMPT_TEMPLATE = """\
Finding:
  Title: {title}
  Severity: {severity}
  Vulnerable file: {file}
  Line: {line}
  Attack type hint: {attack_type_hint}

Description / Stage 2 reasoning:
{description}

Target base URL: {base_url}

Infer the HTTP endpoint and build the attack request. Respond with:
{{
  "not_inferable": false,
  "reason": "",
  "endpoint": {{
    "url": "<full URL, e.g. https://app.example.com/graphql>",
    "method": "<GET|POST|PUT|PATCH|DELETE>",
    "content_type": "<application/json or application/x-www-form-urlencoded>",
    "parameters": [
      {{
        "name": "<param name or GraphQL variable name>",
        "location": "<body|query|header|path>",
        "sample_value": "<a benign sample value that exercises this code path>",
        "type": "<string|integer|boolean|object>"
      }}
    ]
  }},
  "seed_payload": {{
    "value": "<the attack payload string>",
    "injection_point": "<parameter name to inject into>",
    "injection_location": "<body|query|header|path>",
    "rationale": "<one sentence why this payload tests the vulnerability>"
  }},
  "graphql_operation": "<full GraphQL mutation or query string if applicable, else null>"
}}

If not inferable, set not_inferable to true, fill reason, and leave endpoint/seed_payload as null.
"""


def infer_endpoint(
    finding: dict,
    base_url: str,
) -> Tuple[Optional[Endpoint], Optional[AttackPayload]]:
    """
    Use AI to infer the HTTP endpoint and seed payload for a finding.

    Returns (endpoint, seed_payload) or (None, None) if not inferable.
    """
    prompt = _PROMPT_TEMPLATE.format(
        title=finding.get("title", ""),
        severity=finding.get("severity", ""),
        file=finding.get("file", ""),
        line=finding.get("line", ""),
        attack_type_hint=finding.get("attack_type_hint", "unknown"),
        description=(finding.get("description") or "")[:3000],
        base_url=base_url.rstrip("/"),
    )

    try:
        result = bedrock_client.invoke_json(
            system=_SYSTEM,
            user=prompt,
            max_tokens=1024,
        )
    except Exception as e:
        logger.error(
            "Endpoint inference failed",
            title=finding.get("title", "")[:60],
            error=str(e),
        )
        return None, None

    if result.get("not_inferable"):
        logger.info(
            "Finding not inferable as HTTP endpoint",
            title=finding.get("title", "")[:60],
            reason=result.get("reason", ""),
        )
        return None, None

    ep_data = result.get("endpoint")
    seed_data = result.get("seed_payload")
    graphql_op = result.get("graphql_operation")

    if not ep_data or not ep_data.get("url"):
        logger.warning(
            "Inference returned no endpoint URL",
            title=finding.get("title", "")[:60],
        )
        return None, None

    # Build parameters
    params = []
    for p in (ep_data.get("parameters") or []):
        params.append(EndpointParameter(
            name=str(p.get("name", "")),
            location=str(p.get("location", "body")),
            value=str(p.get("sample_value", "")),
            inferred_type=str(p.get("type", "string")),
        ))

    # Build sample request — include GraphQL operation body if present
    sample_body = _build_sample_body(ep_data, params, graphql_op)
    sample_req = HttpRequest(
        method=ep_data.get("method", "POST"),
        url=ep_data["url"],
        headers={"content-type": ep_data.get("content_type", "application/json")},
        body=sample_body,
    )

    endpoint = Endpoint(
        url=ep_data["url"],
        method=ep_data.get("method", "POST"),
        parameters=params,
        content_type=ep_data.get("content_type", "application/json"),
        sample_request=sample_req,
        discovered_via="sast_finding",
    )

    seed_payload = None
    if seed_data and seed_data.get("value"):
        seed_payload = AttackPayload(
            value=str(seed_data["value"]),
            attack_type=finding.get("attack_type_hint", "unknown"),
            injection_point=str(seed_data.get("injection_point", "")),
            injection_location=str(seed_data.get("injection_location", "body")),
            rationale=str(seed_data.get("rationale", "")),
        )

    logger.info(
        "Endpoint inferred",
        title=finding.get("title", "")[:60],
        url=endpoint.url,
        method=endpoint.method,
        params=len(params),
        has_seed=seed_payload is not None,
        graphql=bool(graphql_op),
    )

    return endpoint, seed_payload


def _build_sample_body(ep_data: dict, params: list, graphql_op: Optional[str]) -> Optional[str]:
    """Build a JSON body for the sample request."""
    method = ep_data.get("method", "POST")
    content_type = ep_data.get("content_type", "application/json")

    if method == "GET":
        return None

    body_params = {p.name: p.value for p in params if p.location == "body"}

    if graphql_op:
        variables = {p.name: p.value for p in params if p.location == "body"}
        return json.dumps({
            "query": graphql_op,
            "variables": variables,
        }, ensure_ascii=False)

    if "json" in content_type:
        return json.dumps(body_params, ensure_ascii=False) if body_params else None

    # form-encoded
    from urllib.parse import urlencode
    return urlencode(body_params) if body_params else None

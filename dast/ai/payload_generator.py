"""
AI-driven payload generator.

Given an endpoint and observed responses, asks Claude to:
  1. Identify the most promising injection points
  2. Generate targeted payloads for each attack type
  3. After each attempt, mutate payloads based on the response

This replaces static wordlists with adaptive, context-aware fuzzing.
"""

from typing import List, Optional

from dast.ai import bedrock_client
from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.ai.schemas import PAYLOAD_GEN_SCHEMA, PAYLOAD_MUTATION_SCHEMA
from dast.models import AttackAttempt, AttackPayload, Endpoint
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SYSTEM_PAYLOAD_GEN = """\
You are an expert web application penetration tester.
Given an endpoint description, generate targeted attack payloads.
Respond ONLY with JSON matching the schema requested.
Do NOT add markdown, commentary, or explanations.

Rules:
- Focus on high-impact vulnerabilities: XSS, SQLi, IDOR, SSRF, auth bypass, mass assignment
- Prefer payloads that reveal application behavior (blind detection)
- For GraphQL endpoints, generate introspection and mutation attacks
- For APIs with IDs (numeric, UUID), include IDOR payloads with adjacent IDs
- Keep payloads concise and precise
""" + UNTRUSTED_CONTENT_DIRECTIVE

_SYSTEM_MUTATION = """\
You are an expert web application penetration tester running an iterative attack loop.
You have sent an attack payload and received a response. Decide the next action.
Respond ONLY with JSON matching the schema requested.
""" + UNTRUSTED_CONTENT_DIRECTIVE


def generate_payloads(endpoint: Endpoint, attack_types: List[str]) -> List[AttackPayload]:
    """
    Generate attack payloads for an endpoint using Claude.
    Returns a ranked list of payloads to try.
    """
    endpoint_description = _describe_endpoint(endpoint)

    user = f"""Endpoint:
{endpoint_description}

Attack types to test: {", ".join(attack_types)}

Respond with JSON array. Each item must have:
{{
  "value": "<payload string>",
  "attack_type": "<type>",
  "injection_point": "<parameter name>",
  "injection_location": "<query|body|header|path|cookie>",
  "rationale": "<one sentence why this payload is relevant>"
}}

Generate up to 10 payloads, prioritized by likelihood of success."""

    try:
        result = bedrock_client.invoke_json(system=_SYSTEM_PAYLOAD_GEN, user=user, schema=PAYLOAD_GEN_SCHEMA)
        payloads = []
        items = result if isinstance(result, list) else result.get("payloads", [])
        for item in items:
            payloads.append(AttackPayload(
                value=str(item.get("value", "")),
                attack_type=str(item.get("attack_type", "unknown")),
                injection_point=str(item.get("injection_point", "")),
                injection_location=str(item.get("injection_location", "query")),
                rationale=str(item.get("rationale", "")),
            ))
        return payloads
    except Exception as exc:
        logger.warning("AI payload generation failed", error=str(exc))
        return []


def mutate_payload(
    previous_attempt: AttackAttempt,
    iteration: int,
) -> Optional[AttackPayload]:
    """
    Given a previous attack attempt and its response, generate a mutated payload.
    Returns None if the AI determines no further mutation is worthwhile.
    """
    resp = previous_attempt.response

    user = f"""Previous attempt (iteration {iteration}):
Attack type: {previous_attempt.payload.attack_type}
Payload: {previous_attempt.payload.value!r}
Injection point: {previous_attempt.payload.injection_point} ({previous_attempt.payload.injection_location})

Response:
  Status: {resp.status_code if resp else "N/A"}
  Body (first 1000 chars): {wrap_untrusted(resp.body, "target_response", 1000) if resp else ""}

Based on this response, should we:
A) Try a mutated payload (describe it)
B) Try a different parameter
C) Stop (endpoint is not vulnerable to this attack type)

Respond with JSON:
{{
  "action": "mutate" | "different_param" | "stop",
  "rationale": "<one sentence>",
  "new_payload": {{
    "value": "<new payload string>",
    "injection_point": "<param name>",
    "injection_location": "<query|body|header|path|cookie>",
    "rationale": "<why this mutation>"
  }}
}}
(new_payload is required only when action is mutate or different_param)"""

    try:
        result = bedrock_client.invoke_json(system=_SYSTEM_MUTATION, user=user, schema=PAYLOAD_MUTATION_SCHEMA)
        if result.get("action") == "stop":
            return None

        np = result.get("new_payload")
        if not np:
            return None

        return AttackPayload(
            value=str(np.get("value", "")),
            attack_type=previous_attempt.payload.attack_type,
            injection_point=str(np.get("injection_point", previous_attempt.payload.injection_point)),
            injection_location=str(np.get("injection_location", previous_attempt.payload.injection_location)),
            rationale=str(np.get("rationale", "")),
        )
    except Exception:
        return None


def _describe_endpoint(endpoint: Endpoint) -> str:
    params = "\n".join(
        f"  - {p.name} ({p.location}, type={p.inferred_type}): {p.value!r}"
        for p in endpoint.parameters
    )
    sample_resp_preview = ""
    if endpoint.sample_response:
        sample_resp_preview = f"\nSample response ({endpoint.sample_response.status_code}):\n{wrap_untrusted(endpoint.sample_response.body, 'target_response', 500)}"

    return (
        f"URL: {endpoint.url}\n"
        f"Method: {endpoint.method}\n"
        f"Content-Type: {endpoint.content_type}\n"
        f"Parameters:\n{params or '  (none detected)'}\n"
        f"{sample_resp_preview}"
    )

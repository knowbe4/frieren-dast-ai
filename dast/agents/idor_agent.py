"""
IDOR AI agent — LLM-assisted insecure direct object reference detection.

Complements the deterministic check_idor scanner. Where the scanner confirms
by structural diff (status code + size + JSON equality), this agent sends the
actual baseline and probe response bodies to an LLM to evaluate semantically:
  - Are these clearly different objects belonging to different users/accounts?
  - Do the probe data contain fields that look sensitive (PII, tokens, internal data)?
  - Could this be a public/shared resource that is intentionally world-readable?

Covers the same three injection points as the deterministic scanner:
  - Query string parameters
  - POST/PUT/PATCH JSON body fields (including GraphQL variables)
  - URL path segment IDs

bypass_validation=False — all findings pass through the coordinator LLM validator.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from dast.ai import bedrock_client
from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.payload_generator import _sanitize_for_prompt
from dast.scanners.active_checks import (
    _fmt_http_pair,
    _inject_body,
    _inject_query,
    _idor_confirmed,
    _idor_inject_path,
    _idor_neighbour,
    _IDOR_ID_RE,
    _PATH_ID_RE,
)
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_SYSTEM_IDOR = """\
You are a web application security analyst reviewing a potential IDOR (Insecure Direct Object Reference).
Two HTTP responses are shown: a baseline (original ID) and a probe (neighbour ID).
Determine if the probe response exposes data belonging to a DIFFERENT object/user that should not be accessible.

Respond ONLY with JSON: {"confirmed": true|false, "reasoning": "<one sentence>"}

confirmed=true when:
- Probe response contains identifiers, names, emails, or other fields clearly different from the baseline
- Probe data looks like a real object (user profile, account record, order, etc.) not an error
- The change in data is consistent with accessing a different restricted resource

confirmed=false when:
- Probe response is an error, empty, or generic message
- Data looks identical or is clearly a public/shared resource
- Response contains only non-sensitive metadata that any user could access
- The endpoint appears to be intentionally public (search results, product listings, etc.)
"""


async def _llm_evaluate(
    param_name: str,
    original_id: str,
    probe_id: str,
    baseline_text: str,
    probe_text: str,
    url: str,
) -> tuple[bool, str]:
    """Ask the LLM whether the probe response indicates a real IDOR."""
    try:
        user = (
            f"Endpoint: {_sanitize_for_prompt(url, 200)}\n"
            f"Parameter: {_sanitize_for_prompt(param_name, 100)}\n"
            f"Original ID: {_sanitize_for_prompt(original_id, 100)}\n"
            f"Probe ID:    {_sanitize_for_prompt(probe_id, 100)}\n\n"
            f"--- Baseline response (original ID) ---\n"
            f"{_sanitize_for_prompt(baseline_text, 800)}\n\n"
            f"--- Probe response (neighbour ID) ---\n"
            f"{_sanitize_for_prompt(probe_text, 800)}\n"
        )
        import asyncio
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(system=_SYSTEM_IDOR, user=user),
        )
        confirmed = bool(result.get("confirmed", False))
        reasoning = str(result.get("reasoning", ""))
        return confirmed, reasoning
    except Exception as e:
        logger.debug("IDOR agent LLM call failed", error=str(e))
        return False, ""


class IdorAgent(VulnAgent):
    name = "IDOR Agent"
    attack_type = "idor"
    description = (
        "Detects insecure direct object references by probing neighbour IDs across "
        "query params, POST body fields, GraphQL variables, and URL path segments. "
        "Uses LLM to evaluate whether probe responses expose data from a different object."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        # Baseline — needed for semantic comparison
        from dast.scanners.active_checks import _send
        baseline_resp = await _send(client, target.method, target.url, target.headers, target.body)
        if baseline_resp is None:
            return []
        baseline_status = baseline_resp.status_code
        baseline_text   = baseline_resp.text

        # ── Query and body parameters ──────────────────────────────────────────
        for param in target.params:
            name  = param["name"]
            value = param["value"]
            if not _IDOR_ID_RE.search(name):
                continue
            probe_id = _idor_neighbour(value)
            if not probe_id:
                continue

            if param["location"] == "query":
                probe_url  = _inject_query(target.url, name, probe_id)
                probe_resp = await _send(client, target.method, probe_url, target.headers, target.body)
            elif param["location"] in ("body", "body_graphql"):
                probe_body = _inject_body(
                    target.body or "", name, probe_id,
                    target.headers.get("content-type", ""),
                    location=param["location"],
                )
                probe_resp = await _send(client, target.method, target.url, target.headers, probe_body)
            else:
                continue

            if probe_resp is None:
                continue

            # Quick structural pre-filter — skip obvious non-findings before LLM call
            if not _idor_confirmed(baseline_status, baseline_text, probe_resp.status_code, probe_resp.text):
                continue

            confirmed, reasoning = await _llm_evaluate(
                param_name=name,
                original_id=value,
                probe_id=probe_id,
                baseline_text=baseline_text,
                probe_text=probe_resp.text,
                url=target.url,
            )
            if not confirmed:
                continue

            raw_request, raw_response = _fmt_http_pair(probe_resp)
            findings.append(AgentFinding(
                title="Insecure Direct Object Reference (IDOR)",
                severity="high",
                cwe="CWE-639",
                attack_type="idor",
                evidence=(
                    f"Parameter '{name}' changed from {value!r} to {probe_id!r}: "
                    f"LLM confirmed probe response exposes data from a different object. "
                    f"Reasoning: {reasoning}"
                ),
                payload=f"{name}={probe_id}",
                parameter=name,
                url=target.url,
                request_method=target.method,
                bypass_validation=False,
                reasoning=reasoning,
                raw_request=raw_request,
                raw_response=raw_response,
            ))

        # ── URL path segment IDs ───────────────────────────────────────────────
        from urllib.parse import urlparse
        path_matches = list(_PATH_ID_RE.finditer(urlparse(target.url).path))
        for match in path_matches:
            original_id = match.group(1)
            probe_id    = _idor_neighbour(original_id)
            if not probe_id:
                continue

            probe_url  = _idor_inject_path(target.url, original_id, probe_id)
            probe_resp = await _send(client, target.method, probe_url, target.headers, target.body)
            if probe_resp is None:
                continue

            if not _idor_confirmed(baseline_status, baseline_text, probe_resp.status_code, probe_resp.text):
                continue

            confirmed, reasoning = await _llm_evaluate(
                param_name=f"path:{original_id}",
                original_id=original_id,
                probe_id=probe_id,
                baseline_text=baseline_text,
                probe_text=probe_resp.text,
                url=target.url,
            )
            if not confirmed:
                continue

            raw_request, raw_response = _fmt_http_pair(probe_resp)
            findings.append(AgentFinding(
                title="Insecure Direct Object Reference (IDOR) via URL Path",
                severity="high",
                cwe="CWE-639",
                attack_type="idor",
                evidence=(
                    f"Path ID {original_id!r} changed to {probe_id!r}: "
                    f"LLM confirmed probe response exposes data from a different object. "
                    f"Reasoning: {reasoning}"
                ),
                payload=probe_url,
                parameter=f"path:{original_id}",
                url=target.url,
                request_method=target.method,
                bypass_validation=False,
                reasoning=reasoning,
                raw_request=raw_request,
                raw_response=raw_response,
            ))

        return findings


from dast.ai.coordinator import Coordinator
Coordinator.register(IdorAgent)

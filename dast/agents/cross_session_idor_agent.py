"""
Cross-Session IDOR Agent — detects horizontal privilege escalation by replaying
requests from Session A using the credentials of Session B.

Requires at least two named sessions saved via the Browse tab
("Save as Session A", "Save as Session B"). The agent replays the current
request with each alternate session's cookies and auth headers. If the response
is structurally similar to the original (same status, similar body size) and
the LLM confirms the content belongs to a different user's data, it is an IDOR.

This is distinct from the existing IdorAgent (which mutates numeric/UUID IDs
within a single session). This agent keeps the URL and body identical but
swaps the entire auth context.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional

import httpx

from dast.ai import bedrock_client
from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.payload_generator import _sanitize_for_prompt
from dast.scanners.active_checks import _fmt_http_pair
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService
    from dast.proxy.session_store import NamedSession

logger = get_logger(__name__)

_SYSTEM_CROSS_SESSION = """\
You are a web application security analyst reviewing a potential horizontal privilege escalation (IDOR).
Two HTTP responses are shown for the exact same URL:
- Baseline: sent with Session A credentials (the legitimate owner).
- Probe: sent with Session B credentials (a different user).

Determine if the probe response exposes data that belongs to Session A and should NOT be accessible to Session B.

Respond ONLY with JSON: {"confirmed": true|false, "reasoning": "<one sentence>"}

confirmed=true when:
- Probe response returns the same personal/private data as the baseline (same user record, order, file, etc.)
- Probe response is a 200 with meaningful body content from Session A's resource
- Data clearly belongs to a specific user/account (IDs, emails, names, tokens match the baseline)

confirmed=false when:
- Probe response is 401, 403, 404 or empty — server enforces access control correctly
- Probe response returns Session B's own data (different user data, not Session A's)
- Endpoint is a public resource intentionally accessible to all authenticated users
- Responses differ significantly in content — different objects, not the same resource leaked
"""


async def _llm_evaluate(
    url: str,
    session_a_name: str,
    session_b_name: str,
    baseline_text: str,
    probe_text: str,
    baseline_status: int,
    probe_status: int,
) -> tuple[bool, str]:
    try:
        user = (
            f"URL: {_sanitize_for_prompt(url, 200)}\n"
            f"Session A (owner): {session_a_name}\n"
            f"Session B (attacker): {session_b_name}\n\n"
            f"--- Baseline response (Session A, status {baseline_status}) ---\n"
            f"{_sanitize_for_prompt(baseline_text, 800)}\n\n"
            f"--- Probe response (Session B, status {probe_status}) ---\n"
            f"{_sanitize_for_prompt(probe_text, 800)}\n"
        )
        import asyncio
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=_SYSTEM_CROSS_SESSION,
                user=user,
                model_id=bedrock_client.get_validation_model(),
                max_tokens=512,
            ),
        )
        return bool(result.get("confirmed", False)), str(result.get("reasoning", ""))
    except Exception as exc:
        logger.debug("CrossSessionIdor LLM call failed", error=str(exc))
        return False, ""


def _build_session_headers(
    original_headers: Dict[str, str],
    session: "NamedSession",
) -> Dict[str, str]:
    """Replace auth headers and cookie header with the named session's credentials."""
    _AUTH_KEYS = {"authorization", "x-auth-token", "x-api-key", "cookie"}
    headers = {k: v for k, v in original_headers.items() if k.lower() not in _AUTH_KEYS}
    headers.update(session.auth_headers)
    if session.cookies:
        cookie_str = "; ".join(
            f"{name}={c['value']}" for name, c in session.cookies.items()
        )
        if cookie_str:
            headers["cookie"] = cookie_str
    return headers


def _responses_similar(baseline_status: int, baseline_len: int,
                        probe_status: int, probe_len: int) -> bool:
    """Quick structural pre-filter before the LLM call."""
    if probe_status not in (200, 201, 206):
        return False
    if baseline_len == 0:
        return False
    ratio = probe_len / baseline_len
    return 0.7 < ratio < 1.4


class CrossSessionIdorAgent(VulnAgent):
    name = "Cross-Session IDOR Agent"
    attack_type = "cross_session_idor"
    description = (
        "Detects horizontal privilege escalation by replaying requests from Session A "
        "using Session B credentials. Requires two named sessions saved in the Browse tab. "
        "Catches IDOR, BOLA, and cross-user data leakage that single-session testing cannot find."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        sessions: List["NamedSession"] = list(target.named_sessions or [])
        if len(sessions) < 2:
            return []

        # Only test requests that are likely to return user-specific data
        if target.method not in ("GET", "POST", "PUT", "PATCH"):
            return []

        # Baseline: send with original headers (Session A's context)
        from dast.scanners.active_checks import _send
        baseline_resp = await _send(
            client, target.method, target.url, target.headers, target.body
        )
        if baseline_resp is None or baseline_resp.status_code not in (200, 201, 206):
            return []

        baseline_status = baseline_resp.status_code
        baseline_text = baseline_resp.text
        baseline_len = len(baseline_resp.content)

        # Identify which named session matches the current request headers (Session A)
        def _is_owner_session(session: "NamedSession") -> bool:
            for k, v in session.auth_headers.items():
                if target.headers.get(k) == v:
                    return True
            return False

        owner = next((s for s in sessions if _is_owner_session(s)), sessions[0])
        others = [s for s in sessions if s.name != owner.name]

        findings: List[AgentFinding] = []

        for other_session in others:
            probe_headers = _build_session_headers(target.headers, other_session)
            probe_resp = await _send(
                client, target.method, target.url, probe_headers, target.body
            )
            if probe_resp is None:
                continue

            if not _responses_similar(baseline_status, baseline_len,
                                       probe_resp.status_code, len(probe_resp.content)):
                continue

            confirmed, reasoning = await _llm_evaluate(
                url=target.url,
                session_a_name=owner.name,
                session_b_name=other_session.name,
                baseline_text=baseline_text,
                probe_text=probe_resp.text,
                baseline_status=baseline_status,
                probe_status=probe_resp.status_code,
            )
            if not confirmed:
                continue

            baseline_req_text, baseline_resp_text = _fmt_http_pair(baseline_resp)
            probe_req_text, probe_resp_text = _fmt_http_pair(probe_resp)

            findings.append(AgentFinding(
                title=f"Horizontal Privilege Escalation (IDOR) — {target.method} {target.url}",
                severity="high",
                cwe="CWE-639",
                attack_type="cross_session_idor",
                evidence=(
                    f"Session '{other_session.name}' accessed a resource owned by "
                    f"'{owner.name}' — {reasoning}"
                ),
                payload=f"(session swap: {owner.name} → {other_session.name})",
                parameter="session",
                url=target.url,
                request_method=target.method,
                bypass_validation=False,
                reasoning=reasoning,
                raw_request=baseline_req_text,
                raw_response=baseline_resp_text,
                probe_request=probe_req_text,
                probe_response=probe_resp_text,
            ))

        return findings


from dast.ai.coordinator import Coordinator
Coordinator.register(CrossSessionIdorAgent)

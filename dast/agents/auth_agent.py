"""Auth bypass agent — tests for broken authentication and authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService


def _body_similarity(a: str, b: str) -> float:
    """Return a rough content similarity ratio between two response bodies."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    longer = max(len(a), len(b))
    # Count shared characters at the same positions (a fast approximation)
    matching = sum(ca == cb for ca, cb in zip(a[:2000], b[:2000]))
    return matching / min(longer, 2000)


def _responses_look_equivalent(authed: str, unauthed: str) -> bool:
    """
    Return True when the unauthenticated response looks like the same protected
    resource, not a login redirect or error page.

    Heuristics:
    - Body similarity >= 60% (same structure, different timestamps/tokens)
    - Unauthed response does NOT contain common login-page markers
    """
    _LOGIN_MARKERS = (
        "login", "sign in", "please log in", "unauthorized", "401",
        "access denied", "authentication required", "enter your password",
    )
    unauthed_lower = unauthed[:500].lower()
    if any(m in unauthed_lower for m in _LOGIN_MARKERS):
        return False
    return _body_similarity(authed, unauthed) >= 0.60


_AUTH_HEADERS_TO_STRIP = {
    "authorization", "cookie", "x-auth-token", "x-api-key",
    "x-access-token", "token", "session",
}

# Headers that take the request path as value — filled in dynamically per target
_PATH_OVERRIDE_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Forwarded-URL",
]

# Headers that take an IP value
_IP_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
]


class AuthAgent(VulnAgent):
    name = "Auth Agent"
    attack_type = "auth_bypass"
    description = "Tests for authentication bypass and broken access control"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        log_event("auth_bypass", "info", f"Auth agent started — {target.method} {target.url}", url=target.url, source="agent")

        # Test 1: strip auth headers and retry — if we get 200, auth is broken
        auth_present = any(
            k.lower() in _AUTH_HEADERS_TO_STRIP for k in target.headers
        )
        if auth_present:
            stripped = {
                k: v for k, v in target.headers.items()
                if k.lower() not in _AUTH_HEADERS_TO_STRIP
            }
            original_resp = await _send(client, target.method, target.url, target.headers, target.body)
            unauth_resp = await _send(client, target.method, target.url, stripped, target.body)

            if (
                original_resp is not None
                and unauth_resp is not None
                and original_resp.status_code == 200
                and unauth_resp.status_code == 200
                and len(unauth_resp.text) > 100
                and _responses_look_equivalent(original_resp.text, unauth_resp.text)
            ):
                baseline_req, baseline_resp_text = _fmt_http_pair(original_resp)
                probe_req, probe_resp_text = _fmt_http_pair(unauth_resp)
                log_event("auth_bypass", "finding", f"Broken auth: endpoint accessible without credentials — {target.url}", url=target.url, finding="Broken Authentication", source="agent")
                findings.append(AgentFinding(
                    title="Broken Authentication — Endpoint Accessible Without Credentials",
                    severity="high",
                    cwe="CWE-306",
                    attack_type="auth_bypass",
                    evidence=(
                        f"Authenticated and unauthenticated responses are equivalent "
                        f"({original_resp.status_code} → {unauth_resp.status_code}, "
                        f"body similarity {_body_similarity(original_resp.text, unauth_resp.text):.0%}). "
                        f"The endpoint appears to not enforce authentication."
                    ),
                    payload="(auth headers stripped)",
                    parameter="Authorization",
                    url=target.url,
                    request_method=target.method,
                    raw_request=baseline_req,
                    raw_response=baseline_resp_text,
                    probe_request=probe_req,
                    probe_response=probe_resp_text,
                ))

        # Test 2: header-based URL override using the actual target path.
        # Baseline first — only flag when the extra header changes a non-200 to 200,
        # or changes a 401/403 to a successful response with meaningful body.
        baseline_resp = await _send(client, target.method, target.url, target.headers, target.body)
        baseline_status = baseline_resp.status_code if baseline_resp else None

        # Only run bypass probes when the baseline is a protected response
        if baseline_status not in (401, 403):
            return findings

        from urllib.parse import urlparse
        target_path = urlparse(target.url).path or "/"
        bypass_combos: List[dict] = []
        for hdr in _PATH_OVERRIDE_HEADERS:
            bypass_combos.append({hdr: target_path})
        bypass_combos.extend(_IP_BYPASS_HEADERS)
        logger.debug("Auth agent: testing header bypass", url=target.url, combos=len(bypass_combos))

        for extra_headers in bypass_combos:
            headers_with_override = dict(target.headers)
            headers_with_override.update(extra_headers)
            resp = await _send(client, target.method, target.url, headers_with_override, target.body)
            if not resp:
                continue
            # Confirm: status changed from 401/403 to 200, with meaningful body
            if resp.status_code == 200 and len(resp.text) > 100:
                header_name = list(extra_headers.keys())[0]
                log_event("auth_bypass", "finding", f"Auth bypass via {header_name} header — {target.url}", url=target.url, finding=f"Auth Bypass via {header_name}", source="agent")
                baseline_req, baseline_resp_text = _fmt_http_pair(baseline_resp)
                probe_req, probe_resp_text = _fmt_http_pair(resp)
                findings.append(AgentFinding(
                    title=f"Authentication Bypass via {header_name} Header",
                    severity="high",
                    cwe="CWE-284",
                    attack_type="auth_bypass",
                    evidence=(
                        f"Baseline: {baseline_status}. "
                        f"With {header_name}: {extra_headers[header_name]!r} → {resp.status_code} "
                        f"({len(resp.text)} chars)"
                    ),
                    payload=f"{header_name}: {extra_headers[header_name]}",
                    parameter=header_name,
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_request=baseline_req,
                    raw_response=baseline_resp_text,
                    probe_request=probe_req,
                    probe_response=probe_resp_text,
                ))

        return findings


from dast.ai.coordinator import Coordinator
Coordinator.register(AuthAgent)

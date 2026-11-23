"""BFLA agent — Broken Function-Level Authorization (admin surfaces).

Round 4-B, techniques from ARTEX api-security P3 (L58-63) with hard SAFETY
gates: this agent performs **GET/HEAD only** — no DELETE/PUT/PATCH is ever
sent, so a "successful" probe can never mutate target state (a real BFLA
exploit would swap the method; we report the authorization gap instead of
demonstrating destructive access).

Checks:
1. **Admin surface with another session**: when the target has >=2 named
   sessions (same prerequisite as the cross-session IDOR agent), an
   admin-looking endpoint (``/admin|/manage|/console``) is replayed with each
   OTHER session's auth context (the ``_build_session_headers`` pattern). A
   200 with a substantial, non-login body from a non-admin identity is the
   function-level gap (CWE-862 high).
2. **API version downgrade**: same credentials, ``/v2/…`` → ``/v1/…``. When
   the current version answers 403/401 and the older version answers 200 with
   a substantial body, the older API lacks the newer control (CWE-862
   medium/high). Thesis documented by ``plugins/api_version_detector.py``.

Findings are honest-by-default: confirmed=False (role semantics need operator
judgment) unless the low-priv body is structurally equivalent to a real
admin-session response of the same endpoint.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService
    from dast.proxy.session_store import NamedSession

logger = get_logger(__name__)

_ADMIN_PATH_RE = re.compile(r"/(?:admin|manage|console|backoffice|internal)(?:/|$)", re.IGNORECASE)
_VERSION_RE = re.compile(r"^(.*?)/v(\d+)(/.*|$)", re.IGNORECASE)
_SUBSTANTIAL_BODY = 400  # bytes — a real admin page, not an error stub


def _looks_like_admin_handler(body: str) -> bool:
    """Not a login redirect / auth error — an actual served page."""
    lower = body[:600].lower()
    bad = ("login", "sign in", "unauthorized", "forbidden", "access denied",
           "401", "403", "authentication required")
    return len(body) >= _SUBSTANTIAL_BODY and not any(m in lower for m in bad)


class BflaAgent(VulnAgent):
    name = "BFLA Agent"
    attack_type = "bfla"
    description = (
        "Broken function-level authorization: admin surfaces replayed with "
        "non-admin sessions and API version downgrade — GET/HEAD only, never "
        "state-changing methods"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if (target.method or "GET").upper() not in ("GET", "HEAD"):
            return []  # safety: this agent never sends state-changing methods

        findings: List[AgentFinding] = []
        sessions = [s for s in (getattr(target, "named_sessions", None) or [])
                    if (getattr(s, "role", "") or "").lower() not in ("admin", "administrator")]

        finding = await self._check_admin_replay(target, client, sessions)
        if finding:
            findings.append(finding)

        finding = await self._check_version_downgrade(target, client)
        if finding:
            findings.append(finding)
            return findings
        return findings

    async def _check_admin_replay(
        self, target: "CheckTarget", client: "httpx.AsyncClient",
        sessions: List["NamedSession"],
    ) -> Optional[AgentFinding]:
        if not _ADMIN_PATH_RE.search(target.url) or not sessions:
            return None
        # Local import: the sibling agent owns the session-header machinery.
        from dast.agents.cross_session_idor_agent import _build_session_headers

        for session in sessions[:2]:
            headers = _build_session_headers(target.headers or {}, session)
            resp = await _send(client, "GET", target.url, headers, None)
            if resp is None:
                continue
            body = resp.text
            if resp.status_code != 200 or not _looks_like_admin_handler(body):
                continue
            raw_req, raw_resp = _fmt_http_pair(resp)
            log_event("agent", "finding",
                      f"BFLA: admin surface served to session '{session.name}' on {target.url}",
                      url=target.url, finding="BFLA admin surface", source="agent")
            return AgentFinding(
                title="BFLA — Admin Endpoint Serves Non-Admin Session",
                severity="high",
                cwe="CWE-862",
                attack_type="bfla",
                evidence=(
                    f"An admin-looking endpoint ({target.url}) answered HTTP 200 "
                    f"with a full admin page to session '{session.name}' "
                    f"(role: {getattr(session, 'role', 'unknown') or 'non-admin'}) "
                    f"via GET — function-level authorization is missing for the "
                    f"admin surface. Read-only probe: no state was changed.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=False,
                payload=f"GET {target.url} as session '{session.name}'",
                parameter="",
                url=target.url,
                request_method="GET",
                bypass_validation=False,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )
        return None

    async def _check_version_downgrade(
        self, target: "CheckTarget", client: "httpx.AsyncClient"
    ) -> Optional[AgentFinding]:
        m = _VERSION_RE.match(target.url)
        if not m:
            return None
        base, version, rest = m.group(1), int(m.group(2)), m.group(3) or "/"
        if version <= 1:
            return None
        old_url = f"{base}/v{version - 1}{rest}"

        # Baseline: current version under the SAME credentials.
        current = await _send(client, "GET", target.url, target.headers, None)
        if current is None or current.status_code not in (401, 403):
            return None  # current version authorizes fine — no downgrade thesis

        old = await _send(client, "GET", old_url, target.headers, None)
        if old is None:
            return None
        if old.status_code != 200 or not _looks_like_admin_handler(old.text):
            return None

        raw_req, raw_resp = _fmt_http_pair(old)
        log_event("agent", "finding",
                  f"BFLA: version downgrade {target.url} -> {old_url} served "
                  f"what the current version forbids",
                  url=target.url, finding="version downgrade", source="agent")
        return AgentFinding(
            title=f"BFLA — API Version Downgrade (v{version} Forbidden, v{version - 1} Served)",
            severity="medium",
            cwe="CWE-862",
            attack_type="bfla",
            evidence=(
                f"With the SAME credentials: {target.url} answered "
                f"{current.status_code} (forbidden) while the older API "
                f"{old_url} answered 200 with a substantial body — the older "
                f"version lacks the newer function-level control. Read-only "
                f"probe.\n\nRequest:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
            ),
            confirmed=False,
            payload=f"GET {old_url}",
            parameter="path",
            url=old_url,
            request_method="GET",
            bypass_validation=False,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        )


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(BflaAgent)

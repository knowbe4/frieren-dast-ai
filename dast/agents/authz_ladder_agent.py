"""Authz-ladder agent — role-ladder sweep across named sessions (low → admin).

Round 5-B-3 (XBOW/ARTEX offensive verification). Where bfla answers "does an
admin-looking endpoint leak to a non-admin?" and cross_session_idor answers
"does user A's object leak to user B?", this agent composes the LADDER: every
lower-privilege named session is replayed against the privileged URL set the
scan already observed, with a differential oracle:

    privileged context  → 200 (the read the scan captured)
    low-priv session    → 200 + substantial body   ← the ladder gap
    auth stripped       → 401/403 (the 403 control: SOME authorization runs)

Unauth denied + low-priv allowed + privileged read = CWE-862 confirmed
deterministically (no LLM): the endpoint enforces authentication but not
role-level authorization for that session.

Hard SAFETY gates (bfla contract): **GET/HEAD only** — no state-changing
method is ever sent, so a "successful" probe cannot mutate target state.
Requires >=2 named sessions with DISTINCT roles (same prerequisite shape the
coordinator dispatches on); each pair is one GET replay — bounded to 3
low-priv sessions per target.
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

logger = get_logger(__name__)

# Same keys cross_session_idor's header builder drops/replaces — used here to
# build the auth-stripped 403 control (borrowed from the test_unauth pattern).
_AUTH_KEYS = {"authorization", "x-auth-token", "x-api-key", "cookie", "x-csrf-token"}
_MAX_LOW_SESSIONS = 3

# Recognizable high-privilege role labels. Sessions whose role matches rank
# above everything else; without at least one recognizable privileged label
# the agent cannot ORDER the ladder and stays conservative (no candidates).
_PRIV_ROLE_RE = re.compile(
    r"admin|administrator|owner|root|superuser|manager|supervisor",
    re.IGNORECASE,
)


def _role_rank(session) -> int:
    role = (getattr(session, "role", "") or "").lower()
    return 2 if _PRIV_ROLE_RE.search(role) else 1


def _substantial_response(status: int, body: str) -> bool:
    """A real served page, not a login redirect / auth error stub.

    Same bar as bfla's _looks_like_admin_handler (local copy so the ladder
    oracle does not depend on the admin-path semantics of that agent)."""
    lower = body[:600].lower()
    bad = ("login", "sign in", "unauthorized", "forbidden", "access denied",
           "401", "403", "authentication required")
    return len(body) >= 400 and not any(m in lower for m in bad)


class AuthzLadderAgent(VulnAgent):
    name = "Authz Ladder Agent"
    attack_type = "authz_ladder"
    description = (
        "Role-ladder authorization sweep: privileged URL set replayed under "
        "each lower-privilege named session with a differential oracle "
        "(privileged 200 vs low-priv 200 vs unauth 403) — GET/HEAD only"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if (target.method or "GET").upper() not in ("GET", "HEAD"):
            return []  # safety: this agent never sends state-changing methods

        sessions = list(getattr(target, "named_sessions", None) or [])
        roles = {(getattr(s, "role", "") or "").lower() for s in sessions if getattr(s, "role", "")}
        if len(sessions) < 2 or len(roles) < 2:
            return []  # a ladder needs >=2 sessions on distinct roles
        max_rank = max(_role_rank(s) for s in sessions)
        candidates = [s for s in sessions if _role_rank(s) < max_rank]
        if not candidates:
            return []  # no recognizable low rung — cannot order the ladder

        # The privileged read: the target must serve its capturing context.
        own_resp = await _send(client, "GET", target.url, target.headers, None)
        if own_resp is None or own_resp.status_code != 200 \
                or not _substantial_response(own_resp.status_code, own_resp.text):
            return []

        stripped_headers = {
            k: v for k, v in (target.headers or {}).items() if k.lower() not in _AUTH_KEYS
        }
        unauth_resp = await _send(client, "GET", target.url, stripped_headers, None)
        unauth_denied = unauth_resp is not None and unauth_resp.status_code in (401, 403)
        if not unauth_denied:
            # No authorization control on the endpoint at all — that is
            # auth_bypass territory, not a role-ladder gap.
            return []

        for session in candidates[:_MAX_LOW_SESSIONS]:
            # Local import: the sibling agent owns the session-header machinery.
            from dast.agents.cross_session_idor_agent import _build_session_headers

            low_headers = _build_session_headers(target.headers or {}, session)
            low_resp = await _send(client, "GET", target.url, low_headers, None)
            if low_resp is None or low_resp.status_code != 200 \
                    or not _substantial_response(low_resp.status_code, low_resp.text):
                continue

            priv_req, priv_resp = _fmt_http_pair(own_resp)
            low_req, low_raw = _fmt_http_pair(low_resp)
            log_event("agent", "finding",
                      f"authz_ladder: {target.url} served to session "
                      f"'{session.name}' (role {getattr(session, 'role', '?')}) "
                      f"while unauth is denied",
                      url=target.url, finding="authz ladder", source="agent")
            return [AgentFinding(
                title="Authz Ladder — Low-Privilege Session Reads Privileged Resource",
                severity="high",
                cwe="CWE-862",
                attack_type="authz_ladder",
                evidence=(
                    f"Role-ladder differential on {target.url} (GET/HEAD only, "
                    f"no state changed):\n"
                    f"  1. privileged context → 200 (the read the scan captured)\n"
                    f"  2. session '{session.name}' "
                    f"(role: {getattr(session, 'role', 'unknown') or 'unknown'}) → "
                    f"200 with a substantial body\n"
                    f"  3. auth stripped → {unauth_resp.status_code} (authorization "
                    f"control EXISTS)\n"
                    f"The endpoint authenticates but does not enforce the role "
                    f"boundary between '{session.name}' and the privileged "
                    f"context — the low-privilege rung of the ladder reads the "
                    f"privileged resource. Role labels are the operator's; the "
                    f"differential is deterministic.\n\n"
                    f"Privileged response:\n{priv_resp[:1200]}\n\n"
                    f"Low-privilege request:\n{low_req}\n\n"
                    f"Low-privilege response:\n{low_raw[:1200]}"
                ),
                confirmed=True,
                payload=f"GET {target.url} as session '{session.name}'",
                parameter="",
                url=target.url,
                request_method="GET",
                bypass_validation=True,
                raw_request=low_req,
                raw_response=low_raw[:2000],
                probe_request=low_req,
                probe_response=low_raw[:2000],
                extracted_data={
                    "ladder": (
                        f"privileged=200; '{session.name}' "
                        f"({getattr(session, 'role', 'unknown') or 'unknown'})=200; "
                        f"unauth={unauth_resp.status_code}"
                    ),
                },
            )]
        return []


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(AuthzLadderAgent)

"""OAuth/OIDC agent — authorization-flow checks (ARTEX api-security P2).

Round 4-C, techniques from ARTEX api-security L37-42 (+ bbot `oauth` module):

- **redirect_uri takeover**: swap ``redirect_uri`` to an attacker origin on the
  authorize request — a 3xx whose Location carries the attacker origin means
  authorization codes/tokens flow to the attacker (CWE-601, high, confirmed).
- **state missing**: ``response_type`` + ``client_id`` present with no
  ``state`` — CSRF on the authorization flow (CWE-352, medium, unconfirmed
  mechanism).
- **PKCE missing**: ``response_type=code`` without ``code_challenge`` — public
  clients without PKCE lose the code-interception defense (CWE-352-family,
  low, unconfirmed mechanism).
- **implicit flow**: ``response_type=token`` — access token in the fragment
  (CWE-1275, low, unconfirmed mechanism).

GET-only (authorize requests are navigations); nothing is submitted beyond
the authorize request itself — no code exchange is attempted, so nothing of
value is ever redeemable by this probe.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_AUTHZ_PATH_RE = re.compile(r"/(authorize|oauth2?/|openid|auth)(?:[/?]|$)", re.IGNORECASE)
_EVIL_REDIRECT = "https://evil-attacker.test/callback"


def _is_authorize_target(target: "CheckTarget") -> bool:
    url_l = target.url.lower()
    params = dict(parse_qsl(urlparse(url_l).query, keep_blank_values=True))
    if _AUTHZ_PATH_RE.search(url_l) or "response_type" in params or (
            "client_id" in params and "redirect_uri" in params):
        return True
    body = (target.body or "")
    return "response_type=" in body or "client_id=" in body


def _params_of(target: "CheckTarget") -> List[tuple]:
    return parse_qsl(urlparse(target.url).query, keep_blank_values=True)


class OAuthAgent(VulnAgent):
    name = "OAuth Agent"
    attack_type = "oauth"
    description = (
        "OAuth/OIDC authorization-flow checks: redirect_uri takeover, missing "
        "state, missing PKCE, implicit token flow"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if not _is_authorize_target(target):
            return []

        findings: List[AgentFinding] = []
        params = dict(_params_of(target))
        response_type = params.get("response_type", "")

        # state missing — mechanism finding (CSRF on the authorization flow).
        if ("response_type" in params or "client_id" in params) and "state" not in params:
            findings.append(self._mechanism(
                target, "OAuth state Parameter Missing (Authorization CSRF)",
                "low", "CWE-352",
                "No state parameter on the authorize request — the authorization "
                "response can be forged into a victim's session (login CSRF / "
                "code injection)."))

        # PKCE missing for code flows — mechanism finding.
        if response_type == "code" and "code_challenge" not in params:
            findings.append(self._mechanism(
                target, "OAuth PKCE Missing on Public Authorization Code Flow",
                "low", "CWE-352",
                "response_type=code without code_challenge — an intercepted code "
                "can be redeemed without the PKCE verifier."))

        # Implicit token flow — token lands in the fragment.
        if response_type == "token":
            findings.append(self._mechanism(
                target, "OAuth Implicit Flow (response_type=token)",
                "low", "CWE-1275",
                "response_type=token returns the access token in the URL "
                "fragment — history/referrer leakage surface."))

        # redirect_uri takeover — the CONFIRMED check (only if a redirect_uri
        # is present to swap; the swap keeps every other parameter intact).
        if "redirect_uri" in params:
            swapped = [(k, _EVIL_REDIRECT if k == "redirect_uri" else v)
                       for k, v in _params_of(target)]
            probe_url = target.url.split("?")[0] + "?" + urlencode(swapped)
            resp = await _send(client, target.method or "GET", probe_url,
                               target.headers, None, payload="redirect_uri-swap")
            if resp is not None:
                location = ""
                for k, v in resp.headers.items():
                    if k.lower() == "location":
                        location = v
                        break
                if resp.status_code in (301, 302, 303, 307) and \
                        location.startswith("https://evil-attacker.test"):
                    raw_req, raw_resp = _fmt_http_pair(resp)
                    log_event("agent", "finding",
                              f"OAuth redirect_uri takeover confirmed on {target.url}",
                              url=target.url, finding="redirect_uri takeover",
                              source="agent")
                    findings.append(AgentFinding(
                        title="OAuth redirect_uri Takeover — Attacker Callback Accepted",
                        severity="high",
                        cwe="CWE-601",
                        attack_type="oauth",
                        evidence=(
                            "The authorize endpoint accepted an attacker-controlled "
                            f"redirect_uri and answered {resp.status_code} with "
                            f"Location: {location} — authorization codes/tokens for "
                            "victim sessions flow to the attacker's collector.\n\n"
                            f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                        ),
                        confirmed=True,
                        payload=f"redirect_uri={_EVIL_REDIRECT}",
                        parameter="redirect_uri",
                        url=probe_url,
                        request_method=target.method or "GET",
                        bypass_validation=True,
                        raw_request=raw_req,
                        raw_response=raw_resp[:2000],
                    ))
        return findings

    @staticmethod
    def _mechanism(target: "CheckTarget", title: str, severity: str,
                   cwe: str, why: str) -> AgentFinding:
        log_event("agent", "finding", f"{title} on {target.url}",
                  url=target.url, finding=title, source="agent")
        return AgentFinding(
            title=title,
            severity=severity,
            cwe=cwe,
            attack_type="oauth",
            evidence=f"{why} (mechanism finding — no token was redeemed).",
            confirmed=False,
            payload=target.url,
            parameter="",
            url=target.url,
            request_method=target.method or "GET",
            bypass_validation=False,
        )


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(OAuthAgent)

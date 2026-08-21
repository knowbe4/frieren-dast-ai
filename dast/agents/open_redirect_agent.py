"""
Open Redirect agent — tests URL/path parameters for redirect to attacker-controlled hosts.

Detection is purely response-based:
  1. Response has a 3xx Location header pointing to the injected host.
  2. Response has a 200 with a Refresh header or meta-refresh body pointing to the injected host.
  3. Response is 200 but the final URL (after follow_redirects) moved to the injected host.

No OOB callback needed — all evidence is in-band.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _inject_query, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

# Canary domains — use multiple so one WAF block doesn't hide all evidence
_REDIRECT_CANARIES = [
    "https://dast-redirect-canary.invalid/probe",
    "//dast-redirect-canary.invalid/probe",
    "https:///dast-redirect-canary.invalid/probe",
    r"//\dast-redirect-canary.invalid",
    "/\\dast-redirect-canary.invalid",
    "https://dast-redirect-canary.invalid%2F@legit.example.com",
]

_CANARY_HOST = "dast-redirect-canary.invalid"

# Param name patterns that commonly carry redirect destinations
_REDIRECT_PARAM_RE = re.compile(
    r"return|redirect|next|url|goto|dest(?:ination)?|continue|redir|"
    r"forward|target|location|to|ref|referrer|callback|back|from|out",
    re.IGNORECASE,
)

# Header and body evidence patterns
_LOCATION_RE = re.compile(r"dast-redirect-canary\.invalid", re.IGNORECASE)
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=["\']?([^"\'>\s]+)',
    re.IGNORECASE,
)



def _meta_refresh_to_canary(body: str) -> bool:
    """Return True if the HTML body has a meta-refresh pointing to our canary."""
    for match in _META_REFRESH_RE.finditer(body[:4000]):
        if _CANARY_HOST in match.group(1):
            return True
    return False


def _redirect_params(target: "CheckTarget") -> list[dict]:
    """Return params whose names suggest they carry redirect destinations."""
    params = []
    for p in target.params:
        if _REDIRECT_PARAM_RE.search(p.get("name", "")):
            params.append(p)
        elif p.get("value", "").startswith(("http://", "https://", "/")):
            # param whose current value looks like a URL — also test it
            if p not in params:
                params.append(p)
    return params


class OpenRedirectAgent(VulnAgent):
    name = "Open Redirect Agent"
    attack_type = "open_redirect"
    description = "Tests URL/path parameters for unvalidated redirect to attacker-controlled hosts"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        tested: set[str] = set()

        # Only test parameters that plausibly carry a redirect destination:
        # a redirect-suggestive NAME (return/redirect/next/url/...) or a VALUE
        # that already looks like a URL. Spraying the canary into unrelated
        # params (e.g. a flash-message field) is pure noise — an open redirect
        # cannot exist in a param the server never treats as a location.
        redirect_params = _redirect_params(target)
        if not redirect_params:
            logger.debug(
                "open_redirect: no redirect-carrying params on %s — skipping",
                target.url,
            )
            return []

        param_names = ", ".join(p.get("name", "") for p in redirect_params)
        logger.info(
            "open_redirect: testing %d param(s) on %s",
            len(redirect_params), target.url,
        )
        # Surface the probe intent in the Logs tab so an operator seeing a
        # request to the .invalid canary host understands it is a redirect
        # probe: the canary never resolves (reserved TLD), and detection is
        # based on the response Location/meta-refresh, not on visiting it.
        log_event(
            "agent", "debug",
            f"open_redirect probe: injecting a non-resolving canary host into "
            f"param(s) [{param_names}] on {target.url} — detection reads the "
            f"response redirect target, the canary is never actually visited",
            url=target.url,
            source="agent",
        )

        for param in redirect_params:
            param_name = param.get("name", "")
            if not param_name:
                continue

            for canary in _REDIRECT_CANARIES:
                probe_key = f"{param_name}:{canary}"
                if probe_key in tested:
                    continue
                tested.add(probe_key)

                probe_url = _inject_query(target.url, param_name, canary)
                try:
                    resp = await _send(
                        client,
                        target.method,
                        probe_url,
                        target.headers,
                        target.body,
                        payload=canary,
                    )
                except Exception as exc:
                    logger.warning(
                        "open_redirect: probe error on %s param=%s: %s",
                        target.url, param_name, exc,
                    )
                    continue

                req_text, resp_text = _fmt_http_pair(resp)
                confirmed = False
                evidence_detail = ""

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if _LOCATION_RE.search(location):
                        confirmed = True
                        evidence_detail = f"Location: {location}"

                if not confirmed and resp.status_code == 200:
                    body_text = resp.text[:4000]
                    if _meta_refresh_to_canary(body_text):
                        confirmed = True
                        evidence_detail = "meta-refresh to canary host in response body"

                if confirmed:
                    log_event(
                        "agent", "info",
                        f"Open redirect confirmed: param '{param_name}' on {target.url}",
                        url=target.url,
                        finding=f"Location redirects to {_CANARY_HOST}",
                        source="agent",
                    )
                    findings.append(AgentFinding(
                        title="Open Redirect",
                        severity="medium",
                        cwe="CWE-601",
                        attack_type="open_redirect",
                        evidence=(
                            f"Parameter '{param_name}' in {target.method} {target.url} "
                            f"accepted '{canary}' and triggered a redirect to the canary host. "
                            f"{evidence_detail}"
                        ),
                        payload=canary,
                        parameter=param_name,
                        url=target.url,
                        request_method=target.method,
                        confirmed=True,
                        bypass_validation=True,
                        probe_request=req_text,
                        probe_response=resp_text,
                    ))
                    # One confirmed finding per param is enough
                    break

        if not findings:
            logger.info("open_redirect: no redirect found on %s", target.url)
        return findings


Coordinator.register(OpenRedirectAgent)

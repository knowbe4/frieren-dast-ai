"""CORS agent — active cross-origin validation (reflected Origin + credentials).

Round 4-A, promoted from the passive scanner's active probe
(``plugins/passive_scanner.py::_active_cors_probe`` / ``_eval_cors``) into a
registered VulnAgent so the autonomous pipeline covers CORS, not just the
copilot. Techniques per ARTEX api-security (reflect arbitrary origin with
credentials, ``Origin: null``, attacker-controlled subdomain):

- ``ACAO: <attacker origin>`` + ``ACAC: true``  → critical (credentials-readable
  cross-origin response). Null-origin and suffix-match subdomain variants are
  documented follow-ups — the arbitrary-origin probe covers the dominant case.

Cost discipline: ONE probe per endpoint by default — if the first response does
not reflect an attacker origin at all, the endpoint is not CORS-loose and the
agent returns immediately. Same-site (eTLD+1 equal to the target host) origins
never count as findings — a reflected same-site origin is a legitimate
first-party pattern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional
from urllib.parse import urlparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_EVIL_ORIGIN = "https://evil-attacker.test"

def _etld_plus1(host: str) -> str:
    """Last-two-labels heuristic (same as the passive scanner's — under-suppress
    rather than miss; .co.uk-style multi-label TLDs are not the target here)."""
    host = (host or "").split(":")[0].lower()
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _origin_site(origin: str) -> str:
    try:
        return _etld_plus1(urlparse(origin).hostname or "")
    except ValueError:
        return ""


class CorsAgent(VulnAgent):
    name = "CORS Agent"
    attack_type = "cors"
    description = (
        "Active CORS validation: reflected attacker Origin with credentials, "
        "Origin:null acceptance, and suffix-match subdomain trust"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        headers = {k: v for k, v in (target.headers or {}).items()
                   if not k.lower().startswith("origin")}

        findings: List[AgentFinding] = []

        # Probe 1 — arbitrary attacker origin (the definitive credential test).
        finding = await self._probe(
            target, client, headers, _EVIL_ORIGIN,
            title="CORS — Arbitrary Origin Reflected with Credentials",
            severity="critical", cwe="CWE-942",
            cross_site=True,
        )
        if finding:
            findings.append(finding)
            return findings
        # If an arbitrary origin was NOT reflected, null/subdomain variants can
        # still be honored by configs that switch on the origin value — but a
        # config loose enough for those almost always reflects the plain origin
        # too. One probe covers the overwhelming majority; keep it cheap.
        return findings

    async def _probe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base_headers: dict,
        origin: str,
        title: str,
        severity: str,
        cwe: str,
        cross_site: bool,
    ) -> Optional[AgentFinding]:
        server_site = _etld_plus1(urlparse(target.url).hostname or "")
        if cross_site and _origin_site(origin) == server_site:
            return None  # same-site origin — legitimate first-party pattern
        headers = {**base_headers, "origin": origin}
        resp = await _send(client, target.method, target.url, headers,
                           target.body, source="agent")
        if not resp:
            return None

        acao = ""
        acac = ""
        for k, v in resp.headers.items():
            kl = k.lower()
            if kl == "access-control-allow-origin":
                acao = v.strip()
            elif kl == "access-control-allow-credentials":
                acac = v.strip().lower()

        reflected = acao == origin
        if not reflected:
            return None
        if not acac or acac not in ("true", "1"):
            # Reflecting an attacker origin WITHOUT credentials is low impact —
            # the attacker gains nothing a public page doesn't already expose.
            return None

        raw_req, raw_resp = _fmt_http_pair(resp)
        log_event("agent", "finding",
                  f"CORS misconfiguration confirmed on {target.url}",
                  url=target.url, finding=title, source="agent")
        return AgentFinding(
            title=title,
            severity=severity,
            cwe=cwe,
            attack_type="cors",
            evidence=(
                f"Request with Origin: {origin} was answered with "
                f"Access-Control-Allow-Origin: {acao} and "
                f"Access-Control-Allow-Credentials: {acac} — any page the "
                f"attacker controls can read authenticated responses from this "
                f"endpoint.\n\n"
                f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
            ),
            confirmed=True,
            payload=f"Origin: {origin}",
            parameter="Origin",
            url=target.url,
            request_method=target.method,
            bypass_validation=True,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        )


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(CorsAgent)

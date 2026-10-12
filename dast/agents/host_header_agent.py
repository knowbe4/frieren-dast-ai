"""
Host header injection agent — Host/X-Forwarded-Host override with OOB confirmation.

Two deterministic proof paths, no LLM:

  1. OOB (needs the collaborator): send the request with Host (or
     X-Forwarded-Host) pointed at a unique collaborator token host. Any DNS/HTTP
     callback proves the server embedded the attacker-controlled host into an
     outbound request — the password-reset-poisoning primitive (high).
  2. Reflection: the attacker host shows up in the response's Location header
     or in absolute URLs inside the body (link generation) — the stored/cache
     poisoning feed (medium). Only link-like contexts count; a header value
     echoed into an error message is noise, not a finding.

Without a collaborator only path 2 runs, with a non-routable marker host so the
probe can never cause a real outbound connection.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, List, Optional, Tuple

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_OOB_SETTLE_SECONDS = 2.0
# Static assets never generate links; skip them to cut noise.
_STATIC_CONTENT_RE = re.compile(
    r"text/css|javascript|image/|font/|video/|audio/", re.IGNORECASE
)
# Reflection only counts in link-generating contexts.
_ABSOLUTE_URL_RE = re.compile(
    r"""(?:href|src|action|url|link|redirect|location|reset[_-]?url)\s*[:=]\s*["']?https?://[^"'\s<]{4,200}""",
    re.IGNORECASE,
)

# One probe set per (host, path, header) — re-scans must not re-fire.
_probed: set[Tuple[str, str, str]] = set()


class HostHeaderAgent(VulnAgent):
    name = "Host Header Agent"
    attack_type = "host_header"
    description = (
        "Tests Host / X-Forwarded-Host header injection: OOB callback confirmation "
        "(password-reset poisoning) and reflection into absolute links."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        content_type = " ".join(
            v for k, v in (target.headers or {}).items() if k.lower() == "content-type"
        )
        if _STATIC_CONTENT_RE.search(content_type):
            return []

        findings: List[AgentFinding] = []

        for header_name in ("host", "x-forwarded-host"):
            probe_key = (target.url.split("/")[2] if "://" in target.url else "", target.path, header_name)
            if probe_key in _probed:
                continue
            _probed.add(probe_key)

            marker_host = self._marker_host(collaborator)
            token = collaborator.issue_token() if collaborator else ""

            headers = dict(target.headers or {})
            # httpx derives Host from the URL unless an explicit Host header is
            # given — for the Host probe we override it directly; for
            # X-Forwarded-Host the real Host stays and the unkeyed copy rides along.
            headers = {k: v for k, v in headers.items() if k.lower() != "host"}
            if header_name == "host":
                headers["Host"] = marker_host
            else:
                headers["X-Forwarded-Host"] = marker_host

            try:
                resp = await _send(client, target.method, target.url, headers, target.body)
            except Exception as exc:
                logger.debug(
                    "Host header probe failed", header=header_name, url=target.url, error=str(exc)
                )
                continue
            if resp is None:
                continue

            # Path 1 — OOB callback: the server dereferenced our host.
            if collaborator:
                await asyncio.sleep(_OOB_SETTLE_SECONDS)
                if collaborator.was_hit(token):
                    raw_request, raw_response = _fmt_http_pair(resp)
                    findings.append(AgentFinding(
                        title=f"Host Header Injection — Outbound Request To Attacker Host ({header_name})",
                        severity="high",
                        cwe="CWE-644",
                        attack_type="host_header",
                        evidence=(
                            f"Overriding {header_name} with {marker_host} made the server contact "
                            f"the attacker host (OOB callback for token {token!r}). This is the "
                            f"password-reset-poisoning primitive: reset links are generated from "
                            f"the injected host and sent to victims."
                        ),
                        payload=marker_host,
                        parameter=header_name,
                        url=target.url,
                        request_method=target.method,
                        bypass_validation=True,  # OOB callback is deterministic proof
                        raw_request=raw_request,
                        raw_response=raw_response,
                    ))
                    continue

            # Path 2 — reflection into link-generating contexts.
            reflected = self._link_reflection(resp, marker_host)
            if reflected:
                raw_request, raw_response = _fmt_http_pair(resp)
                findings.append(AgentFinding(
                    title=f"Host Header Reflected In Absolute Links ({header_name})",
                    severity="medium",
                    cwe="CWE-644",
                    attack_type="host_header",
                    evidence=(
                        f"Overriding {header_name} with {marker_host} is reflected into the "
                        f"response links: {reflected[:200]}. Combined with a cache or an "
                        f"email-sent link this poisons other users."
                    ),
                    payload=marker_host,
                    parameter=header_name,
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,  # verbatim reflection in a link context
                    raw_request=raw_request,
                    raw_response=raw_response,
                ))

        return findings

    @staticmethod
    def _marker_host(collaborator: Optional["CollaboratorService"]) -> str:
        """The host to inject: the collaborator domain when available (real OOB
        evidence), else a non-routable marker (reflection-only probing)."""
        if collaborator:
            return f"hostprobe.{collaborator.host}"
        return "hostprobe.invalid"

    @staticmethod
    def _link_reflection(resp: "httpx.Response", marker_host: str) -> str:
        """First link-context reflection of the marker host, or ''."""
        if marker_host in (resp.headers.get("location") or ""):
            return f"Location: {resp.headers['location'][:200]}"
        text = resp.text or ""
        for match in _ABSOLUTE_URL_RE.finditer(text):
            url = match.group(0)
            if marker_host in url:
                return url
        return ""


from dast.ai.coordinator import Coordinator
Coordinator.register(HostHeaderAgent)

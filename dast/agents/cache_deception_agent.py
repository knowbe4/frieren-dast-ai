"""Cache deception agent — autonomous port of the copilot WCD probe.

Round 4-A: the deterministic three-step web-cache-deception dance
(``tools/web_cache_deception_tools.py``, CWE-525) promoted to a registered
VulnAgent so the autonomous pipeline covers it:

1. baseline AUTHENTICATED fetch of the sensitive URL (the session client);
2. victim markers auto-derived from the authed-vs-anonymous diff
   (high-entropy secrets + account keywords unique to the authed page);
3. for each deterministic path-mapping variant (static-ext append, path
   delimiters, trailing slash, encoded dot-segment): authed fetch to prove the
   origin path-maps back to the sensitive handler, a second authed fetch for a
   miss→hit cacheable signal, then an ANONYMOUS re-read — CONFIRMED iff the
   victim markers survive without any auth signal.

The anonymous re-read runs on a BARE client (no session cookies — that is the
attacker position); probes are GET-only and secrets in recorded evidence are
REDACTED to ``<redacted:len=NN>`` placeholders. Pure helpers are imported from
the tool module (single source of truth for the technique).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.tools.web_cache_deception_tools import (
    _AUTH_HEADER_NAMES,
    _cacheable_signal,
    _cache_headers,
    _derive_markers,
    _leak_snippet,
    _markers_present,
    _redact,
    _wcd_variants,
)
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_MAX_VARIANTS = 6  # cap the autonomous probe count (the tool used the full 14)


class CacheDeceptionAgent(VulnAgent):
    name = "Cache Deception Agent"
    attack_type = "cache_deception"
    description = (
        "Web cache deception: authenticated path-mapping + cacheable signal + "
        "anonymous re-read (victim markers surviving without auth confirms)"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        # GET-only reads; the dance is meaningless without an authenticated
        # session (no cookie/authorization → there is no victim response to leak).
        if (target.method or "GET").upper() != "GET":
            return []
        hdrs_l = {k.lower() for k in (target.headers or {})}
        if not (hdrs_l & {"cookie", "authorization"}):
            return []

        authed_headers = {**target.headers, "x-requested-with": "XMLHttpRequest"}

        # Step 1 — authenticated baseline of the sensitive URL.
        baseline = await _send(client, "GET", target.url, authed_headers, None)
        if baseline is None:
            return []
        base_body = baseline.text

        # Step 2 — victim markers: authed-vs-anonymous diff of the base URL.
        anon_base = await self._anon_fetch(target.url, authed_headers)
        markers = _derive_markers(base_body, anon_base or "")
        if not markers:
            return []

        # Steps 3+4 — variants: path-map, cacheable signal, anonymous re-read.
        for variant in _wcd_variants(target.url)[:_MAX_VARIANTS]:
            vurl = variant["url"]
            r1 = await _send(client, "GET", vurl, authed_headers, None)
            if r1 is None or not _markers_present(r1.text, markers):
                continue  # origin did not path-map back to the sensitive handler
            r2 = await _send(client, "GET", vurl, authed_headers, None)
            c1 = _cache_headers(r1)
            c2 = _cache_headers(r2) if r2 is not None else c1
            cacheable, reason = _cacheable_signal(c1, c2)
            if not cacheable:
                continue

            anon_body = await self._anon_fetch(vurl, authed_headers) or ""
            leaked = _markers_present(anon_body, markers)
            if not leaked:
                continue

            raw_req, raw_resp = _fmt_http_pair(r2 or r1)
            log_event("agent", "finding",
                      f"Web cache deception confirmed on {vurl}",
                      url=target.url, finding="Web Cache Deception", source="agent")
            return [AgentFinding(
                title="Web Cache Deception — Victim Response Cached and Served Anonymously",
                severity="critical",
                cwe="CWE-525",
                attack_type="cache_deception",
                evidence=(
                    f"Variant '{vurl}' ({variant['technique']}) path-mapped back to "
                    f"the authenticated handler, was cached ({reason}), and an "
                    f"UNAUTHENTICATED re-read returned the victim's markers: "
                    f"{[_redact(m) for m in leaked]}. Snippet: "
                    f"{_leak_snippet(anon_body, leaked[0])}\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=True,
                payload=vurl,
                parameter="path",
                url=vurl,
                request_method="GET",
                bypass_validation=True,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )]
        return []

    async def _anon_fetch(self, url: str, authed_headers: dict) -> Optional[str]:
        """Anonymous re-read: bare httpx client OUTSIDE the session (the
        attacker position — no cookies, no auth headers), direct connection."""
        import httpx

        anon_headers = {k: v for k, v in authed_headers.items()
                        if k.lower() not in _AUTH_HEADER_NAMES}
        try:
            async with httpx.AsyncClient(verify=False, timeout=30,
                                         follow_redirects=False) as client:
                resp = await client.request("GET", url, headers=anon_headers)
                return resp.text
        except Exception as exc:
            logger.debug("cache_deception: anonymous fetch failed", url=url, error=str(exc))
            return None


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(CacheDeceptionAgent)

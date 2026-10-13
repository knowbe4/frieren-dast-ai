"""
Header OOB Scanner — deterministic (no AI) blind detection through request headers.

For each in-scope entry queued for scanning, sends one probe that puts a unique
out-of-band hostname in every header listed in dast/payloads/oob_headers.yaml.
A DNS or HTTP interaction on that hostname is attributed by its marker to the
exact entry + header, so a finding needs no judgment call:

  - HTTP callback  -> the server fetched the URL: blind SSRF via the header (high)
  - DNS callback   -> something on the target side resolved the value: confirmed
                      out-of-band DNS resolution via the header (medium) — the
                      lookup may come from a proxy, WAF or log pipeline rather
                      than the application itself
  - value reflected in the probe response -> held for review: a browser rendering
    that response could have produced the callback

Callbacks also appear in the Interactions tab (display-only session).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from dast.payloads.loader import get_value
from dast.proxy.plugin_base import ProxyPlugin
from dast.scanners.oob_correlator import OobCorrelator, OobHit, OobInjection
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

_PLUGIN_NAME = "Header OOB Scanner"

# Hop-by-hop / transport headers never replayed from the original request.
_DROP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "accept-encoding", "x-dast-crawler", "x-dast-source",
}


def load_header_specs() -> List[Tuple[str, str]]:
    """(header name, value template) pairs from dast/payloads/oob_headers.yaml."""
    specs: List[Tuple[str, str]] = []
    for item in get_value("oob_headers", "headers", []) or []:
        name = str((item or {}).get("name", "")).strip()
        template = str((item or {}).get("value", "")).strip()
        if name and "{{OOB_HOST}}" in template:
            specs.append((name, template))
    return specs


def base_headers(entry: "ProxyEntry") -> Dict[str, str]:
    """The original request headers minus transport headers and the ones we inject."""
    injected = {name.lower() for name, _ in load_header_specs()}
    return {
        key: value for key, value in (entry.request_headers or {}).items()
        if key.lower() not in _DROP_HEADERS and key.lower() not in injected
    }


def probe_key(entry: "ProxyEntry") -> Tuple[str, str, str]:
    """One probe per method + host + normalised path."""
    from dast.proxy.scan_support import normalise_dedup_path
    path = urlparse(entry.url).path or "/"
    return (entry.method.upper(), entry.host, normalise_dedup_path(path))


def build_finding(hit: OobHit) -> Dict[str, object]:
    """Finding dict for an attributed interaction (see module docstring for the rules)."""
    injection = hit.injection
    interaction = hit.interaction
    source = interaction.get("remote-address", "?")
    when = interaction.get("timestamp", "")
    if hit.protocol in ("http", "https"):
        title = f"Blind SSRF via {injection.name} header (OOB HTTP callback)"
        severity, cwe = "high", "CWE-918"
        what = "an HTTP request to"
    else:
        title = f"Out-of-band {hit.protocol.upper()} interaction via {injection.name} header"
        severity, cwe = "medium", "CWE-918"
        what = f"a {hit.protocol.upper()} lookup of"
    evidence = (
        f"The {injection.name} header of {injection.method} {injection.url} carried the unique "
        f"OOB marker '{injection.marker}'. {what.capitalize()} that marker's hostname arrived "
        f"from {source} at {when} (interactsh full-id: {interaction.get('full-id', '')}). "
        f"The marker is unique to this request + header, so the interaction is attributable."
    )
    raw_request = str(interaction.get("raw-request", ""))[:600]
    finding: Dict[str, object] = {
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "attack_type": "ssrf",
        "parameter": injection.name,
        "payload": injection.value[:200],
        "evidence": evidence,
        "snippet": raw_request,
        "confirmed": True,
        "needs_review": False,
        "confidence": 1.0,
        "validated_by": ["oob_callback"],
        "source": "plugin",
    }
    if injection.reflected:
        # A client rendering the reflected value could have made the callback.
        finding["confirmed"] = False
        finding["needs_review"] = True
        finding["confidence"] = 0.5
        finding["reasoning"] = (
            "The injected value was reflected in the probe response, so a browser or other "
            "client rendering that response could have produced this callback. Verify that "
            "the interaction comes from the target's infrastructure."
        )
    return finding


class HeaderOobScannerPlugin(ProxyPlugin):
    name = _PLUGIN_NAME
    description = (
        "Deterministic blind detection through request headers: injects a unique "
        "out-of-band hostname per header and confirms on the DNS/HTTP callback "
        "attributed to that exact header. No AI. Callbacks show in the Interactions tab."
    )
    version = "1.0.0"
    author = "Frieren DAST-AI"
    active = True

    def __init__(self) -> None:
        self._seen: Set[Tuple[str, str, str]] = set()
        self._store: Optional["SessionStore"] = None
        self._correlator = OobCorrelator(label=_PLUGIN_NAME, on_hit=self._on_hit)

    async def on_active_probe(
        self, entry: "ProxyEntry", store: "SessionStore", client: "httpx.AsyncClient",
    ) -> None:
        if entry.method.upper() == "CONNECT":
            return
        key = probe_key(entry)
        if key in self._seen:
            return
        specs = load_header_specs()
        if not specs or not await self._correlator.start():
            return
        self._seen.add(key)
        self._store = store
        await self._probe(entry, client, specs)

    async def _probe(
        self, entry: "ProxyEntry", client: "httpx.AsyncClient", specs: List[Tuple[str, str]],
    ) -> None:
        from dast.proxy.plugin_manager import log_event

        headers = base_headers(entry)
        # Tag as agent traffic: "agent" is the source the store keeps authoritative
        # and that auto-scan, session intelligence and the passive observers skip,
        # so the probe is recorded in history without being re-scanned or analysed
        # as genuine traffic.
        headers["x-dast-source"] = "agent"
        injections: List[OobInjection] = []
        for name, template in specs:
            injection = self._correlator.new_injection(
                entry_id=entry.id, url=entry.url, method=entry.method,
                location="header", name=name, template=template,
            )
            if injection is not None:
                headers[name] = injection.value
                injections.append(injection)
        if not injections:
            return
        body = entry.request_body or None
        try:
            response = await client.request(entry.method, entry.url, headers=headers, content=body)
        except Exception as exc:
            logger.warning("Header OOB probe failed", url=entry.url, error=str(exc))
            return
        response_text = response.text or ""
        for injection in injections:
            injection.reflected = injection.value in response_text
        self._correlator.track()
        logger.debug("Header OOB probe sent", url=entry.url, headers=len(injections),
                     status=response.status_code)
        log_event(_PLUGIN_NAME, "info",
                  f"Injected {len(injections)} OOB header markers; watching for callbacks",
                  url=entry.url, source="plugin")

    async def _on_hit(self, hit: OobHit) -> None:
        from dast.proxy.plugin_manager import log_event

        if self._store is None:
            return
        finding = build_finding(hit)
        # Same convention as the scan worker: held findings also mark the entry
        # "vulnerable"; the finding's confirmed / needs_review flags drive the UI.
        self._store.add_finding(hit.injection.entry_id, finding, "vulnerable")
        logger.info("Header OOB finding", url=hit.injection.url, header=hit.injection.name,
                    protocol=hit.protocol, confirmed=finding["confirmed"])
        log_event(_PLUGIN_NAME, "finding", str(finding["title"]),
                  url=hit.injection.url, finding=str(finding["title"]), source="plugin")

    async def teardown(self) -> None:
        await self._correlator.stop()

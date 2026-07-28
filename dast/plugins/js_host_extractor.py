"""
JS Host Extractor plugin — scans JavaScript response bodies for hardcoded
hostnames, URLs, and IP addresses that may indicate undiscovered API endpoints,
internal services, or staging environments.
"""

import re

from dast.proxy.plugin_base import ProxyPlugin

_URL_RE   = re.compile(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})(?:[:/][^\s"\'`<>]*)?')
_IP_RE    = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
_HOST_RE  = re.compile(r'["\']([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){2,})["\']')

_NOISE = {
    "example.com", "localhost", "schema.org", "w3.org",
    "mozilla.org", "google.com", "cdn.jsdelivr.net",
}


class JsHostExtractorPlugin(ProxyPlugin):
    name        = "js-host-extractor"
    description = "Extracts hardcoded hostnames and URLs from JavaScript responses"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry, store) -> None:
        ct = (entry.content_type or "").lower()
        if "javascript" not in ct and not entry.path.endswith(".js"):
            return
        if not entry.response_body:
            return

        try:
            body = entry.response_body.decode("utf-8", errors="replace")
        except Exception:
            return

        found: set[str] = set()

        for m in _URL_RE.finditer(body):
            host = m.group(1).lower()
            if host not in _NOISE and host != entry.host:
                found.add(m.group(0)[:120])

        for m in _IP_RE.finditer(body):
            ip = m.group(0)
            if not ip.startswith(("127.", "0.", "255.")):
                found.add(ip)

        for m in _HOST_RE.finditer(body):
            host = m.group(1).lower()
            if host not in _NOISE and host != entry.host and "." in host:
                found.add(host)

        if not found:
            return

        store.add_finding(
            entry.id,
            {
                "title": f"Hardcoded hosts found in JavaScript ({len(found)} unique)",
                "severity": "informational",
                "attack_type": "js-host-extractor",
                "confidence": 0.7,
                "evidence": "\n".join(sorted(found)[:20]),
                "confirmed": False,
            },
            "safe",
        )

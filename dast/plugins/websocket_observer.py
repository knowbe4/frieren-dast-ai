"""
WebSocket observer plugin — passively catalogues WebSocket endpoints.

Fires on observed WebSocket handshakes (GET with Upgrade: websocket answered by
101). Two deterministic checks:

  - The handshake succeeded while the browser-supplied Origin header belongs to
    a different host than the WS endpoint — evidence the server does not
    validate Origin, i.e. cross-site WebSocket hijacking is possible (medium).
  - Otherwise the endpoint is catalogued informationally (recon value: WS
    endpoints are attack surface that plain HTTP crawling never shows).

No probes are sent; the Origin-mismatch finding only fires when such traffic
was genuinely observed through the proxy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from dast.proxy.plugin_base import ProxyPlugin
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

# One catalogue entry per WS endpoint (host + path); the Origin-mismatch check
# fires once per endpoint as well — repeated frames would re-fire otherwise.
_seen_endpoints: set[tuple[str, str]] = set()


def _origin_mismatch(entry: "ProxyEntry") -> bool:
    """True when the handshake's Origin header host differs from the WS host."""
    headers = {k.lower(): v for k, v in (entry.request_headers or {}).items()}
    origin = headers.get("origin", "")
    if not origin:
        return False
    origin_host = (urlparse(origin).hostname or "").lower()
    ws_host = (entry.host or "").lower()
    if not origin_host or not ws_host:
        return False
    return origin_host != ws_host and not origin_host.endswith("." + ws_host) and not ws_host.endswith("." + origin_host)


class WebsocketObserverPlugin(ProxyPlugin):
    name = "websocket-observer"
    description = "Catalogues WebSocket endpoints and flags handshakes that accepted a cross-origin Origin"
    version = "1.0.0"
    author = "Frieren DAST-AI"
    enabled = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        # Skip the scanner's own injected requests.
        if getattr(entry, "source", "proxy") not in ("proxy", "browse"):
            return
        headers = {k.lower(): v for k, v in (entry.request_headers or {}).items()}
        if headers.get("upgrade", "").lower() != "websocket":
            return
        if entry.response_status != 101:
            # Failed handshake (4xx/3xx) — not a live WS endpoint.
            return

        endpoint_key = (entry.host or "", entry.path or "")
        first_seen = endpoint_key not in _seen_endpoints
        _seen_endpoints.add(endpoint_key)

        if _origin_mismatch(entry):
            store.add_finding(
                entry.id,
                {
                    "title": "WebSocket Handshake Accepted Without Origin Validation",
                    "severity": "medium",
                    "cwe": "CWE-346",
                    "attack_type": "websocket",
                    "evidence": (
                        f"WebSocket endpoint wss://{entry.host}{entry.path} completed the 101 "
                        f"handshake although the request Origin was for a different host — "
                        f"cross-site WebSocket hijacking (CSWSH) is possible when the server "
                        f"authenticates by cookie."
                    ),
                    "confirmed": False,
                    "validated_by": ["pattern"],
                },
                "safe",
            )
            return

        if first_seen:
            store.add_finding(
                entry.id,
                {
                    "title": f"WebSocket Endpoint Observed ({entry.host}{entry.path})",
                    "severity": "informational",
                    "attack_type": "websocket",
                    "evidence": (
                        f"101 Switching Protocols handshake on {entry.method} {entry.path}. "
                        f"WebSocket endpoints accept messages outside the HTTP scanning "
                        f"pipeline — review the message schema manually."
                    ),
                    "confirmed": False,
                    "validated_by": ["pattern"],
                },
                "safe",
            )

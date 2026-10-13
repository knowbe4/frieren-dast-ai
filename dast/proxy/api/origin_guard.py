"""
Origin guard — ASGI middleware that keeps the dashboard reachable only from itself.

The dashboard binds to 127.0.0.1 and has no login, so the only thing stopping an
arbitrary website open in the operator's browser from driving it is the browser's
same-origin policy. That policy is not enough on its own:

  * Many routes parse the body with ``await request.json()``, which ignores the
    Content-Type. A cross-site ``text/plain`` POST is a "simple request" (no CORS
    preflight), so a hostile page could import findings, start scans, or fire
    Repeater/Intruder requests into the local network.
  * WebSockets are not covered by CORS at all. Without an Origin check any page
    could open ``/ws`` and read every captured request (cookies, auth headers).
  * DNS rebinding lets a hostile domain resolve to 127.0.0.1 and read GET routes.

Two checks close all three:

  1. Host header must be a loopback name (defeats DNS rebinding).
  2. For state-changing methods and WebSocket handshakes, a present ``Origin``
     header must equal the dashboard's own origin (``http://<Host>``).

Requests without an Origin header (curl, the desktop launcher's health checks,
same-origin GETs) are allowed — browsers always send Origin on cross-origin
POSTs and on WebSocket handshakes, which is exactly the traffic we must reject.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Iterable, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

Scope = dict
Receive = Callable[[], Awaitable[dict]]
Send = Callable[[dict], Awaitable[None]]


def _header(scope: Scope, name: bytes) -> Optional[str]:
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _hostname(host_header: str) -> str:
    """Strip the port from a Host header value, keeping IPv6 brackets."""
    if host_header.startswith("["):
        closing = host_header.find("]")
        return host_header[: closing + 1] if closing != -1 else host_header
    return host_header.rsplit(":", 1)[0] if ":" in host_header else host_header


def is_allowed_host(host_header: Optional[str], allowed_hostnames: Iterable[str]) -> bool:
    if not host_header:
        return False
    return _hostname(host_header.strip().lower()) in allowed_hostnames


def is_allowed_origin(origin: Optional[str], host_header: Optional[str]) -> bool:
    """True when no Origin is sent, or it is exactly this dashboard's own origin."""
    if origin is None:
        return True
    if not host_header:
        return False
    return origin.strip().lower() == f"http://{host_header.strip().lower()}"


class OriginGuardMiddleware:
    """Reject non-loopback Host headers and cross-origin state-changing requests."""

    def __init__(self, app, extra_allowed_hostnames: Iterable[str] = ()) -> None:
        self.app = app
        self.allowed_hostnames = _LOOPBACK_HOSTNAMES | {h.lower() for h in extra_allowed_hostnames}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        host_header = _header(scope, b"host")
        origin = _header(scope, b"origin")
        path = scope.get("path", "")

        if not is_allowed_host(host_header, self.allowed_hostnames):
            logger.warning("Dashboard request rejected — non-loopback Host", host=host_header, path=path)
            await self._reject(scope, receive, send)
            return

        needs_origin_check = scope_type == "websocket" or scope.get("method", "GET") not in _SAFE_METHODS
        if needs_origin_check and not is_allowed_origin(origin, host_header):
            logger.warning("Dashboard request rejected — cross-origin", origin=origin, path=path)
            await self._reject(scope, receive, send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            # Closing before accept makes the server answer the handshake with 403.
            await receive()
            await send({"type": "websocket.close", "code": 1008})
            return
        body = b'{"error":"forbidden"}'
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})

"""CSWSH agent — Cross-Site WebSocket Hijacking with a raw handshake.

Round 4-B, closing the gap the audit found: WebSocket endpoints were only
covered PASSIVELY (``plugins/websocket_observer.py`` observes 101s and the
Blazor agent probes the SignalR *negotiate* POST) — nobody performed the real
``Upgrade: websocket`` handshake with an attacker Origin.

Technique: replay the captured request as a raw WS handshake with
``Origin: <attacker>`` over a direct socket (httpx cannot speak WS, and the
MITM re-frames upgrades — the same reason ``smuggling_agent`` uses raw
sockets; the transport idiom is shared with it). A ``101 Switching Protocols``
whose ``Sec-WebSocket-Accept`` validates for OUR key proves the endpoint
performs no Origin validation — any web page the victim has open could have
opened this socket with the victim's cookies (CWE-346).

Severity discipline: HIGH only when session cookies were attached (a browser
on the victim's session would authenticate the socket); without cookies the
handshake proves the missing validation but not victim impact → informational
and unconfirmed. Discovery channel: ``websocket_observer`` now tags 101
entries with ``focus_attack_types=["websocket"]``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import is_host_dead
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_CONNECT_TIMEOUT_S = 10.0
_READ_TIMEOUT_S = 8.0
_WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_EVIL_ORIGIN = "https://evil-attacker.test"
# Hop-by-hop / handshake-owned headers we never copy from the captured request.
_DROPPED = {"host", "upgrade", "connection", "sec-websocket-key",
            "sec-websocket-version", "sec-websocket-accept", "origin",
            "content-length", "transfer-encoding", "x-dast-source",
            "x-dast-crawler", "x-dast-payload", "proxy-connection"}


def _expected_accept(key: str) -> str:
    digest = hashlib.sha1((key + _WS_MAGIC).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _build_handshake(target: "CheckTarget", origin: str, key: str) -> bytes:
    """Raw WS handshake for the captured URL with an attacker Origin. Session
    cookies (and other non-hop-by-hop captured headers) ride along — that is
    the victim-socket position."""
    parsed = urlparse(target.url)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    host = parsed.netloc  # includes :port when non-default
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"Origin: {origin}",
    ]
    for k, v in (target.headers or {}).items():
        if k.lower() in _DROPPED:
            continue
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def _parse_head(data: bytes) -> Optional[Tuple[int, Dict[str, str]]]:
    """Parse the response head (status line + headers up to the first
    \\r\\n\\r\\n). Returns (status, lowercased-header dict) or None."""
    head_end = data.find(b"\r\n\r\n")
    if head_end < 0:
        return None
    try:
        text = data[:head_end].decode("latin-1")
    except UnicodeDecodeError:
        return None
    lines = text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/1."):
        return None
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        return None
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers


async def _send_handshake(host: str, port: int, use_tls: bool,
                          payload: bytes) -> Optional[Tuple[int, Dict[str, str]]]:
    """One direct connection, one handshake, read the response head. Never
    raises; returns None on any transport failure (best-effort like smuggling)."""
    ssl_ctx = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx),
            timeout=_CONNECT_TIMEOUT_S,
        )
        writer.write(payload)
        await writer.drain()
        data = b""
        deadline = time.monotonic() + _READ_TIMEOUT_S
        while time.monotonic() < deadline and len(data) < 65536:
            if b"\r\n\r\n" in data:
                break
            try:
                chunk = await asyncio.wait_for(
                    reader.read(4096), timeout=max(0.1, deadline - time.monotonic()))
            except (asyncio.TimeoutError, ConnectionError, OSError):
                break
            if not chunk:
                break
            data += chunk
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 — close is best-effort
            pass
        return _parse_head(data)
    except Exception as exc:  # noqa: BLE001 — probing is best-effort, never crash
        logger.debug("cswsh: raw handshake failed", host=host, error=str(exc)[:160])
        return None


class CswshAgent(VulnAgent):
    name = "CSWSH Agent"
    attack_type = "cswsh"
    description = (
        "Cross-Site WebSocket Hijacking: raw Upgrade handshake with an attacker "
        "Origin — 101 with a valid Sec-WebSocket-Accept proves no Origin validation"
    )

    async def run(
        self,
        target: "CheckTarget",
        client=None,  # unused — raw sockets bypass the shared client
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        focus = [t.lower() for t in (getattr(target, "focus_attack_types", None) or [])]
        upgrade_hdr = ""
        for k, v in (target.headers or {}).items():
            if k.lower() == "upgrade":
                upgrade_hdr = str(v).lower()
        if target.url.lower().startswith(("ws://", "wss://")):
            use_tls = target.url.lower().startswith("wss://")
        else:
            use_tls = target.url.lower().startswith("https://")
        ws_hinted = ("websocket" in focus or "cswsh" in focus
                     or upgrade_hdr == "websocket"
                     or target.url.lower().startswith(("ws://", "wss://")))
        if not ws_hinted:
            return []  # plain HTTP endpoints are not WS candidates

        parsed = urlparse(target.url if not target.url.lower().startswith(("ws://", "wss://"))
                          else target.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1))
        host = parsed.hostname or ""
        if not host or is_host_dead(host):
            return []
        port = parsed.port or (443 if use_tls else 80)

        has_session_cookie = any(k.lower() == "cookie" for k in (target.headers or {}))

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        payload = _build_handshake(target, _EVIL_ORIGIN, key)
        result = await _send_handshake(host, port, use_tls, payload)
        if result is None:
            return []
        status, headers = result
        if status != 101:
            return []  # origin rejected / endpoint is not a WS endpoint at all
        if headers.get("sec-websocket-accept") != _expected_accept(key):
            return []  # not a genuine WS handshake — do not report noise

        log_event("agent", "finding",
                  f"CSWSH: WebSocket handshake accepted with attacker Origin on {target.url}",
                  url=target.url, finding="Cross-Site WebSocket Hijacking", source="agent")
        with_cookies = has_session_cookie
        raw = payload.decode("latin-1", errors="replace")
        return [AgentFinding(
            title="Cross-Site WebSocket Hijacking — Handshake Accepted Without Origin Validation",
            severity="high" if with_cookies else "info",
            cwe="CWE-346",
            attack_type="cswsh",
            evidence=(
                f"A WebSocket handshake for {target.url} with attacker Origin "
                f"'{_EVIL_ORIGIN}' was answered with 101 Switching Protocols and a "
                f"valid Sec-WebSocket-Accept — the endpoint performs NO Origin "
                f"validation."
                + (" Session cookies were attached by the captured request, so a "
                   "malicious page could open this socket under the victim's "
                   "identity and read frames."
                   if with_cookies else
                   " No session cookie was present in the captured request — the "
                   "missing Origin validation is confirmed, but victim impact "
                   "depends on how browsers authenticate this socket.")
                + f"\n\nHandshake:\n{raw[:2000]}"
            ),
            confirmed=with_cookies,
            payload=f"Origin: {_EVIL_ORIGIN}",
            parameter="Origin",
            url=target.url,
            request_method="GET",
            bypass_validation=True,
            raw_request=raw[:2000],
            raw_response="",
        )]


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(CswshAgent)

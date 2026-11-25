"""
Out-of-band (OOB) interaction listener — detects blind SSRF, XXE, and
command injection that produce DNS/HTTP callbacks rather than inline
evidence.

Usage:
    async with CollaboratorService() as col:
        token = col.issue_token()          # unique per check
        payload = f"http://{col.host}:{col.port}/{token}"
        # ... inject payload into request ...
        await asyncio.sleep(2)
        hit = col.was_hit(token)

The service binds a random high port and listens for plain-text HTTP
GET requests. Each inbound request path is treated as the token.
"""

from __future__ import annotations

import asyncio
import random
import re
from typing import Optional, Set
from urllib.parse import unquote, urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Redirect-chain targets (5-B-2) are restricted to internal/private space — the
# collaborator must never become an open redirect to attacker infrastructure.
# External `to` values get a 403 and no redirect.
_INTERNAL_HOSTNAME_RE = re.compile(
    r"^(localhost|127\.|10\.|192\.168\.|169\.254\.|100\.100\.100\.|"
    r"172\.(1[6-9]|2\d|3[01])\.|\[::1\]|.*\.internal|.*\.localhost)",
    re.IGNORECASE,
)


def _is_internal_redirect_target(to_url: str) -> bool:
    """True when ``to_url`` is an http(s) URL to private/internal space."""
    try:
        parsed = urlparse(to_url)
    except Exception:  # noqa: BLE001 — malformed values just fail the gate
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    return bool(_INTERNAL_HOSTNAME_RE.match(parsed.hostname.lower()))


class CollaboratorService:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._host = host
        self._requested_port = port
        self._port: int = 0
        self._server: Optional[asyncio.Server] = None
        self._hits: Set[str] = set()

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    def issue_token(self) -> str:
        return f"dast{random.randint(100000, 999999)}"

    def was_hit(self, token: str) -> bool:
        """True when a callback carrying ``token`` arrived.

        Matches the exact path OR any sub-path under it: XXE payload templates fetch
        resources BENEATH the callback URL (``CALLBACK_URL/xxe.dtd``), which the
        listener records as ``<token>/xxe.dtd`` — exact membership would silently
        miss every such hit. SSRF-style tokens (whole path) still match exactly."""
        if token in self._hits:
            return True
        prefix = f"{token}/"
        return any(path.startswith(prefix) for path in self._hits)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle,
            host=self._host,
            port=self._requested_port,
        )
        self._port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> "CollaboratorService":
        await self.start()
        return self

    async def __aexit__(self, *_) -> None:
        await self.stop()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            line = data.decode("utf-8", errors="replace").split("\n")[0]
            # Parse first line: "GET /TOKEN HTTP/1.1" or "GET /redirect/TOKEN?to=… HTTP/1.1"
            parts = line.strip().split()
            if len(parts) >= 2:
                target_path = parts[1].lstrip("/")
                if target_path:
                    self._hits.add(target_path)
                    # 5-B-2 redirect-chain: also record the bare token so
                    # was_hit(token) matches both the initial /redirect/<token>
                    # fetch and the followed /follow/<token> second stage.
                    base = target_path.split("?", 1)[0]
                    segment = base.split("/", 1)
                    if len(segment) == 2 and segment[0] in ("redirect", "follow") and segment[1]:
                        self._hits.add(segment[1])
                if target_path.startswith("redirect/") and "?to=" in target_path:
                    # Serve the 302 the redirect-chain payloads rely on: the
                    # target's SSRF allowlist sees the collaborator (external),
                    # the server-side fetch follows to the internal `to` target.
                    # `to` is restricted to internal/private space — never an
                    # open redirect to the outside.
                    _, _, to_value = target_path.partition("?to=")
                    to_url = unquote(to_value)
                    if _is_internal_redirect_target(to_url):
                        writer.write(
                            f"HTTP/1.0 302 Found\r\nLocation: {to_url}\r\n"
                            "Content-Length: 0\r\n\r\n".encode()
                        )
                    else:
                        logger.debug("Collaborator: refused external redirect target",
                                     to=to_url[:120])
                        writer.write(b"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
                    return
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except Exception as exc:
            logger.debug("Collaborator: callback handling failed", error=str(exc))
        finally:
            try:
                writer.close()
            except Exception as exc:
                logger.debug("Collaborator: writer close failed", error=str(exc))

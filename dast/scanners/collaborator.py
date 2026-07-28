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
from typing import Optional, Set


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
        return token in self._hits

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
            # Parse first line: "GET /TOKEN HTTP/1.1"
            parts = line.strip().split()
            if len(parts) >= 2:
                path = parts[1].lstrip("/")
                if path:
                    self._hits.add(path)
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

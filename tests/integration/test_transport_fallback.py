"""Integration: the Phase 2 API->browser transport fallback over the REAL stack.

A plain API request (fresh httpx, no browser session) gets 401 from an endpoint that requires
the session cookie; the live AgentBrowser — which holds that cookie after navigating — reaches
it via page.request.fetch and gets 200. This is the api.phisher shape in miniature (a token the
API path cannot carry but the browser session can), proven end to end through
CopilotSession._browser_fallback -> run_tool("browser_fetch") -> _fetch -> page.request.fetch,
including the learned-capability seeding.

Deterministic and CI-safe: a loopback server on 127.0.0.1:0, real Chromium (skipped when
unavailable), no proxy, no LLM, no network.
"""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import AsyncIterator, Iterator

import httpx
import pytest
import pytest_asyncio

from dast.ai.copilot.session import CopilotSession
from dast.tools import ToolContext, run_tool
from tests.fixtures.login_pages.browser_harness import (
    chromium_available,
    proxyless_agent_browser,
)

pytestmark = pytest.mark.skipif(not chromium_available(), reason="chromium not installed")

_SESSION_COOKIE = "sid=live-session"


class _Handler(BaseHTTPRequestHandler):
    """`/` sets the session cookie + returns a tiny page; `/api/data` needs that cookie
    (200 with it, 401 without) — the transport asymmetry the browser session resolves."""

    def log_message(self, *args) -> None:  # silence
        pass

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_response(200)
            self.send_header("Set-Cookie", f"{_SESSION_COOKIE}; Path=/")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>app</body></html>")
            return
        if self.path.startswith("/api/data"):
            if _SESSION_COOKIE in (self.headers.get("Cookie") or ""):
                body = json.dumps({"ok": True, "data": "secret"}).encode()
                self.send_response(200)
            else:
                body = json.dumps({"error": "unauthorized"}).encode()
                self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


@contextlib.contextmanager
def _server() -> Iterator[str]:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


class _Scope:
    def is_in_scope(self, url: str) -> bool:
        return url.startswith("http://127.0.0.1:")


@pytest_asyncio.fixture
async def agent() -> AsyncIterator:
    async with proxyless_agent_browser() as browser:
        yield browser


@pytest.mark.asyncio
async def test_api_401_falls_back_to_browser_and_is_learned(agent, tmp_path, monkeypatch):
    from dast.session import transport_capability
    monkeypatch.setattr(transport_capability, "_DIR", tmp_path / "transport_capability")

    with _server() as base:
        api_url = f"{base}/api/data"

        # Baseline: a plain API request with no browser session is rejected.
        async with httpx.AsyncClient() as client:
            direct = await client.get(api_url)
        assert direct.status_code == 401

        # The browser acquires the session cookie by loading the app.
        await agent.navigate(base + "/")

        ctx = ToolContext(settings=_Scope(), browser=agent, store=None)
        session = CopilotSession("s-integration")

        # The fallback re-issues the 401'd API request via the browser session -> 200.
        result = await session._browser_fallback(
            ctx, {"url": api_url, "method": "GET"}, run_tool)
        assert result is not None
        assert result["status"] == 200
        assert "transport=browser" in result.get("note", "")
        assert "secret" in result.get("body", "")

        # And the host is learned to prefer the browser transport.
        rec = transport_capability.capability_for("127.0.0.1", "/api/data")
        assert rec is not None and rec["prefer"] == "browser"

"""Integration: the Bearer-refresh ladder re-mints a SHORT-TTL in-memory token over the REAL
stack. This guards the short-TTL in-memory Bearer case (a token that expires within minutes, held in the
SPA's JS and re-minted on load) deterministically in CI, without the live target — and it would
have caught the bug where `_browser_on_host` read a non-existent `.page` and the WAIT_SPA/RELOAD
re-mint tiers silently never fired against a real browser.

A loopback "SPA": `/` mints a fresh short-TTL JWT on every load and calls `/api/data` with it;
`/api/data` requires a non-expired Bearer. A real AgentBrowser loads it; when the only token in
history is expired, `refresh_bearer` must RELOAD the SPA so it re-mints, capture the fresh token,
and recover. Real Chromium (skipped when unavailable), no proxy, no LLM, no network.
"""

from __future__ import annotations

import base64
import contextlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from typing import AsyncIterator, Iterator
from urllib.parse import urlparse

import pytest
import pytest_asyncio

from dast.ai.copilot.session import CopilotSession, RefreshTier
from tests.fixtures.login_pages.browser_harness import (
    chromium_available,
    proxyless_agent_browser,
)

pytestmark = pytest.mark.skipif(not chromium_available(), reason="chromium not installed")

_TTL = 120  # seconds — short-lived, short-lived, like a real in-memory SPA token


def _mint_jwt() -> str:
    def seg(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    # Unique per call (iat) so each load's token is distinct; short exp.
    return (f"{seg({'alg': 'HS256', 'typ': 'JWT'})}."
            f"{seg({'exp': int(time.time()) + _TTL, 'iat': time.time()})}.sig")


def _exp_of(token: str) -> float:
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    return float(json.loads(base64.urlsafe_b64decode(payload))["exp"])


_PAGE = b"""<!doctype html><html><body>
<div>a</div><div>b</div><div>c</div><button>go</button>
<script>
(async () => {
  const t = await (await fetch('/mint')).text();
  await fetch('/api/data', {headers: {'Authorization': 'Bearer ' + t}});
})();
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a) -> None:
        pass

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_response(200); self.send_header("Content-Type", "text/html")
            self.end_headers(); self.wfile.write(_PAGE); return
        if self.path == "/mint":
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.end_headers(); self.wfile.write(_mint_jwt().encode()); return
        if self.path.startswith("/api/data"):
            auth = self.headers.get("Authorization") or ""
            ok = False
            if auth.lower().startswith("bearer "):
                with contextlib.suppress(Exception):
                    ok = _exp_of(auth.split(" ", 1)[1]) > time.time()
            self.send_response(200 if ok else 401)
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"ok":true}' if ok else b'{"error":"unauthorized"}')
            return
        self.send_response(404); self.end_headers()


@contextlib.contextmanager
def _server() -> Iterator[str]:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


class _CaptureStore:
    """Stands in for the proxy store: records the SPA's own /api/data Bearer requests."""
    def __init__(self) -> None:
        self.entries: list = []

    def all_entries(self) -> list:
        return list(self.entries)

    def _on_request(self, request) -> None:
        auth = request.headers.get("authorization") or ""
        if "/api/data" in request.url and auth.lower().startswith("bearer "):
            self.entries.append(SimpleNamespace(
                host=urlparse(request.url).hostname or "", path=urlparse(request.url).path,
                source="proxy", id=f"e{len(self.entries)}",
                request_headers={"Authorization": auth}))


@pytest_asyncio.fixture
async def agent() -> AsyncIterator:
    async with proxyless_agent_browser() as browser:
        yield browser


@pytest.mark.asyncio
async def test_refresh_ladder_remints_short_ttl_token_via_reload(agent):
    with _server() as base:
        host = urlparse(base).hostname or "127.0.0.1"
        store = _CaptureStore()
        agent._page.on("request", store._on_request)

        await agent.navigate(base + "/")          # SPA mints a token and calls /api/data
        assert store.entries, "the SPA should have called /api/data with a Bearer on load"

        # Simulate the failure state: the only token Frieren has is EXPIRED (history + cache).
        store.entries = []
        expired = (f"{base64.urlsafe_b64encode(json.dumps({'alg':'HS256'}).encode()).rstrip(b'=').decode()}."
                   f"{base64.urlsafe_b64encode(json.dumps({'exp': int(time.time()) - 60}).encode()).rstrip(b'=').decode()}.sig")
        store.entries.append(SimpleNamespace(host=host, path="/api/data", source="proxy", id="old",
                                             request_headers={"Authorization": f"Bearer {expired}"}))
        session = CopilotSession("s-shortttl")
        session._bearer_tokens[host] = {"token": expired, "exp": time.time() - 60, "auth_endpoint": ""}
        assert not session._rec_is_fresh(session._select_bearer(host, "/api/data"))

        # The ladder must RELOAD the SPA (re-mint) and recover a fresh token.
        outcome = await session.refresh_bearer(
            store, host, "/api/data", browser=agent,
            max_tier=RefreshTier.RELOAD, timeout_s=4, reason="401")

        assert outcome.tier_reached == RefreshTier.RELOAD
        assert outcome.acted is True
        assert outcome.record and session._rec_is_fresh(outcome.record)
        assert outcome.record["token"] != expired   # a freshly re-minted token
        assert outcome.record["exp"] > time.time()

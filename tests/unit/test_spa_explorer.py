"""
Browser-level test for SpaExplorer against a local static multi-route SPA.

Exercises the behaviours that the old crawler missed: following hash routes and
routerLink attributes, descending open shadow DOM, hover-revealed menu links, and
(opt-in) filling + submitting a form. The explorer normally routes through the
MITM proxy; here we monkeypatch its launcher to a plain local browser so the test
needs no proxy — it validates traversal/frontier logic, not proxy capture.

Skipped automatically when Playwright/Chromium is unavailable.
"""

from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from dast.proxy import spa_explorer
from dast.proxy.session_store import SessionStore
from dast.proxy.ui_route_graph import normalise_route_key

playwright = pytest.importorskip("playwright.async_api")

# One page serves the same SPA shell for every GET path, so every discovered
# route "exists" and returns 200. A button reveals an extra link only on hover
# (to prove hover-reveal), and there is a form that POSTs to /submit.
_SPA_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>fixture</title></head>
<body>
  <nav>
    <a href="/#/dashboard">Dashboard</a>
    <a href="/#/settings">Settings</a>
    <span routerLink="/reports">Reports</span>
  </nav>
  <button id="menu" aria-haspopup="true">Menu</button>
  <div id="flyout"></div>
  <form action="/submit" method="post">
    <input name="org_name" type="text">
    <input name="contact_email" type="email">
    <button type="submit">Save</button>
  </form>
  <my-widget></my-widget>
  <script>
    // Shadow DOM hosting a link the plain collector would miss.
    const w = document.querySelector('my-widget');
    const root = w.attachShadow({mode: 'open'});
    root.innerHTML = '<a href="/shadow-page">Shadow Link</a>';
    // Hover-only link: inserted into #flyout when the menu is hovered.
    document.getElementById('menu').addEventListener('mouseenter', () => {
      document.getElementById('flyout').innerHTML = '<a href="/hovered">Hovered</a>';
    });
  </script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_SPA_HTML.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.posted.append(self.path)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture
def spa_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.posted = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()


def _patched_launcher(monkeypatch):
    """Replace the proxied launcher with a plain local Chromium (no proxy)."""
    @asynccontextmanager
    async def _ctx(store, proxy_port, session_id, *, read_only=False, headless=True, log_cb=None):
        async with playwright.async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                page = await context.new_page()
                yield context, page, [0]
            finally:
                await browser.close()
    monkeypatch.setattr(spa_explorer, "proxied_browser_context", _ctx)


async def _run_explorer(server_url, *, submit_forms):
    store = SessionStore()
    stop = asyncio.Event()
    explorer = spa_explorer.SpaExplorer(store, lambda m: None, stop, proxy_port=0)
    await explorer.run(server_url, read_only=False, submit_forms=submit_forms, headless=True)
    return store


@pytest.mark.asyncio
async def test_explorer_drains_frontier_across_route_types(spa_server, monkeypatch):
    _server, url = spa_server
    _patched_launcher(monkeypatch)
    store = await _run_explorer(url, submit_forms=False)
    graph = store.ui_route_graph

    stats = graph.stats()
    assert stats["frontier"] == 0, "frontier must be fully drained"
    assert stats["visited"] >= 5

    visited_keys = {r.route_key for r in graph.visited()}
    host = normalise_route_key(url).split("/")[0]
    # routerLink, shadow-DOM link, and hover-revealed link were all discovered+visited.
    assert f"{host}/reports" in visited_keys
    assert f"{host}/shadow-page" in visited_keys
    assert f"{host}/hovered" in visited_keys


@pytest.mark.asyncio
async def test_explorer_submits_forms_only_when_opted_in(spa_server, monkeypatch):
    server, url = spa_server
    _patched_launcher(monkeypatch)

    store = await _run_explorer(url, submit_forms=False)
    assert server.posted == [], "no form POST without submit_forms"
    assert store.ui_route_graph.stats()["forms_submitted"] == 0

    server.posted.clear()
    store = await _run_explorer(url, submit_forms=True)
    assert "/submit" in server.posted
    assert store.ui_route_graph.stats()["forms_submitted"] >= 1

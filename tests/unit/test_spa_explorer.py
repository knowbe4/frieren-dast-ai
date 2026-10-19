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
    # HTTP/1.1 + Content-Length so responses terminate cleanly and Playwright's
    # `networkidle` resolves promptly (a real server always sends Content-Length).
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        body = _SPA_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.posted.append(self.path)  # type: ignore[attr-defined]
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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


# ── vision fallback: canvas nav that DOM/AX can't see ────────────────────────

_CANVAS_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>canvas app</title></head>
<body style="margin:0">
  <canvas id="c" width="1280" height="900"
          style="cursor:default;position:fixed;top:0;left:0;width:100vw;height:100vh"></canvas>
  <script>
    // Nav drawn on a canvas with a JS click listener — no DOM element, no ARIA
    // role, no href: invisible to querySelector and the accessibility tree. The
    // listener is on document so any coordinate click lands it (the canvas fills
    // the viewport), modelling a pixel-only UI the DOM/AX crawlers can't drive.
    document.addEventListener('click', () => {
      window.location.href = '/section-a';
    });
  </script>
</body></html>"""


class _CanvasHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 + Content-Length so the response terminates cleanly and Playwright's
    # `networkidle` resolves immediately. A default HTTP/1.0 handler leaves the load
    # state "busy" until networkidle times out, which in turn makes a subsequent raw
    # mouse.click fail to register its navigation — a test-server artifact, not a
    # product issue (real servers always send Content-Length).
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/section-a"):
            body = b"<!doctype html><html><body><h1>Section A</h1></body></html>"
        else:
            body = _CANVAS_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def canvas_server():
    server = HTTPServer(("127.0.0.1", 0), _CanvasHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_vision_fallback_navigates_canvas_nav(canvas_server, monkeypatch):
    url = canvas_server
    _patched_launcher(monkeypatch)

    # DOM/AX find nothing on the canvas page; stub the vision model to point at the
    # canvas center. The explorer must click it and discover /section-a.
    async def _fake_vision(page, invoke_json_fn, viewport):
        return [{"label": "Section A", "x": 200, "y": 150, "kind": "nav"}]
    monkeypatch.setattr(spa_explorer, "_VIEWPORT", {"width": 1280, "height": 900})
    import dast.proxy.vision_nav as vn
    monkeypatch.setattr(vn, "vision_clickables", _fake_vision)

    store = SessionStore()
    explorer = spa_explorer.SpaExplorer(store, lambda m: None, asyncio.Event(), proxy_port=0)
    await explorer.run(url, read_only=False, headless=True, vision=True)

    assert explorer._vision_calls >= 1, "vision must fire when DOM/AX find nothing"
    graph = store.ui_route_graph
    routes = {r.route_key: r for r in graph.visited() + graph.frontier()}
    host = normalise_route_key(url).split("/")[0]
    section = routes.get(f"{host}/section-a")
    assert section is not None, "vision click should discover the canvas-nav route"
    assert section.discovered_via == "vision", "the route must be attributed to vision nav"


@pytest.mark.asyncio
async def test_vision_not_used_when_flag_off(canvas_server, monkeypatch):
    url = canvas_server
    _patched_launcher(monkeypatch)
    called = {"n": 0}

    async def _fake_vision(page, invoke_json_fn, viewport):
        called["n"] += 1
        return []
    import dast.proxy.vision_nav as vn
    monkeypatch.setattr(vn, "vision_clickables", _fake_vision)

    store = SessionStore()
    explorer = spa_explorer.SpaExplorer(store, lambda m: None, asyncio.Event(), proxy_port=0)
    await explorer.run(url, read_only=False, headless=True, vision=False)  # vision OFF
    assert called["n"] == 0, "vision must not run unless explicitly enabled"

"""
End-to-end smoke test for the dashboard UI's tab/sub-tab navigation.

The UI has no dedicated frontend test framework — this is its only automated
regression guard. Runs a real uvicorn instance of the dashboard app (in a
background thread) and drives it with a real headless Chromium via Playwright,
clicking through every top-level tab and every sub-tab, plus the cross-tab
shortcut buttons (Browse<->Crawl, ->Scan). Fails if any click produces a
console error or an uncaught page exception, or if a shortcut lands on the
wrong sub-tab.

AWS/Bedrock calls are avoided entirely: prefetch_ai_status is monkeypatched to
a no-op before the app starts, and no code path exercised here calls the LLM
gateway.

Skips cleanly when Playwright chromium is not installed.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time

import pytest


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            b.close()
        return True
    except Exception:
        return False


_CHROMIUM = _chromium_available()
pytestmark = pytest.mark.skipif(not _CHROMIUM, reason="chromium not installed")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def dashboard_url(tmp_path_factory, monkeypatch_module):
    """Start a real dashboard app (uvicorn, in a background thread) and yield its base URL."""
    import uvicorn

    from dast.proxy import proxy_settings as ps_module
    from dast.proxy.api import status_routes as status_mod
    from dast.proxy.dashboard_server import build_app
    from dast.proxy.plugin_manager import PluginManager
    from dast.proxy.intercept_store import InterceptStore
    from dast.proxy.session_store import SessionStore

    tmp_settings_path = tmp_path_factory.mktemp("dashboard-ui") / "proxy-settings.json"
    monkeypatch_module.setattr(ps_module, "_SETTINGS_PATH", tmp_settings_path)

    async def _noop_prefetch(ctx):
        return None
    monkeypatch_module.setattr(status_mod, "prefetch_ai_status", _noop_prefetch)

    store = SessionStore()
    settings = ps_module.ProxySettings()
    plugin_manager = PluginManager()
    intercept_store = InterceptStore()

    app = build_app(
        store=store,
        scan_queue=asyncio.Queue(),
        settings=settings,
        plugin_manager=plugin_manager,
        intercept_store=intercept_store,
        scan_config={},
    )

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 10
    while not getattr(server, "started", False) and time.monotonic() < deadline:
        time.sleep(0.05)

    url = f"http://127.0.0.1:{port}"
    yield url

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def monkeypatch_module():
    """Module-scoped monkeypatch (pytest's built-in `monkeypatch` is function-scoped)."""
    from _pytest.monkeypatch import MonkeyPatch
    mp = MonkeyPatch()
    yield mp
    mp.undo()


TOP_LEVEL_TABS = [
    "overview", "proxy", "browse", "ai", "plugins", "graphql", "repeater", "intruder", "logs", "extras",
]
PROXY_SUB_TABS = ["history", "intercept", "sitemap", "issues", "psettings"]
BROWSE_SUB_TABS = ["manual", "crawl", "discovery"]
AI_SUB_TABS = ["suggestions", "scan", "settings"]
EXTRAS_SUB_TABS = ["h1", "code", "fedramp", "interactions", "decoder", "jwt"]
GRAPHQL_SUB_TABS = ["explorer", "fuzzer"]


@contextlib.contextmanager
def _console_error_guard(page):
    errors: list[str] = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    yield errors


def test_top_level_tabs_have_no_console_errors(dashboard_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)

            for tab in TOP_LEVEL_TABS:
                page.evaluate(f"switchMain('{tab}')")
                page.wait_for_timeout(100)

        browser.close()

    assert errors == []


def test_proxy_sub_tabs_have_no_console_errors(dashboard_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            page.evaluate("switchMain('proxy')")
            for sub in PROXY_SUB_TABS:
                page.evaluate(f"switchProxySub('{sub}')")
                page.wait_for_timeout(100)
        browser.close()

    assert errors == []


def test_browse_sub_tabs_have_no_console_errors(dashboard_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            page.evaluate("switchMain('browse')")
            for sub in BROWSE_SUB_TABS:
                page.evaluate(f"switchBrowseSub('{sub}')")
                page.wait_for_timeout(100)
        browser.close()

    assert errors == []


def test_ai_sub_tabs_have_no_console_errors(dashboard_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            page.evaluate("switchMain('ai')")
            for sub in AI_SUB_TABS:
                page.evaluate(f"switchAiSub('{sub}')")
                page.wait_for_timeout(100)
        browser.close()

    assert errors == []


def test_extras_sub_tabs_have_no_console_errors(dashboard_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            page.evaluate("switchMain('extras')")
            for sub in EXTRAS_SUB_TABS:
                page.evaluate(f"switchExtrasSub('{sub}')")
                page.wait_for_timeout(100)
        browser.close()

    assert errors == []


def test_decoder_transforms_and_layout(dashboard_url):
    """Decoder input->output round-trip works and the panel fills real height."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            page.evaluate("switchMain('extras')")
            page.evaluate("switchExtrasSub('decoder')")
            page.wait_for_timeout(150)

            # The panel must occupy real vertical space (regression: flex collapse).
            box = page.eval_on_selector(
                "#extras-sub-decoder",
                "el => { const r = el.getBoundingClientRect(); return {w: r.width, h: r.height}; }",
            )
            assert box["h"] > 300, f"decoder panel collapsed: {box}"
            assert box["w"] > 800, f"decoder panel too narrow: {box}"

            # Base64 decode round-trip.
            page.evaluate("decoderPick('b64-dec')")
            page.fill("#dec-input", "YWRtaW46cGFzcw==")
            page.wait_for_timeout(100)
            out = page.eval_on_selector("#dec-output", "el => el.textContent")
            assert out == "admin:pass", f"unexpected decode output: {out!r}"

            # Bad input yields a friendly message, not a raw JS exception.
            page.evaluate("decoderPick('b64url-dec')")
            page.fill("#dec-input", "a")
            page.wait_for_timeout(100)
            err = page.eval_on_selector("#dec-output", "el => el.textContent")
            assert "atob" not in err and "Window" not in err, f"raw error leaked: {err!r}"
            assert "Base64" in err, f"expected friendly base64 message: {err!r}"
        browser.close()

    assert errors == []


def test_jwt_decode_and_build(dashboard_url):
    """JWT tab decodes a token, builds a re-signed one via the backend route."""
    from playwright.sync_api import sync_playwright

    # HS256 token: {"alg":"HS256","typ":"JWT"} / {"sub":"1234","role":"user"}
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ."
        "dummsig"
    )

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            page.evaluate("switchMain('extras')")
            page.evaluate("switchExtrasSub('jwt')")
            page.wait_for_timeout(150)

            page.fill("#jwt-input", token)
            page.wait_for_timeout(150)
            hdr = page.eval_on_selector("#jwt-header", "el => el.value")
            pl = page.eval_on_selector("#jwt-payload", "el => el.value")
            assert '"role"' in pl and "user" in pl, f"payload not decoded: {pl!r}"
            assert '"alg"' in hdr, f"header not decoded: {hdr!r}"

            # Build a re-signed token via POST /api/jwt/build.
            page.fill("#jwt-secret", "s3cr3t")
            page.evaluate("jwtBuild()")
            page.wait_for_timeout(400)
            built = page.eval_on_selector("#jwt-output", "el => el.textContent")
            assert built.count(".") == 2 and built.startswith("eyJ"), f"bad built token: {built!r}"
        browser.close()

    assert errors == []


def test_interactions_raw_formatter(dashboard_url):
    """The raw-callback formatter decodes CRLF escapes and structures the HTTP
    interaction so the operator sees a real request, not one escaped line."""
    from playwright.sync_api import sync_playwright

    http_blob = (
        '{"protocol":"http","unique-id":"abc","remote-address":"1.2.3.4",'
        '"raw-request":"HEAD / HTTP/1.1\\r\\nHost: abc.oast.site\\r\\n'
        'User-Agent: python-requests\\r\\n\\r\\n"}'
    )
    dns_blob = '{"protocol":"dns","q-type":"A","remote-address":"9.9.9.9"}'

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)

            out = page.evaluate(f"_interactionsFormatRaw({http_blob!r})")
            # CRLF escapes are gone, real newlines present, request is labelled.
            assert "\\r\\n" not in out, f"escapes not decoded: {out!r}"
            assert "--- Request ---" in out, f"no request section: {out!r}"
            assert "HEAD / HTTP/1.1" in out
            assert "Host: abc.oast.site" in out
            assert out.count("\n") >= 4, f"not multi-line: {out!r}"

            dns_out = page.evaluate(f"_interactionsFormatRaw({dns_blob!r})")
            assert "Protocol" in dns_out and "DNS" in dns_out
            assert "Query type" in dns_out and "A" in dns_out

            # Non-JSON input is returned verbatim, never throws.
            plain = page.evaluate("_interactionsFormatRaw('just text')")
            assert plain == "just text"
        browser.close()

    assert errors == []


def test_graphql_sub_tabs_have_no_console_errors(dashboard_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)
            page.evaluate("switchMain('graphql')")
            for sub in GRAPHQL_SUB_TABS:
                page.evaluate(f"switchGraphqlSub('{sub}')")
                page.wait_for_timeout(100)
        browser.close()

    assert errors == []


def test_crawl_host_shortcut_lands_on_browse_crawl_subtab(dashboard_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)

            page.evaluate("crawlHost('example.com')")
            page.wait_for_timeout(150)

            top_active = page.evaluate("document.getElementById('mt-browse').classList.contains('on')")
            sub_active = page.evaluate("document.getElementById('st-browse-crawl').classList.contains('on')")
            crawl_url = page.evaluate("document.getElementById('crawl-url').value")

        browser.close()

    assert errors == []
    assert top_active is True
    assert sub_active is True
    assert crawl_url == "https://example.com/"


def test_browse_and_login_button_inside_crawl_switches_to_manual_subtab(dashboard_url):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        with _console_error_guard(page) as errors:
            page.goto(dashboard_url, wait_until="domcontentloaded")
            page.wait_for_timeout(500)

            page.evaluate("switchMain('browse')")
            page.evaluate("switchBrowseSub('crawl')")
            page.wait_for_timeout(100)
            page.click("#browse-sub-crawl >> text=Browse & Login")
            page.wait_for_timeout(150)

            sub_active = page.evaluate("document.getElementById('st-browse-manual').classList.contains('on')")

        browser.close()

    assert errors == []
    assert sub_active is True

"""
End-to-end regression guard for the HTTP History context menu's
"Copy as cURL" and "Copy Reproduce Link" actions.

These replace the old broken "Copy request" item, which called a
non-existent endpoint (/api/proxy/entry/{id} instead of /api/entry/{id})
and silently did nothing. Runs a real uvicorn dashboard + headless
Chromium via Playwright to drive the actual clipboard calls, not just the
HTML string builder in isolation.

Skips cleanly when Playwright chromium is not installed.
"""

from __future__ import annotations

import asyncio
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


@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    """Start a real dashboard app (uvicorn, background thread) with one
    seeded HTTP history entry; yield (base_url, entry_id)."""
    import uvicorn

    from dast.proxy import proxy_settings as ps_module
    from dast.proxy.api import status_routes as status_mod
    from dast.proxy.dashboard_server import build_app
    from dast.proxy.plugin_manager import PluginManager
    from dast.proxy.intercept_store import InterceptStore
    from dast.proxy.session_store import SessionStore

    tmp_settings_path = tmp_path / "proxy-settings.json"
    monkeypatch.setattr(ps_module, "_SETTINGS_PATH", tmp_settings_path)

    async def _noop_prefetch(ctx):
        return None
    monkeypatch.setattr(status_mod, "prefetch_ai_status", _noop_prefetch)

    store = SessionStore()
    entry_id = store.new_entry(
        "POST",
        "https://example.com/api/transfer",
        {"Content-Type": "application/json", "Authorization": "Bearer secret-token"},
        b'{"amount": "1000", "to": "attacker"}',
    )
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

    yield f"http://127.0.0.1:{port}", entry_id

    server.should_exit = True
    thread.join(timeout=5)


def _open_context_menu_on_row(page, entry_id: str) -> None:
    """Load history, switch to the Proxy tab, and right-click the seeded
    entry's row — this is the real user path that populates the IIFE-scoped
    _ctxId, not a shortcut that bypasses the actual event wiring."""
    page.evaluate("loadAllEntries()")
    page.wait_for_timeout(300)
    page.evaluate("switchMain('proxy')")
    page.wait_for_timeout(150)
    row = page.locator(f"#row-{entry_id}")
    row.wait_for(state="visible", timeout=5000)
    row.click(button="right")
    page.wait_for_timeout(150)


def test_copy_as_curl_produces_runnable_command_with_secret(dashboard):
    """The old 'Copy request' silently failed because it hit a 404 endpoint.
    Copy as cURL must fetch the real entry and put a full command — including
    the Authorization header a browser-navigation reproduction cannot send —
    onto the clipboard."""
    from playwright.sync_api import sync_playwright

    base_url, entry_id = dashboard

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(permissions=["clipboard-read", "clipboard-write"])
        page = context.new_page()
        page.goto(base_url, wait_until="domcontentloaded")
        page.wait_for_timeout(300)

        _open_context_menu_on_row(page, entry_id)
        page.click("text=Copy as cURL")
        page.wait_for_timeout(300)

        clipboard_text = page.evaluate("navigator.clipboard.readText()")
        browser.close()

    assert clipboard_text.startswith("curl ")
    assert "https://example.com/api/transfer" in clipboard_text
    assert "-X 'POST'" in clipboard_text
    assert "Authorization: Bearer secret-token" in clipboard_text
    assert "amount" in clipboard_text


def test_copy_reproduce_link_copies_working_link_to_clipboard(dashboard):
    """'Copy Reproduce Link' must copy a /api/reproduce/{id} URL — not open a
    tab automatically — so the user can paste it wherever they need (another
    tab, Slack, a ticket). Following that link must load a real page (not a
    404) with a form pre-filled from the body, an explicit OK button (no
    auto-submit — this page might be reached from a shared link), and a
    warning about the Authorization header it cannot replicate."""
    from playwright.sync_api import sync_playwright

    base_url, entry_id = dashboard

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(permissions=["clipboard-read", "clipboard-write"])
        page = context.new_page()
        page.goto(base_url, wait_until="domcontentloaded")
        page.wait_for_timeout(300)

        _open_context_menu_on_row(page, entry_id)
        page.click("text=Copy Reproduce Link")
        page.wait_for_timeout(300)

        link = page.evaluate("navigator.clipboard.readText()")
        assert link == f"{base_url}/api/reproduce/{entry_id}"

        page.goto(link, wait_until="domcontentloaded")
        assert "example.com/api/transfer" in page.content()
        assert page.locator("#repro-form").count() == 1
        assert page.locator('input[name="amount"]').input_value() == "1000"
        assert "Authorization" in page.content()
        assert "OK" in page.locator("button.go").inner_text()
        browser.close()

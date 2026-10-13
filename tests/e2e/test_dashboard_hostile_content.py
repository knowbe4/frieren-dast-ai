"""
The dashboard renders content controlled by the scanned target (paths, headers,
bodies) and by our own agents (probe requests carrying XSS payloads, LLM-written
suggestions). None of it may ever execute in the operator's browser.

Seeds a marker into every rendered field — both an HTML breakout and a JS-string
breakout for inline handlers — then walks the main views, checks every inline
handler still parses, clicks each handler that carries a marker, and asserts
no marker ran.

Regression for inline handlers built as onclick="f('${esc(v)}')" (the browser
decodes &#39; back to ' before the JS runs) and onclick="f(${JSON.stringify(v)})"
(the JSON double quote closed the attribute, injecting new attributes).
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
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _chromium_available(), reason="chromium not installed")


def _marker(tag: str) -> str:
    js = f"window.__pwned=(window.__pwned||[]).concat('{tag}')"
    js_backtick = f"window.__pwned=(window.__pwned||[]).concat(`{tag}`)"
    return (
        f'"\'><img src=x onerror="{js}"><svg onload="{js}">'
        f"');{js_backtick};//"
        f'");{js_backtick};//'
    )


@pytest.fixture
def hostile_dashboard(tmp_path, monkeypatch):
    import uvicorn

    from dast.proxy import proxy_settings as ps_module
    from dast.proxy.api import status_routes as status_mod
    from dast.proxy.dashboard_server import build_app
    from dast.proxy.intercept_store import InterceptStore
    from dast.proxy.plugin_manager import PluginManager, log_event
    from dast.proxy.session_store import SessionStore

    monkeypatch.setattr(ps_module, "_SETTINGS_PATH", tmp_path / "proxy-settings.json")

    async def _noop_prefetch(ctx):
        return None
    monkeypatch.setattr(status_mod, "prefetch_ai_status", _noop_prefetch)

    store = SessionStore()
    entry_id = store.new_entry(
        "POST",
        "https://evil.test/p" + _marker("path").replace(" ", "%20").replace('"', "%22"),
        {"X-Hdr": _marker("request_header"), "Content-Type": "application/json"},
        ('{"k": "' + _marker("request_body").replace('"', '\\"') + '"}').encode(),
    )
    store.complete_entry(
        entry_id, 200, {"content-type": "text/html", "x-r": _marker("response_header")},
        ("<html>" + _marker("response_body") + "</html>").encode(), 12.0,
    )
    for field in ("title", "evidence", "payload", "parameter", "reasoning", "snippet",
                  "raw_request", "probe_request"):
        finding = {"title": "T", "evidence": "e", "payload": "p", "parameter": "x", "reasoning": "r",
                   "snippet": "s", "cwe": "CWE-79", "attack_type": "xss", "severity": "high",
                   "confirmed": True, "validated_by": ["ai"]}
        finding[field] = _marker("finding_" + field)
        store.add_finding(entry_id, finding, "vulnerable")
    store.active_suggestions.append({
        "host": _marker("suggestion_host"), "endpoint": "GET /x", "method": "GET",
        "path": _marker("suggestion_path"), "attack_type": _marker("suggestion_type"),
        "parameter": _marker("suggestion_param"), "hypothesis": _marker("suggestion_hypothesis"),
        "severity": "info", "source": "test", "rationale": _marker("suggestion_rationale"),
        "priority": "info", "status": "pending", "body_preview": _marker("suggestion_body"),
        "ts": time.time(),
    })
    log_event("test", "warn", _marker("log_message"), url=_marker("log_url"), source="agent")

    app = build_app(
        store=store, scan_queue=asyncio.Queue(), settings=ps_module.ProxySettings(),
        plugin_manager=PluginManager(), intercept_store=InterceptStore(), scan_config={},
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not getattr(server, "started", False) and time.monotonic() < deadline:
        time.sleep(0.05)

    yield f"http://127.0.0.1:{port}", entry_id

    server.should_exit = True
    thread.join(timeout=5)


_VIEWS = [
    "switchMain('proxy'); switchProxySub('history')",
    "switchMain('proxy'); switchProxySub('sitemap')",
    "switchMain('findings')",
    "switchMain('ai')",
    "switchMain('overview')",
    "switchMain('logs')",
]

_BROKEN_HANDLERS_JS = """() => {
    const broken = [];
    for (const el of document.querySelectorAll('*')) {
        for (const attr of el.attributes) {
            if (!attr.name.startsWith('on')) continue;
            if (attr.value.includes('__pwned') && !/^on(click|change|input|dblclick|contextmenu)$/.test(attr.name)) {
                broken.push('injected attribute ' + attr.name);
                continue;
            }
            try { new Function(attr.value); } catch (e) { broken.push(attr.name + ': ' + attr.value.slice(0, 80)); }
        }
    }
    return broken;
}"""

_CLICK_MARKED_HANDLERS_JS = """() => {
    let clicked = 0;
    for (const el of document.querySelectorAll('[onclick]')) {
        if (el.getAttribute('onclick').includes('__pwned')) {
            try { el.click(); clicked++; } catch (_) {}
        }
    }
    return clicked;
}"""


def test_hostile_target_content_never_executes(hostile_dashboard):
    from playwright.sync_api import sync_playwright

    base_url, entry_id = hostile_dashboard
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page_errors: list = []
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.goto(base_url, wait_until="load")
        page.wait_for_timeout(1000)

        page.evaluate("switchMain('proxy'); switchProxySub('history')")
        page.wait_for_timeout(300)
        page.evaluate(f"(() => {{ try {{ selectRow('{entry_id}') }} catch (_) {{}} }})()")
        page.wait_for_timeout(400)

        broken: list = []
        # The request-detail "Findings" pane renders agent HTTP evidence (probe
        # requests carrying XSS payloads) into "Send to Repeater" handlers.
        page.evaluate("(() => { try { setDTab('findings') } catch (_) {} })()")
        page.wait_for_timeout(500)
        broken.extend(page.evaluate(_BROKEN_HANDLERS_JS))
        page.evaluate(_CLICK_MARKED_HANDLERS_JS)
        page.wait_for_timeout(300)
        for view in _VIEWS:
            # Tolerate views a given UI revision does not have.
            page.evaluate(f"(() => {{ try {{ {view} }} catch (_) {{}} }})()")
            page.wait_for_timeout(500)
            broken.extend(page.evaluate(_BROKEN_HANDLERS_JS))
            page.evaluate(_CLICK_MARKED_HANDLERS_JS)
            page.wait_for_timeout(300)

        executed = page.evaluate("window.__pwned || []")
        browser.close()

    assert broken == [], f"inline handlers broken or injected by hostile content: {broken[:5]}"
    assert executed == [], f"hostile content executed in the dashboard: {sorted(set(executed))}"
    assert page_errors == [], f"JS errors while rendering hostile content: {page_errors[:5]}"

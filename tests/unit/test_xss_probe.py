"""Unit tests for the deterministic ``xss_probe`` tool.

A FAKE AgentBrowser stands in for the live Playwright page: it reflects the probe's benign marker
into a chosen context (so ``classify_context`` picks that context), then, per a configurable mode,
raises a JS dialog for the delivered payloads — a marker-echoing dialog ("match"), a dialog that
does NOT carry the marker ("wrong"), or no dialog ("none"). The tests assert the tool confirms with
the right context/version and records a finding on "match", and does NOT confirm on "wrong"/"none".
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from dast.tools import xss_probe_tools as xpt


class _FakePage:
    def __init__(self, browser) -> None:
        self._browser = browser
        self.init_scripts: list = []

    async def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)

    async def evaluate(self, expr: str):
        # window._xssAlertFired read (native pop path is used by the fake) → never fired here.
        return False

    async def content(self) -> str:
        b = self._browser
        return b._dom_template.replace("{MARKER}", b.marker or "NOMARK")


class _FakeStore:
    def __init__(self) -> None:
        self.recorded: list = []

    def record_manual_finding(self, finding, url, method="GET"):
        self.recorded.append((finding, url, method))
        return "entry-xss-1"


class _FakeBrowser:
    """Reflects the marker into ``dom_template`` and fires dialogs per ``mode``.

    ``mode``: 'match' → dialog message is the number inside the delivered ``alert(...)``;
    'wrong' → a dialog with no marker; 'none' → no dialog fires.
    """

    def __init__(self, dom_template: str, point: str, mode: str = "match") -> None:
        self._dom_template = dom_template
        self.point = point
        self.mode = mode
        self._page = _FakePage(self)
        self.marker = ""
        self.navigated: list = []
        self._dialog = None

    async def _ensure_page(self):
        return self._page

    def _value(self, url: str) -> str:
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        vals = qs.get(self.point, [])
        return vals[0] if vals else ""

    async def navigate(self, url: str):
        self.navigated.append(url)
        val = self._value(url)
        if "alert(" not in val:
            # benign-marker step: remember it so content() can reflect it in context.
            self.marker = val
            self._dialog = None
            return {"ok": True, "url": url}
        self._dialog = self._dialog_for(val)
        return {"ok": True, "url": url}

    def _dialog_for(self, val: str):
        if self.mode == "none":
            return None
        if self.mode == "wrong":
            return {"type": "alert", "message": "ambient-no-marker"}
        m = re.search(r"alert\(([^)]*)\)", val)
        return {"type": "alert", "message": (m.group(1) if m else "")}

    def pop_last_dialog(self):
        dlg, self._dialog = self._dialog, None
        return dlg

    # Snapshot/fill/click unused for query location; stubbed for completeness.
    async def snapshot(self):
        return {"forms": [], "fields": [], "buttons": [], "links": []}

    async def fill(self, selector, value):
        return {"ok": True}

    async def click(self, selector, expect_nav=False):
        return {"ok": True}


class _FakeCtx:
    def __init__(self, browser, store) -> None:
        self.browser = browser
        self.store = store
        self.source_label = "copilot"
        self.proxy_port = 8080
        self.dashboard_port = 8088

    def is_in_scope(self, url):
        return True


_URL = "https://app.example.com/search"


async def test_html_body_confirms_and_records():
    browser = _FakeBrowser("<html><body><div>q = {MARKER}</div></body></html>", "q", mode="match")
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await xpt._xss_probe(ctx, {"url": _URL, "injection_point": "q"})
    assert out["ok"] is True
    assert out["confirmed"] is True
    assert out["context"] == "html_body"
    assert "alert(" in out["payload"]
    assert out["recorded_entry_id"] == "entry-xss-1"
    assert len(store.recorded) == 1
    finding = store.recorded[0][0]
    assert finding["attack_type"] == "xss"
    assert finding["cwe"] == "CWE-79"
    assert finding["validated_by"] == ["xss_probe"]
    assert finding["source"] == "copilot"
    assert finding["severity"] == "high"


async def test_angular_csti_confirms_with_version():
    dom = ('<html><head><script src="/js/angular_1-4-4.js"></script></head>'
           '<body ng-app><p>{{ {MARKER} }}</p></body></html>')
    browser = _FakeBrowser(dom, "q", mode="match")
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await xpt._xss_probe(ctx, {"url": _URL, "injection_point": "q"})
    assert out["confirmed"] is True
    assert out["context"] == "angular_expression"
    assert out["framework_version"] == "1.4"
    # A fired dialog is proof for the fixed AngularJS alert(1) vectors.
    assert out["dialog"]["message"] == "1"
    assert len(store.recorded) == 1
    assert "CSTI" in store.recorded[0][0]["title"] or "template injection" in store.recorded[0][0]["title"]


async def test_dialog_without_marker_does_not_confirm():
    browser = _FakeBrowser("<html><body><div>q = {MARKER}</div></body></html>", "q", mode="wrong")
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await xpt._xss_probe(ctx, {"url": _URL, "injection_point": "q"})
    assert out["confirmed"] is False
    assert out["context"] == "html_body"
    assert store.recorded == []


async def test_no_dialog_does_not_confirm():
    browser = _FakeBrowser("<html><body><div>q = {MARKER}</div></body></html>", "q", mode="none")
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await xpt._xss_probe(ctx, {"url": _URL, "injection_point": "q"})
    assert out["confirmed"] is False
    assert store.recorded == []


async def test_marker_not_reflected_is_not_confirmed():
    browser = _FakeBrowser("<html><body>static page, no reflection</body></html>", "q", mode="match")
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await xpt._xss_probe(ctx, {"url": _URL, "injection_point": "q"})
    assert out["confirmed"] is False
    assert out["context"] == "unknown"
    assert store.recorded == []


async def test_browser_unavailable_errors_cleanly():
    class _NoBrowserCtx(_FakeCtx):
        def __init__(self):
            super().__init__(None, _FakeStore())
    out = await xpt._xss_probe(_NoBrowserCtx(), {"url": _URL, "injection_point": "q"})
    assert out["ok"] is False
    assert "browser" in out["error"]

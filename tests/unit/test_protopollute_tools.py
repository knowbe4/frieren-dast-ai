"""Unit tests for the deterministic ``prototype_pollution_probe`` tool.

A FAKE AgentBrowser stands in for the live Playwright page. Its ``page.evaluate(READ_PROTO_JS, k)``
reads back the value the last-navigated URL assigned to the sentinel key — simulating a real
Object.prototype pollution — so every source vector "pollutes". Its ``navigate`` fires a native JS
dialog (captured via ``pop_last_dialog``) only when a delivered gadget URL contains
``alert(<marker>)`` AND the browser is in confirm mode. The tests assert: (i) a polluting source +
a firing gadget → CONFIRMED and a CWE-1321 finding recorded; (ii) a polluting source but no firing
gadget → NOT CONFIRMED and nothing recorded; (iii) an out-of-scope url is rejected.
"""

from __future__ import annotations

import re

from dast.tools import protopollute_tools as ppt

_URL = "https://lab.example.com/"


class _FakePage:
    def __init__(self, browser) -> None:
        self._browser = browser

    async def evaluate(self, expr, arg=None):
        return self._browser._read_proto(arg)


class _FakeStore:
    def __init__(self) -> None:
        self.recorded: list = []

    def record_manual_finding(self, finding, url, method="GET"):
        self.recorded.append((finding, url, method))
        return "entry-pp-1"


class _FakeBrowser:
    """Simulates Object.prototype pollution via the URL and a native gadget dialog.

    ``confirm_gadget`` → a navigated gadget URL carrying ``alert(<n>)`` fires a dialog whose
    message is ``<n>``; False → no gadget ever fires.
    """

    def __init__(self, confirm_gadget: bool = True) -> None:
        self.confirm_gadget = confirm_gadget
        self._page = _FakePage(self)
        self._last_url = ""
        self._pending = None
        self.navigated: list = []
        self.reloaded = 0

    async def _ensure_page(self):
        return self._page

    async def navigate(self, url: str):
        self.navigated.append(url)
        self._last_url = url
        m = re.search(r"alert\((\d+)\)", url)
        if m and self.confirm_gadget:
            self._pending = {"type": "alert", "message": m.group(1)}
        return {"ok": True, "url": url}

    async def reload(self):
        self.reloaded += 1
        return {"ok": True}

    def pop_last_dialog(self):
        dlg, self._pending = self._pending, None
        return dlg

    def _read_proto(self, key):
        """Return the value the last-navigated URL assigned to ``key`` (simulating the polluted
        Object.prototype), or None when the key is absent."""
        url = self._last_url or ""
        i = url.find(key)
        if i == -1:
            return None
        eq = url.find("=", i)
        if eq == -1:
            return None
        val = url[eq + 1:]
        for sep in ("&", "#"):
            j = val.find(sep)
            if j != -1:
                val = val[:j]
        return val


class _FakeCtx:
    def __init__(self, browser, store, in_scope: bool = True) -> None:
        self.browser = browser
        self.store = store
        self._in_scope = in_scope
        self.source_label = "copilot"

    def is_in_scope(self, url):
        return self._in_scope


async def test_source_found_and_gadget_confirmed_records():
    browser = _FakeBrowser(confirm_gadget=True)
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await ppt._protopollute(ctx, {"url": _URL})
    assert out["ok"] is True
    assert out["confirmed"] is True
    # first polluting source + first gadget in the library
    assert out["source_vector"] == "proto_query"
    assert out["gadget"] == "transport_url"
    assert out["recorded_entry_id"] == "entry-pp-1"
    assert len(store.recorded) == 1
    finding = store.recorded[0][0]
    assert finding["attack_type"] == "prototype_pollution"
    assert finding["cwe"] == "CWE-1321"
    assert finding["validated_by"] == ["prototype_pollution_probe"]
    assert finding["source"] == "copilot"
    assert finding["severity"] == "high"
    assert finding["polluted_property"] == "transport_url"


async def test_source_found_but_no_gadget_fires_not_confirmed():
    browser = _FakeBrowser(confirm_gadget=False)
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await ppt._protopollute(ctx, {"url": _URL})
    assert out["ok"] is True
    assert out["confirmed"] is False
    # a source DID pollute the prototype, so the verdict reports pollution-present.
    assert out["source_vector"] is not None
    assert store.recorded == []


async def test_out_of_scope_url_rejected():
    browser = _FakeBrowser(confirm_gadget=True)
    store = _FakeStore()
    ctx = _FakeCtx(browser, store, in_scope=False)
    out = await ppt._protopollute(ctx, {"url": _URL})
    assert out["ok"] is False
    assert "scope" in out["error"]
    assert store.recorded == []
    assert browser.navigated == []


async def test_browser_unavailable_errors_cleanly():
    ctx = _FakeCtx(None, _FakeStore())
    out = await ppt._protopollute(ctx, {"url": _URL})
    assert out["ok"] is False
    assert "browser" in out["error"]


async def test_pinned_unknown_gadget_rejected():
    browser = _FakeBrowser(confirm_gadget=True)
    ctx = _FakeCtx(browser, _FakeStore())
    out = await ppt._protopollute(ctx, {"url": _URL, "gadget": "no_such_gadget"})
    assert out["ok"] is False
    assert "gadget" in out["error"]

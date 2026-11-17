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


class _AngularParseSinkBrowser:
    """Models the AngularJS ``$parse`` js-string lab: the benign marker reflects into a
    single-quoted JS string that the page feeds through ``$parse`` (surface context js_string_single,
    but an Angular-expression sink). A dialog fires ONLY for the string-free Angular escape vector
    (its ``fromCharCode`` signature) — NOT for the JS-string break-out, and NOT for the moustache
    CSTI vector (which does not apply to a direct ``$parse`` of a string)."""

    _DOM = (
        '<html><head><script src="/resources/js/angular_1-4-4.js"></script></head>'
        '<body ng-app>'
        "<script>$scope.query[key] = '{MARKER}'; $scope.value = $parse(key)($scope.query);</script>"
        '</body></html>'
    )

    def __init__(self, point: str) -> None:
        self.point = point
        self._page = _FakePage(self)
        self.marker = ""
        self.delivered: list = []
        self._dialog = None

    async def _ensure_page(self):
        return self._page

    def _value(self, url: str) -> str:
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        vals = qs.get(self.point, [])
        return vals[0] if vals else ""

    async def navigate(self, url: str):
        val = self._value(url)
        if val.startswith("dastxss"):
            self.marker = val  # benign-marker step
            self._dialog = None
            return {"ok": True, "url": url}
        self.delivered.append(val)
        # Only the string-free Angular escape (fromCharCode) actually evaluates to alert(1) here.
        self._dialog = {"type": "alert", "message": "1"} if "fromCharCode" in val else None
        return {"ok": True, "url": url}

    def pop_last_dialog(self):
        dlg, self._dialog = self._dialog, None
        return dlg

    async def snapshot(self):
        return {"forms": [], "fields": [], "buttons": [], "links": []}

    async def fill(self, selector, value):
        return {"ok": True}

    async def click(self, selector, expect_nav=False):
        return {"ok": True}

    @property
    def _dom_template(self):
        return self._DOM


async def test_angular_parse_sink_in_js_string_confirms_via_no_strings_vector():
    from dast.payloads.loader import get_value

    browser = _AngularParseSinkBrowser("key")
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await xpt._xss_probe(ctx, {"url": _URL, "injection_point": "key"})

    assert out["ok"] is True
    assert out["confirmed"] is True
    # Surface context is a JS string, yet the confirming payload is the Angular CSTI escape vector.
    assert out["context"] == "js_string_single"
    assert out["framework_version"] == "1.4"
    no_strings = (get_value("xss", "angular_no_strings", {}) or {})["1.4"][0]
    assert out["payload"] == no_strings
    # The tool delivered an Angular vector (fromCharCode escape), not just the JS-string break-out.
    assert any("fromCharCode" in v for v in browser.delivered)
    assert not out["payload"].startswith("';alert(")
    # Reported as CSTI even though the surface context was a JS string.
    assert len(store.recorded) == 1
    title = store.recorded[0][0]["title"]
    assert "CSTI" in title or "template injection" in title


class _AngularParseKeySinkBrowser:
    """Models the AngularJS ``$parse``-of-KEY lab: the benign marker reflects into a single-quoted
    JS string that the page feeds through ``$parse(key)`` where ``key`` is the query-param NAME. The
    sandbox only escapes when the Angular expression is delivered AS A SECOND RAW QUERY-PARAM KEY
    (``?search=1&...charAt%3d[].join;...=1``) — so a dialog fires ONLY when the opened URL carries
    the expression as a raw key with a lowercase ``%3d`` and a raw ``&``, NOT for the url-encoded
    value delivery of the same vector, and NOT for the JS-string break-outs."""

    _DOM = (
        '<html><head><script src="/resources/js/angular_1-4-4.js"></script></head>'
        '<body ng-app>'
        "<script>$scope.query[key] = '{MARKER}'; $scope.value = $parse(key)($scope.query);</script>"
        '</body></html>'
    )

    def __init__(self, point: str) -> None:
        self.point = point
        self._page = _FakePage(self)
        self.marker = ""
        self.navigated: list = []
        self.confirming_url = ""
        self._dialog = None

    async def _ensure_page(self):
        return self._page

    async def navigate(self, url: str):
        self.navigated.append(url)
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        first_val = (qs.get(self.point, [""]) or [""])[0]
        if first_val.startswith("dastxss"):
            self.marker = first_val  # benign-marker step
            self._dialog = None
            return {"ok": True, "url": url}
        # Fire ONLY for the raw KEY-delivery URL: the expression sits as a second param KEY with its
        # internal '=' as a lowercase %3d (value delivery would url-encode it to %3D and never add a
        # raw '&'). This is the exact exploit structure for the $parse-of-key sandbox escape.
        if "&" in url and "charAt%3d[].join" in url and "fromCharCode" in url:
            self.confirming_url = url
            self._dialog = {"type": "alert", "message": "1"}
        else:
            self._dialog = None
        return {"ok": True, "url": url}

    def pop_last_dialog(self):
        dlg, self._dialog = self._dialog, None
        return dlg

    async def snapshot(self):
        return {"forms": [], "fields": [], "buttons": [], "links": []}

    async def fill(self, selector, value):
        return {"ok": True}

    async def click(self, selector, expect_nav=False):
        return {"ok": True}

    @property
    def _dom_template(self):
        return self._DOM


async def test_angular_parse_key_sink_confirms_via_raw_key_delivery():
    from dast.payloads.loader import get_value

    browser = _AngularParseKeySinkBrowser("search")
    store = _FakeStore()
    ctx = _FakeCtx(browser, store)
    out = await xpt._xss_probe(ctx, {"url": _URL, "injection_point": "search"})

    assert out["ok"] is True
    assert out["confirmed"] is True
    # Surface context is a JS string, yet the confirming payload is the key-delivered no-strings vector.
    assert out["context"] == "js_string_single"
    assert out["framework_version"] == "1.4"
    no_strings = (get_value("xss", "angular_no_strings", {}) or {})["1.4"][0]
    assert out["payload"] == no_strings

    # The confirming delivery was a RAW second query-param KEY: internal '=' → lowercase %3d, raw '&',
    # and NO url-encoding of the '&' (%26) or the key '=' (uppercase %3D).
    key_url = browser.confirming_url
    assert key_url, "expected a key-delivery URL to have fired the dialog"
    assert "search=1&" in key_url
    assert "charAt%3d[].join" in key_url          # internal '=' encoded, structure kept raw
    assert key_url.endswith("=1")                 # trailing KEY→value separator preserved
    assert "%26" not in key_url                   # the '&' between params is RAW, not url-encoded
    assert "charAt%3D" not in key_url             # not url-encoded (urlencode would uppercase)
    # Raw expression chars the lab needs must survive verbatim (not percent-encoded).
    for raw in ("[].join;", "|orderBy:", "fromCharCode(120,61"):
        assert raw in key_url

    # Reported as CSTI even though the surface context was a JS string.
    assert len(store.recorded) == 1
    title = store.recorded[0][0]["title"]
    assert "CSTI" in title or "template injection" in title


async def test_browser_unavailable_errors_cleanly():
    class _NoBrowserCtx(_FakeCtx):
        def __init__(self):
            super().__init__(None, _FakeStore())
    out = await xpt._xss_probe(_NoBrowserCtx(), {"url": _URL, "injection_point": "q"})
    assert out["ok"] is False
    assert "browser" in out["error"]

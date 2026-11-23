"""Copilot-facing HTTP tools (browser_fetch, send_request) must drop caller-pasted auth
and ride the managed session/browser instead.

Diagnosed live on IS-8804: against a CSRF/origin-gated GraphQL endpoint the copilot kept
pasting STALE raw auth (Cookie / Authorization / X-CSRF-Token), which overrode the live
session and 403'd. Two fixes:
  1. Strip caller Cookie/Authorization/X-CSRF-Token/X-XSRF-Token in both tools (keep every
     other header — Origin/Referer/Content-Type/...), note it in the result.
  2. browser_fetch: a SAME-ORIGIN request rides the in-page fetch (browser stamps Origin/
     Referer -> the gate returns 200); cross-origin uses page.request.fetch; a 401/403 on the
     primary falls back to in-page.

The deterministic sqli_probe/xss_probe cookie-injection path (_send_value) is untouched — it
crafts its own Cookie and does NOT route through this strip.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from dast.proxy.auth_headers import strip_caller_auth_headers
from dast.tools import browser_tools
from dast.tools.http_tools import _send_request


# ── the shared helper ────────────────────────────────────────────────────────

def test_strip_caller_auth_headers_drops_all_four_case_insensitive():
    headers = {
        "cookie": "session=stale",
        "Authorization": "Bearer stale",
        "X-CSRF-Token": "stalecsrf",
        "x-xsrf-token": "stalexsrf",
        "Origin": "https://app.example.com",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }
    dropped = strip_caller_auth_headers(headers)
    assert {d.lower() for d in dropped} == {
        "cookie", "authorization", "x-csrf-token", "x-xsrf-token"}
    # every non-auth header is preserved verbatim
    assert headers == {
        "Origin": "https://app.example.com",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }


def test_strip_caller_auth_headers_noop_when_absent():
    headers = {"Origin": "https://app.example.com", "Accept": "*/*"}
    assert strip_caller_auth_headers(headers) == []
    assert headers == {"Origin": "https://app.example.com", "Accept": "*/*"}


# ── send_request ─────────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status=200, text="{}"):
        self.status_code = status
        self.text = text
        self.headers = httpx.Headers({"content-type": "application/json"})
        self.url = "https://app.example.com/persona/graphql"
        self.history = []


class _CaptureClient:
    """Patches httpx.AsyncClient and records the headers actually sent."""

    last_headers: dict = {}

    def __init__(self, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None, content=None):
        _CaptureClient.last_headers = dict(headers or {})
        return _Resp()


class _JarStore:
    """Minimal store: a jar cookie for managed re-seeding; history scans find nothing."""

    def get_cookies_for_host(self, host):
        return [{"name": "session", "value": "LIVE-SESSION"}]

    def all_entries(self):
        return []

    def entries_newest_first(self):
        return []


def _send_ctx():
    return SimpleNamespace(
        store=_JarStore(), source_label="copilot", read_only=False,
        is_in_scope=lambda url: True, proxy_url="http://127.0.0.1:8080",
        _session=None,
    )


@pytest.mark.asyncio
async def test_send_request_drops_caller_auth_keeps_managed_cookie(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", _CaptureClient)
    result = await _send_request(_send_ctx(), {
        "method": "POST",
        "url": "https://app.example.com/persona/graphql",
        "headers": {
            "Cookie": "session=STALE-PASTED",
            "Authorization": "Bearer stalepastedtokenvalue123456",
            "X-CSRF-Token": "stale-csrf",
            "X-XSRF-Token": "stale-xsrf",
            "Origin": "https://app.example.com",
            "Content-Type": "application/json",
        },
        "body": '{"query":"query{__typename}"}',
    })
    assert result["ok"] is True
    sent = _CaptureClient.last_headers
    lower = {k.lower(): v for k, v in sent.items()}
    # caller's stale Authorization / CSRF are gone
    assert "authorization" not in lower
    assert lower.get("x-csrf-token") != "stale-csrf"
    assert lower.get("x-xsrf-token") != "stale-xsrf"
    # managed cookie injection re-seeded the LIVE session cookie, not the pasted one
    assert "STALE-PASTED" not in lower.get("cookie", "")
    assert "LIVE-SESSION" in lower.get("cookie", "")
    # a non-auth caller header survives
    assert lower.get("origin") == "https://app.example.com"
    # the operator is told what was dropped
    assert "note" in result
    note = result["note"].lower()
    assert "cookie" in note and "authorization" in note


# ── browser_fetch ────────────────────────────────────────────────────────────

class _BFResp:
    def __init__(self, status=200, body="{}"):
        self.status = status
        self._body = body
        self.headers = {"content-type": "application/json"}

    async def text(self):
        return self._body


class _FakeRequest:
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    async def fetch(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._resp


class _FakePage:
    def __init__(self, page_url, apirequest_resp, inpage_result):
        self.url = page_url
        self.request = _FakeRequest(apirequest_resp)
        self._inpage_result = inpage_result
        self.evaluate_calls = []

    async def evaluate(self, js, args):
        self.evaluate_calls.append(args)
        return self._inpage_result


class _FakeBrowser:
    def __init__(self, page):
        self._page = page

    async def ensure_fresh_cookies(self):
        return None

    async def _ensure_page(self):
        return self._page

    async def export_cookies(self):
        return {}


def _bf_ctx(page):
    return SimpleNamespace(
        browser=_FakeBrowser(page), store=None,
        is_in_scope=lambda url: True,
    )


@pytest.mark.asyncio
async def test_browser_fetch_same_origin_uses_inpage():
    page = _FakePage(
        "https://app.example.com/app",
        _BFResp(status=200, body="APIREQUEST"),
        {"ok": True, "status": 200, "headers": {}, "body": "INPAGE", "length": 6},
    )
    out = await browser_tools._fetch(_bf_ctx(page), {
        "url": "https://app.example.com/persona/graphql",
        "method": "POST", "body": "{}",
    })
    # same-origin -> in-page path is primary; page.request.fetch never called
    assert page.evaluate_calls, "expected the in-page fetch path"
    assert page.request.calls == []
    assert out["body"] == "INPAGE"


@pytest.mark.asyncio
async def test_browser_fetch_cross_origin_uses_apirequest():
    page = _FakePage(
        "https://app.example.com/app",
        _BFResp(status=200, body="APIREQUEST"),
        {"ok": True, "status": 200, "headers": {}, "body": "INPAGE", "length": 6},
    )
    out = await browser_tools._fetch(_bf_ctx(page), {
        "url": "https://api.example.com/graphql",
        "method": "POST", "body": "{}",
    })
    # cross-origin -> page.request.fetch (no CORS wall); in-page not used
    assert page.request.calls, "expected the network transport"
    assert page.evaluate_calls == []
    assert out["body"] == "APIREQUEST"


@pytest.mark.asyncio
async def test_browser_fetch_cross_origin_403_falls_back_to_inpage():
    page = _FakePage(
        "https://app.example.com/app",
        _BFResp(status=403, body="FORBIDDEN"),
        {"ok": True, "status": 200, "headers": {}, "body": "INPAGE-OK", "length": 9},
    )
    out = await browser_tools._fetch(_bf_ctx(page), {
        "url": "https://api.example.com/graphql",
        "method": "POST", "body": "{}",
    })
    # primary 403 -> retry in-page (which the gate accepts)
    assert page.request.calls and page.evaluate_calls
    assert out["status"] == 200
    assert out["body"] == "INPAGE-OK"


@pytest.mark.asyncio
async def test_browser_fetch_drops_caller_auth_keeps_origin_and_notes():
    page = _FakePage(
        "https://app.example.com/app",
        _BFResp(status=200, body="OK"),
        {"ok": True, "status": 200, "headers": {}, "body": "OK", "length": 2},
    )
    out = await browser_tools._fetch(_bf_ctx(page), {
        "url": "https://app.example.com/persona/graphql",  # same-origin -> in-page
        "method": "POST", "body": "{}",
        "headers": {
            "Cookie": "session=STALE",
            "Authorization": "Bearer stale",
            "X-CSRF-Token": "stale-csrf",
            "X-XSRF-Token": "stale-xsrf",
            "Origin": "https://app.example.com",
            "Content-Type": "application/json",
        },
    })
    sent = page.evaluate_calls[-1]["headers"]
    lower = {k.lower(): v for k, v in sent.items()}
    assert "cookie" not in lower
    assert "authorization" not in lower
    assert lower.get("x-csrf-token") != "stale-csrf"
    assert "x-xsrf-token" not in lower
    # non-auth caller headers preserved
    assert lower.get("origin") == "https://app.example.com"
    assert lower.get("content-type") == "application/json"
    assert "note" in out
    assert "session provides them" in out["note"]


# ── regression guard: the deterministic probe cookie path is untouched ─────────

def test_sqli_xss_probes_do_not_route_through_caller_auth_strip():
    import inspect

    from dast.tools import sqli_probe_tools, xss_probe_tools
    for mod in (sqli_probe_tools, xss_probe_tools):
        src = inspect.getsource(mod)
        assert "strip_caller_auth_headers" not in src, (
            f"{mod.__name__} must NOT route its cookie-injection _send_value through the "
            "caller-auth strip")

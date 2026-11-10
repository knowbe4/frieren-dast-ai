"""
Unit tests for the Repeater send route.

Covers the follow-redirects option: when enabled, the route follows 3xx hops
and returns the final URL plus the redirect chain; when disabled (default), it
returns the raw 3xx response without following it.
"""

from __future__ import annotations

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.proxy.api.repeater_routes import make_router


class _Ctx:
    pass


def _client(monkeypatch, handler) -> TestClient:
    """Build a TestClient whose repeater route talks to an in-memory ASGI/handler
    transport instead of the network, via a patched httpx.AsyncClient."""

    real_async_client = httpx.AsyncClient

    def _fake_async_client(*args, **kwargs):
        kwargs.pop("verify", None)
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    # The route does `import httpx as _httpx` inside the handler, so patching the
    # httpx module's AsyncClient is what takes effect.
    monkeypatch.setattr(httpx, "AsyncClient", _fake_async_client)

    app = FastAPI()
    app.include_router(make_router(_Ctx()))
    return TestClient(app)


def test_follow_redirects_off_returns_raw_3xx(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/"}, text="")

    c = _client(monkeypatch, handler)
    r = c.post("/api/repeater/send", json={
        "method": "GET", "url": "https://example.com/vis_proxy/../../Dockerfile",
        "headers": {}, "body": None, "follow_redirects": False,
    })
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == 302
    assert d["redirect_chain"] == []


def test_follow_redirects_on_follows_chain_and_reports_hops(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/":
            return httpx.Response(302, headers={"location": "https://example.com/"})
        return httpx.Response(200, text="landed")

    c = _client(monkeypatch, handler)
    r = c.post("/api/repeater/send", json={
        "method": "GET", "url": "https://example.com/vis_proxy/../../Dockerfile",
        "headers": {}, "body": None, "follow_redirects": True,
    })
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == 200
    assert d["body"] == "landed"
    assert d["final_url"] == "https://example.com/"
    assert len(d["redirect_chain"]) == 1


def test_follow_redirects_defaults_to_off(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "https://example.com/"})

    c = _client(monkeypatch, handler)
    r = c.post("/api/repeater/send", json={
        "method": "GET", "url": "https://example.com/x", "headers": {},
    })
    assert r.status_code == 200
    assert r.json()["status"] == 301


def _client_with_ctx(monkeypatch, handler, ctx) -> TestClient:
    real_async_client = httpx.AsyncClient

    def _fake_async_client(*args, **kwargs):
        kwargs.pop("verify", None)
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _fake_async_client)
    app = FastAPI()
    app.include_router(make_router(ctx))
    return TestClient(app)


def test_session_name_injects_cookies_and_csrf(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["cookie"] = request.headers.get("cookie")
        captured["csrf"] = request.headers.get("x-csrf-token")
        captured["xrw"] = request.headers.get("x-requested-with")
        return httpx.Response(200, text="ok")

    class _Store:
        def get_named_session_cookies_for_host(self, name, host):
            assert name == "admin" and host == "app.example.com"
            return [{"name": "CSRF-TOKEN", "value": "tok"}, {"name": "_s", "value": "v"}]

    class _StoreCtx:
        store = _Store()

    c = _client_with_ctx(monkeypatch, handler, _StoreCtx())
    r = c.post("/api/repeater/send", json={
        "method": "POST", "url": "https://app.example.com/graphql",
        "headers": {}, "body": '{"query":"query { me }"}', "session_name": "admin",
    })
    assert r.status_code == 200
    assert "csrf-token=tok" in (captured["cookie"] or "").lower()
    assert captured["csrf"] == "tok"
    assert captured["xrw"] == "XMLHttpRequest"


def test_no_session_name_sends_request_verbatim(monkeypatch):
    # Without session_name the store is never consulted and a hand-pasted Cookie
    # header is sent unchanged.
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["cookie"] = request.headers.get("cookie")
        return httpx.Response(200, text="ok")

    class _Store:
        def get_named_session_cookies_for_host(self, name, host):
            raise AssertionError("store must not be consulted without session_name")

    class _StoreCtx:
        store = _Store()

    c = _client_with_ctx(monkeypatch, handler, _StoreCtx())
    r = c.post("/api/repeater/send", json={
        "method": "GET", "url": "https://app.example.com/x",
        "headers": {"Cookie": "hand=pasted"},
    })
    assert r.status_code == 200
    assert captured["cookie"] == "hand=pasted"


def test_strip_recomputed_headers_is_case_insensitive():
    from dast.proxy.api.http_utils import strip_recomputed_headers
    cleaned = strip_recomputed_headers({"HOST": "a", "Content-Length": "3", "X-Keep": "1", "accept-encoding": "gzip"})
    assert cleaned == {"X-Keep": "1"}

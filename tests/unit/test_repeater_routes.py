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

"""Unit tests for POST /api/login/adaptive.

The AgentBrowser and the cascade are stubbed, so these exercise the route wiring,
the hard scope gate, and input validation without launching Playwright or a model.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.browser.login_cascade import LoginCascadeResult
from dast.proxy.api import login_adaptive_routes
from dast.proxy.api.context import DashboardContext
from dast.proxy.session_store import SessionStore


class _Scope:
    def __init__(self, allow: bool) -> None:
        self.allow = allow

    def is_in_scope(self, url: str) -> bool:
        return self.allow


class _FakeAgentBrowser:
    def __init__(self, *args, **kwargs) -> None:
        pass

    async def close(self) -> None:
        return None


def _client(allow_scope: bool, monkeypatch) -> TestClient:
    ctx = DashboardContext(store=SessionStore(), scan_queue=asyncio.Queue(),
                           settings=_Scope(allow_scope))
    monkeypatch.setattr("dast.browser.agent_browser.AgentBrowser", _FakeAgentBrowser)
    app = FastAPI()
    app.include_router(login_adaptive_routes.make_router(ctx))
    return TestClient(app)


def test_adaptive_login_route_success(monkeypatch):
    async def _fake_cascade(browser, url, email, password, **kwargs):
        return LoginCascadeResult(ok=True, engine="llm",
                                  url="https://app.example.com/dashboard", llm_steps=3)

    monkeypatch.setattr("dast.browser.login_cascade.adaptive_login", _fake_cascade)
    client = _client(True, monkeypatch)
    resp = client.post("/api/login/adaptive", json={
        "url": "https://app.example.com/login",
        "email": "a@b.com", "password": "secret"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["engine"] == "llm"
    assert data["url"].endswith("/dashboard")
    assert data["llm_steps"] == 3


def test_adaptive_login_route_out_of_scope(monkeypatch):
    called = {"browser": False}

    class _Guard(_FakeAgentBrowser):
        def __init__(self, *a, **k):
            called["browser"] = True

    monkeypatch.setattr("dast.browser.agent_browser.AgentBrowser", _Guard)
    ctx = DashboardContext(store=SessionStore(), scan_queue=asyncio.Queue(),
                           settings=_Scope(False))
    app = FastAPI()
    app.include_router(login_adaptive_routes.make_router(ctx))
    client = TestClient(app)
    resp = client.post("/api/login/adaptive", json={
        "url": "https://evil.example.com/login",
        "email": "a@b.com", "password": "secret"})
    assert resp.status_code == 400
    assert "out of scope" in resp.json()["error"]
    assert called["browser"] is False, "browser must not be built for out-of-scope URL"


@pytest.mark.parametrize("body", [
    {"email": "a@b.com", "password": "x"},            # no url
    {"url": "https://app.example.com/login", "password": "x"},  # no email
    {"url": "https://app.example.com/login", "email": "a@b.com"},  # no password
])
def test_adaptive_login_route_missing_fields(monkeypatch, body):
    client = _client(True, monkeypatch)
    resp = client.post("/api/login/adaptive", json=body)
    assert resp.status_code == 400
    assert "required" in resp.json()["error"]

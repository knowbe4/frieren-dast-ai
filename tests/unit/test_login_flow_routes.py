"""Unit tests for the login-flow API routes (record / replay / resume).

A fake login worker consumes ctx.login_queue and fabricates results, so these
tests exercise the route + persistence logic without launching Playwright.
"""

from __future__ import annotations

import asyncio
import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in ("dast.profiles.crypto", "dast.profiles.models",
                 "dast.profiles.store", "dast.proxy.api.profiles_routes",
                 "dast.proxy.api.login_flow_routes"):
        importlib.reload(importlib.import_module(name))

    from dast.proxy.api import login_flow_routes, profiles_routes
    from dast.proxy.api.context import DashboardContext
    from dast.proxy.session_store import SessionStore

    ctx = DashboardContext(
        store=SessionStore(),
        scan_queue=asyncio.Queue(),
        login_queue=asyncio.Queue(),
    )

    app = FastAPI()

    @app.on_event("startup")
    async def _spawn_worker() -> None:
        asyncio.create_task(_fake_login_worker(ctx))

    app.include_router(profiles_routes.make_router(ctx))
    app.include_router(login_flow_routes.make_router(ctx))
    # Context-manager form so startup fires and the fake worker task spawns.
    with TestClient(app) as tc:
        tc.ctx = ctx  # type: ignore[attr-defined]
        yield tc


async def _fake_login_worker(ctx) -> None:
    """Stand-in for runner._login_worker — no real browser."""
    while True:
        job = await ctx.login_queue.get()
        action = job.get("action")
        if action == "start_record":
            job["result_cb"](True, "", "sess-1")
        elif action == "stop_record":
            job["result_cb"](True, "", {
                "flow": {
                    "start_url": "https://app.example.com/login",
                    "steps": [
                        {"action": "fill", "selector": "#u", "value_ref": "username"},
                        {"action": "fill", "selector": "#p", "value_ref": "password"},
                        {"action": "click", "selector": "#go"},
                    ],
                },
                "cookies": [{"name": "sid", "value": "x", "domain": "app.example.com", "path": "/"}],
                "storage_state": {"cookies": [
                    {"name": "sid", "value": "x", "domain": "app.example.com", "path": "/"}
                ], "origins": []},
            })
        elif action == "cancel_record":
            job["result_cb"](True, "")
        elif action == "replay":
            if job.get("on_pause"):
                await job["on_pause"]("captcha detected")
            job["result_cb"]({
                "success": True, "error": "", "needed_human": True,
                "cookies": [{"name": "sid", "value": "y", "domain": "app.example.com", "path": "/"}],
                "auth_headers": {}, "storage_state": {"cookies": [], "origins": []},
            })


def _make_profile(client, with_cred=True):
    body = {"name": "App", "host_pattern": "app.example.com",
            "auth_url": "https://app.example.com/login"}
    if with_cred:
        body["credentials"] = [{"label": "admin", "username": "a@b.com", "secret": "pw"}]
    return client.post("/api/profiles", json=body).json()


def test_record_start_stop_persists_flow(client):
    _make_profile(client)
    assert client.post("/api/login-flow/record/start", json={"url": "https://app.example.com/login"}).json()["recording"] is True
    r = client.post("/api/login-flow/record/stop", json={"slug": "app", "save_session": True})
    assert r.status_code == 200
    body = r.json()
    assert body["flow_set"] is True
    assert body["flow_step_count"] == 3
    assert body["session_set"] is True  # captured session saved as fallback

    got = client.get("/api/login-flow/app").json()
    assert got["step_count"] == 3
    assert got["start_url"] == "https://app.example.com/login"


def test_record_stop_unknown_profile(client):
    assert client.post("/api/login-flow/record/stop",
                       json={"slug": "nope"}).status_code == 404


def test_replay_requires_flow(client):
    _make_profile(client)
    # No flow recorded yet.
    assert client.post("/api/login-flow/replay", json={"slug": "app"}).status_code == 400


def test_replay_imports_session(client):
    _make_profile(client)
    client.post("/api/login-flow/record/start", json={"url": "https://app.example.com/login"})
    client.post("/api/login-flow/record/stop", json={"slug": "app"})

    r = client.post("/api/login-flow/replay", json={"slug": "app"})
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["cookies_imported"] == 1
    # The replayed session cookie landed in the live jar.
    cookies = client.ctx.store.get_cookies_for_host("app.example.com")
    assert any(c["name"] == "sid" for c in cookies)


def test_replay_unknown_profile(client):
    assert client.post("/api/login-flow/replay", json={"slug": "ghost"}).status_code == 404


def test_resume_sets_event(client):
    client.ctx.login_resume_event.clear()
    assert client.post("/api/login-flow/resume").json()["resumed"] is True
    assert client.ctx.login_resume_event.is_set()


def test_needs_human_broadcast_over_ws(client):
    _make_profile(client)
    client.post("/api/login-flow/record/start", json={"url": "https://app.example.com/login"})
    client.post("/api/login-flow/record/stop", json={"slug": "app"})
    with client.websocket_connect("/ws/login") as ws:
        client.post("/api/login-flow/replay", json={"slug": "app"})
        # The fake worker calls on_pause -> needs_human is broadcast first.
        seen = set()
        for _ in range(4):
            msg = ws.receive_json()
            seen.add(msg.get("type"))
            if "needs_human" in seen and "replay_done" in seen:
                break
        assert "needs_human" in seen

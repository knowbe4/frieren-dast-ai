"""
Unit tests for the Exploration Copilot route helpers.

Focus: the "Login done" auth handoff. The browser the operator logs into routes
through the proxy, so its Set-Cookie responses land in the shared proxy jar — NOT
in the header-less UI entry list the client can read. ``_collect_jar_cookies``
sources those cookies server-side for the paused host so the copilot can retry
authenticated.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dast.proxy.api.copilot_routes import _collect_jar_cookies, make_router


class _Store:
    def __init__(self, cookies_by_host):
        self._cookies_by_host = cookies_by_host
        self.asked_for = []

    def get_cookies_for_host(self, host):
        self.asked_for.append(host)
        return self._cookies_by_host.get(host, [])


class _Ctx:
    def __init__(self, store):
        self.store = store


def _pause(host="", url=""):
    payload = {"status": 200}
    if host:
        payload["host"] = host
    if url:
        payload["url"] = url
    return {"kind": "auth", "payload": payload}


def test_collect_jar_cookies_by_host():
    store = _Store({"app.acme-corp.com": [
        {"name": "session", "value": "abc123", "domain": "app.acme-corp.com"},
        {"name": "csrf", "value": "tok", "domain": "app.acme-corp.com"},
    ]})
    cookies = _collect_jar_cookies(_Ctx(store), _pause(host="app.acme-corp.com"))
    assert cookies == {"session": "abc123", "csrf": "tok"}
    assert store.asked_for == ["app.acme-corp.com"]


def test_collect_jar_cookies_falls_back_to_url_host():
    store = _Store({"app.acme-corp.com": [
        {"name": "session", "value": "xyz", "domain": "app.acme-corp.com"},
    ]})
    # No explicit host on the payload — derive it from the paused URL.
    cookies = _collect_jar_cookies(
        _Ctx(store), _pause(url="https://app.acme-corp.com/lx/dashboard")
    )
    assert cookies == {"session": "xyz"}


def test_collect_jar_cookies_no_store():
    assert _collect_jar_cookies(_Ctx(None), _pause(host="app.acme-corp.com")) == {}


def test_collect_jar_cookies_no_host():
    store = _Store({"app.acme-corp.com": [{"name": "s", "value": "v"}]})
    assert _collect_jar_cookies(_Ctx(store), _pause()) == {}


def test_collect_jar_cookies_skips_valueless():
    store = _Store({"app.acme-corp.com": [
        {"name": "good", "value": "v"},
        {"name": "noval"},          # missing value -> skipped
        {"value": "orphan"},        # missing name -> skipped
    ]})
    cookies = _collect_jar_cookies(_Ctx(store), _pause(host="app.acme-corp.com"))
    assert cookies == {"good": "v"}


# ── Autonomous run + guidance routes (thin adapters over CopilotService) ────────
class _StubService:
    """Records calls the autonomous routes make, with configurable return values."""

    def __init__(self) -> None:
        self.started = None
        self.controls: list = []
        self.control_result = True
        self.sessions: dict = {}

    def run_autonomous(self, objective, focus_hosts=None, profile_slug=None,
                       budget=None, auto_ai_mode=True) -> str:
        self.started = {
            "objective": objective, "focus_hosts": focus_hosts,
            "profile_slug": profile_slug, "budget": budget, "auto_ai_mode": auto_ai_mode,
        }
        return "sid-auto"

    def stop_autonomous(self, sid) -> bool:
        self.controls.append(("stop", sid))
        return self.control_result

    def pause_autonomous(self, sid) -> bool:
        self.controls.append(("pause", sid))
        return self.control_result

    def resume_autonomous(self, sid) -> bool:
        self.controls.append(("resume", sid))
        return self.control_result

    def get(self, sid):
        return self.sessions.get(sid)

    # Unused by these tests but referenced when the router is built / other routes.
    def list_summaries(self):
        return []


class _AutoCtx:
    def __init__(self, service) -> None:
        self.copilot = service
        self.store = None
        self.browse_queue = None
        self.copilot_ws_clients = set()


@pytest.fixture()
def auto_client():
    service = _StubService()
    app = FastAPI()
    app.include_router(make_router(_AutoCtx(service)))
    tc = TestClient(app)
    tc.service = service  # type: ignore[attr-defined]
    return tc


def test_autonomous_start_passes_args(auto_client):
    resp = auto_client.post("/api/copilot/autonomous", json={
        "objective": "find BAC on the API",
        "focus_hosts": ["api.example.com"],
        "profile_slug": "admin",
        "auto_ai_mode": False,
        "budget": {"max_tool_calls": 50},
    })
    assert resp.status_code == 200
    assert resp.json() == {"session_id": "sid-auto", "status": "running"}
    started = auto_client.service.started
    assert started["objective"] == "find BAC on the API"
    assert started["focus_hosts"] == ["api.example.com"]
    assert started["profile_slug"] == "admin"
    assert started["auto_ai_mode"] is False
    assert started["budget"] == {"max_tool_calls": 50}


def test_autonomous_start_requires_objective(auto_client):
    resp = auto_client.post("/api/copilot/autonomous", json={"objective": "  "})
    assert resp.status_code == 400


def test_autonomous_start_rejects_bad_types(auto_client):
    assert auto_client.post("/api/copilot/autonomous",
                            json={"objective": "x", "focus_hosts": "nope"}).status_code == 400
    assert auto_client.post("/api/copilot/autonomous",
                            json={"objective": "x", "budget": "nope"}).status_code == 400


@pytest.mark.parametrize("action", ["stop", "pause", "resume"])
def test_autonomous_controls(auto_client, action):
    resp = auto_client.post(f"/api/copilot/autonomous/sid-1/{action}")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert ("stop" if action == "stop" else action, "sid-1") in auto_client.service.controls


@pytest.mark.parametrize("action", ["stop", "pause", "resume"])
def test_autonomous_controls_404_when_not_autonomous(auto_client, action):
    auto_client.service.control_result = False
    resp = auto_client.post(f"/api/copilot/autonomous/sid-x/{action}")
    assert resp.status_code == 404


def test_resume_guidance_sets_result_and_event(auto_client):
    event = asyncio.Event()
    auto_client.service.sessions["sid-g"] = {
        "pause": {"kind": "guidance", "payload": {"message": "need token"}},
        "_pause_event": event,
        "_pause_result": None,
    }
    resp = auto_client.post("/api/copilot/resume/sid-g", json={
        "kind": "guidance", "value": {"answer": "token=abc", "action": "continue"},
    })
    assert resp.status_code == 200
    session = auto_client.service.sessions["sid-g"]
    assert session["_pause_result"] == {"answer": "token=abc", "action": "continue"}
    assert event.is_set()


def test_resume_guidance_rejects_bad_action(auto_client):
    auto_client.service.sessions["sid-g"] = {
        "pause": {"kind": "guidance", "payload": {}},
        "_pause_event": asyncio.Event(),
        "_pause_result": None,
    }
    resp = auto_client.post("/api/copilot/resume/sid-g", json={
        "kind": "guidance", "value": {"action": "explode"},
    })
    assert resp.status_code == 400


def test_resume_rejects_unknown_kind(auto_client):
    auto_client.service.sessions["sid-g"] = {
        "pause": {"kind": "guidance", "payload": {}},
        "_pause_event": asyncio.Event(),
        "_pause_result": None,
    }
    resp = auto_client.post("/api/copilot/resume/sid-g", json={"kind": "bogus", "value": {}})
    assert resp.status_code == 400


def test_resume_rejects_kind_mismatch_with_active_pause(auto_client):
    # A guidance answer must not resolve an approve/auth wall: the answer would be
    # read with the wrong keys (no decision/cookies). Reject the mismatch (409).
    event = asyncio.Event()
    auto_client.service.sessions["sid-g"] = {
        "pause": {"kind": "approve", "payload": {"host": "evil.test"}},
        "_pause_event": event,
        "_pause_result": None,
    }
    resp = auto_client.post("/api/copilot/resume/sid-g", json={
        "kind": "guidance", "value": {"answer": "go", "action": "continue"},
    })
    assert resp.status_code == 409
    # The wall is untouched: no result written and the gate stays closed.
    assert auto_client.service.sessions["sid-g"]["_pause_result"] is None
    assert not event.is_set()

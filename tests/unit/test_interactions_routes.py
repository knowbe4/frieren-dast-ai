"""
Unit tests for the Interactions routes (Extras > Interactions tab backend).

Guarantees the stop-vs-delete distinction that the UI relies on:
  * POST /api/interactions/{id}/stop marks the session inactive but KEEPS the
    session record and every callback already received (operator can review);
  * DELETE /api/interactions/{id} removes the session entirely;
  * both stop and delete cancel the poll task and are 404 for unknown ids.
"""

from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient

import dast.proxy.api.interactions_routes as ir
from dast.proxy.api.interactions_routes import make_router


class _Ctx:
    ws_clients: set = set()


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(make_router(_Ctx()))
    return TestClient(app)


class _FakeTask:
    """Stand-in for the poll asyncio.Task — records that it was cancelled."""

    def __init__(self) -> None:
        self.cancelled = False

    def done(self) -> bool:
        return self.cancelled

    def cancel(self) -> None:
        self.cancelled = True


def _seed_session(session_id: str = "sess1234") -> _FakeTask:
    """Insert a session with one callback directly, bypassing interactsh network."""
    ir._sessions[session_id] = {
        "session_id": session_id,
        "oob_url": "http://abc.oast.site",
        "created_at": 1_700_000_000.0,
        "active": True,
        "callbacks": [{"received_at": 1_700_000_001.0, "type": "dns", "raw": "{}"}],
        "_interactsh": None,
    }
    task = _FakeTask()
    ir._tasks[session_id] = task
    return task


def _clear_store() -> None:
    ir._tasks.clear()
    ir._sessions.clear()


def test_stop_keeps_session_and_callbacks():
    _clear_store()
    task = _seed_session()
    c = _client()

    r = c.post("/api/interactions/sess1234/stop")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "active": False}

    # Session still listed, marked inactive, callbacks intact.
    listing = c.get("/api/interactions").json()
    assert len(listing) == 1
    assert listing[0]["session_id"] == "sess1234"
    assert listing[0]["active"] is False
    assert len(listing[0]["callbacks"]) == 1

    # Poll task cancelled and removed.
    assert task.cancelled is True
    assert "sess1234" not in ir._tasks

    # A stopped_at timestamp is recorded so the UI can freeze the age.
    assert listing[0]["stopped_at"] is not None
    assert listing[0]["stopped_at"] >= listing[0]["created_at"]
    _clear_store()


def test_delete_removes_session_entirely():
    _clear_store()
    _seed_session()
    c = _client()

    r = c.delete("/api/interactions/sess1234")
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    assert c.get("/api/interactions").json() == []
    assert "sess1234" not in ir._sessions
    assert "sess1234" not in ir._tasks
    _clear_store()


def test_stop_and_delete_404_for_unknown_session():
    _clear_store()
    c = _client()
    assert c.post("/api/interactions/nope/stop").status_code == 404
    assert c.delete("/api/interactions/nope").status_code == 404
    _clear_store()

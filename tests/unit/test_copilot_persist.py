"""Unit tests for copilot session resume across restarts (6-A-1).

Snapshot store (atomic write/load/prune, interrupted marking), todolist
round-trip, service restore into ``_sessions`` and the ``resume_session``
re-drive — with the snapshot dir redirected to a per-test tmp dir by the
shared conftest fixture.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace


from dast.ai.copilot.todolist import MissionTodoList
from dast.proxy.api import copilot_persist


# ── todolist round-trip ──────────────────────────────────────────────────────

def test_todolist_round_trip_preserves_progress():
    todo = MissionTodoList.seed_default("pwn")
    todo.mark("map", "done")
    todo.mark("auth", "done")
    todo.mark("scan", "done", detail="40 endpoints")
    restored = MissionTodoList.from_dict(todo.to_dict())

    assert [i.id for i in restored._items.values()] == \
        [i.id for i in todo._items.values()]
    assert restored.get("map").status == "done"
    assert restored.get("scan").status == "done"
    assert restored.get("scan").detail == "40 endpoints"
    assert restored.get("escalate").status == "pending"
    # gating still applies after restore: escalate needs scan (done) — ok now
    assert restored.mark("escalate", "done") is True
    # and a prereq-gated item still refuses
    assert restored.mark("wrapup", "done") is False  # chains pending


def test_todolist_from_dict_ignores_garbage():
    todo = MissionTodoList.from_dict([None, {"no_id": 1}, {"id": "ok", "status": "weird"}])
    assert [i.id for i in todo._items.values()] == ["ok"]
    assert todo.get("ok").status == "pending"


# ── snapshot store ───────────────────────────────────────────────────────────

def _fake_session(sid="abc123def456"):
    from dast.ai.copilot import CopilotSession
    engine = CopilotSession(sid, focus_hosts=["shop.test"])
    engine.messages = [{"role": "operator", "content": "find sqli"},
                       {"role": "copilot", "content": "on it"}]
    engine._scratchpad = [{"line": "GET / -> 200", "tool": "send_request",
                           "host": "shop.test", "path": "/"}]
    engine.seed_session_cookies({"sid": "x"})
    engine._bearer_tokens = {"shop.test": {"token": "t", "exp": 1}}
    todo = MissionTodoList.seed_default("pwn")
    todo.mark("map", "done")
    autonomous = {
        "objective": "pwn", "config": {"max_tool_calls": 300}, "hosts": ["shop.test"],
        "profile": None, "session_safe": False, "read_only": False, "mode": "bounded",
        "validation_only": False, "submit_forms": False, "initial_explore_done": True,
        "stop_event": asyncio.Event(), "pause_gate": asyncio.Event(),
        "tool_calls": 42, "turns": 5, "errors": 0, "complete_rejections": 1,
        "escalations_run": 2, "todo": todo, "started_at": 1.0, "status": "running",
        "detail": "",
    }
    return {
        "engine": engine, "session_id": sid, "status": "running",
        "created_at": 1.0, "updated_at": 2.0, "trace": [], "pause": None,
        "last_reply": {"message": "checkpoint"}, "origin": "autonomous",
        "escalation": None, "hypothesis": None, "profile_slug": None,
        "_downgrade_armed": False, "_profile_activated": True,
        "_pause_event": asyncio.Event(), "_pause_result": None,
        "approved_hosts": {"shop.test"}, "_task": None,
        "autonomous": autonomous,
    }


def test_snapshot_round_trip_and_interrupted_marking():
    session = _fake_session()
    assert copilot_persist.save_snapshot("abc123def456", session) is True

    loaded = copilot_persist.load_snapshots()
    assert "abc123def456" in loaded
    data = loaded["abc123def456"]
    assert data["origin"] == "autonomous"
    assert data["approved_hosts"] == ["shop.test"]          # set → sorted list
    assert data["autonomous"]["status"] == "interrupted"    # was running
    assert data["autonomous"]["tool_calls"] == 42
    assert "stop_event" not in data["autonomous"]           # live object dropped
    # engine state survives
    assert data["engine_state"]["messages"][0]["content"] == "find sqli"
    assert data["engine_state"]["_session_cookies"] == {"sid": "x"}
    assert data["engine_state"]["_bearer_tokens"]["shop.test"]["token"] == "t"
    # the raw session dict is untouched (live objects still live)
    assert session["autonomous"]["status"] == "running"


def test_service_restores_and_resumes(monkeypatch):
    copilot_persist.save_snapshot("abc123def456", _fake_session())

    from dast.proxy.api.copilot_service import CopilotService
    ctx = SimpleNamespace(store=None, settings=None)
    service = CopilotService(ctx)

    assert service.has("abc123def456")
    restored = service.get("abc123def456")
    assert restored["_restored"] is True
    assert restored["status"] == "interrupted"
    assert restored["autonomous"]["status"] == "interrupted"
    engine = restored["engine"]
    assert engine.messages[0]["content"] == "find sqli"
    assert engine._session_cookies == {"sid": "x"}
    assert restored["autonomous"]["todo"].get("map").status == "done"

    # resume re-drives the autonomous session with the SAME todo/counters.
    # spawn_tracked (like run_autonomous) needs a running loop.
    driven = []

    async def fake_drive(sid):
        driven.append(sid)

    monkeypatch.setattr(service, "_drive_autonomous", fake_drive)

    async def _resume():
        out = service.resume_session("abc123def456")
        await asyncio.sleep(0)  # let the spawned driver task start
        return out

    out = asyncio.run(_resume())
    assert out["ok"] is True and out["resumed"] == "autonomous"
    assert out["objective"] == "pwn"
    assert out["todo"] == {"done": 1, "total": 6, "failed": 0, "revision": 6}
    assert driven == ["abc123def456"]
    assert service.get("abc123def456")["_restored"] is False


def test_service_resume_interactive_and_unknown():
    from dast.proxy.api.copilot_service import CopilotService
    ctx = SimpleNamespace(store=None, settings=None)
    service = CopilotService(ctx)

    assert service.resume_session("ghost")["ok"] is False

    sid = service.new_session()
    out = service.resume_session(sid)
    assert out == {"ok": True, "resumed": "interactive", "messages": 0}


def test_snapshot_prune_keeps_cap(monkeypatch):
    monkeypatch.setattr(copilot_persist, "_MAX_SNAPSHOTS", 3)
    for i in range(5):
        session = _fake_session(sid=f"sid{i:03d}")
        session["created_at"] = 100.0 + i
        copilot_persist.save_snapshot(f"sid{i:03d}", session)
    loaded = copilot_persist.load_snapshots()
    assert len(loaded) == 3
    assert "sid004" in loaded and "sid000" not in loaded  # newest kept


def test_resume_copilot_session_tool_registered():
    import dast.tools  # noqa: F401
    from dast.tools.base import get_tool
    tool = get_tool("resume_copilot_session")
    assert tool is not None
    assert "interrupted" in tool.description

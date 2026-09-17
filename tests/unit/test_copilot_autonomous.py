"""
Unit tests for the autonomous Exploration Copilot orchestrator
(``CopilotService.run_autonomous`` + ``_drive_autonomous``).

The driver self-continues turns commanding the arsenal until a stop condition
trips. These tests mock the copilot engine's ``send`` so no LLM/network call
happens, and drive the loop deterministically to cover:

  * self-continue across turns (a plain reply is a checkpoint, not a stop),
  * each stop condition: self-declared complete, tool-call budget, wall-clock
    budget, stuck detector, and the operator kill switch,
  * a ``need_human`` escalation that pauses then resumes on operator guidance
    (continue / abort),
  * the scope/auth policy (auto-deny out of scope vs. serve the jar session).

The engine's ``send`` is patched on the live instance (an instance attribute is
returned as-is, so it is NOT bound as a method and receives no ``self``), which
lets a plain ``async def`` stand in and inspect the prompts the driver builds.
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Optional
from unittest.mock import AsyncMock

import pytest

from dast.proxy.api.copilot_service import CopilotService


class _Reply:
    """Stand-in for CopilotReply — only .message and .blocked_reason are read."""

    def __init__(self, message: str = "", blocked_reason: str = "") -> None:
        self.message = message
        self.blocked_reason = blocked_reason


class _Entry:
    def __init__(self, findings: Optional[List[dict]] = None) -> None:
        self.findings = findings or []


class _FakeStore:
    def __init__(self, entries: Optional[List[_Entry]] = None,
                 cookies: Optional[List[dict]] = None) -> None:
        self.ai_mode = False
        self._entries = entries if entries is not None else []
        self._cookies = cookies if cookies is not None else []

    def in_scope_entries(self) -> List[_Entry]:
        return self._entries

    def get_cookies_for_host(self, host: str) -> List[dict]:
        return self._cookies


class _FakeCtx:
    def __init__(self, store: Optional[_FakeStore] = None) -> None:
        self.proxy_port = 8080
        self.dashboard_port = 8088
        self.store = store if store is not None else _FakeStore()
        self.settings = None
        self.broadcast_copilot = AsyncMock()


async def _wait_for(predicate, timeout: float = 2.0) -> bool:
    """Poll until predicate() is truthy or the timeout elapses."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.005)
    return False


# ── run_autonomous basics ─────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_run_autonomous_requires_objective():
    service = CopilotService(_FakeCtx())
    with pytest.raises(ValueError):
        service.run_autonomous("   ")


@pytest.mark.asyncio
async def test_run_autonomous_enables_ai_mode_and_records_config():
    store = _FakeStore()
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("find BAC", focus_hosts=["Api.Example.com"],
                                 budget={"max_tool_calls": 42})
    session = service.get(sid)
    # Ambient auto-scan is turned on for the run.
    assert store.ai_mode is True
    auto = session["autonomous"]
    assert auto["objective"] == "find BAC"
    assert auto["hosts"] == ["api.example.com"]          # normalized lower-case
    assert auto["config"]["max_tool_calls"] == 42
    assert session["origin"] == "autonomous"
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)


@pytest.mark.asyncio
async def test_run_autonomous_clamps_out_of_range_budget():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", budget={
        "max_tool_calls": 0, "max_wall_clock_seconds": 1, "max_stuck_turns": 0,
    })
    session = service.get(sid)
    cfg = session["autonomous"]["config"]
    assert cfg["max_tool_calls"] == 1                    # clamped up from 0
    assert cfg["max_wall_clock_seconds"] == 30           # clamped up from 1
    assert cfg["max_stuck_turns"] == 1                   # clamped up from 0
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)


# ── Stop conditions ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_driver_stops_on_self_declared_complete():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[_Reply("done", "complete")])
    await session["_task"]
    assert session["autonomous"]["status"] == "complete"
    assert session["engine"].send.await_count == 1


@pytest.mark.asyncio
async def test_driver_self_continues_then_completes():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 10})
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[
        _Reply("progress 1"), _Reply("progress 2"), _Reply("all done", "complete"),
    ])
    await session["_task"]
    assert session["autonomous"]["status"] == "complete"
    assert session["engine"].send.await_count == 3
    # Turn 1 is the autonomous preamble; later turns are continuation prompts.
    prompts = [c.args[0] for c in session["engine"].send.await_args_list]
    assert "AUTONOMOUS PENTEST" in prompts[0]
    assert "Continue with your plan" in prompts[1]


@pytest.mark.asyncio
async def test_driver_stops_on_tool_call_budget():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_tool_calls": 1, "max_stuck_turns": 99})
    session = service.get(sid)
    calls = {"n": 0}

    async def fake_send(text: str, tool_ctx: Any, *, on_event, wait_for_human) -> _Reply:
        calls["n"] += 1
        # Emit one tool-call step event so the driver's counter ticks.
        await on_event({"type": "step", "action": "call_tool", "step": calls["n"]})
        return _Reply("working")

    session["engine"].send = fake_send
    await session["_task"]
    assert session["autonomous"]["status"] == "stopped"
    assert "tool-call budget" in session["autonomous"]["detail"]
    # One turn ran (tool_calls hit 1), then the budget gate stopped the next.
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_driver_stops_on_wall_clock_budget():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    # The task has not run yet (no await since run_autonomous). Backdate the start
    # so the deadline is already in the past when the driver computes it.
    session["autonomous"]["started_at"] -= 100_000
    send = AsyncMock(side_effect=[_Reply("should not run")])
    session["engine"].send = send
    await session["_task"]
    assert session["autonomous"]["status"] == "stopped"
    assert "wall-clock" in session["autonomous"]["detail"]
    assert send.await_count == 0                         # stopped before any turn


@pytest.mark.asyncio
async def test_driver_stops_on_stuck_detector():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 2, "max_tool_calls": 999})
    session = service.get(sid)
    # Progress never changes (store stays empty), so every turn is "no progress".
    session["engine"].send = AsyncMock(side_effect=[_Reply("nothing new")] * 10)
    await session["_task"]
    assert session["autonomous"]["status"] == "stopped"
    assert "no progress" in session["autonomous"]["detail"]
    # Two turns run, then the stuck gate trips before the third.
    assert session["engine"].send.await_count == 2


@pytest.mark.asyncio
async def test_progress_resets_stuck_counter():
    store = _FakeStore()
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 2, "max_tool_calls": 999})
    session = service.get(sid)
    turn = {"n": 0}

    async def fake_send(text: str, tool_ctx: Any, *, on_event, wait_for_human) -> _Reply:
        turn["n"] += 1
        if turn["n"] == 2:
            # A new finding appears on turn 2 — progress, so stuck resets to 0.
            store._entries.append(_Entry(findings=[{"title": "x"}]))
        if turn["n"] >= 4:
            return _Reply("done", "complete")
        return _Reply("working")

    session["engine"].send = fake_send
    await session["_task"]
    # Turn 1 is stuck=1; turn 2's progress resets it to 0; turn 3 is stuck=1
    # again; turn 4 completes. Without the reset, the stuck gate (2) would have
    # fired before turn 3 ever ran.
    assert session["autonomous"]["status"] == "complete"
    assert turn["n"] == 4


# ── Operator controls ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_stop_autonomous_kills_the_run():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)

    async def slow_send(text: str, tool_ctx: Any, *, on_event, wait_for_human) -> _Reply:
        await asyncio.sleep(0.05)
        return _Reply("working")

    session["engine"].send = slow_send
    assert await _wait_for(lambda: session["autonomous"]["turns"] >= 1)
    assert service.stop_autonomous(sid) is True
    await asyncio.gather(session["_task"], return_exceptions=True)
    assert session["autonomous"]["status"] == "stopped"


@pytest.mark.asyncio
async def test_pause_and_resume_toggle_the_gate():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    auto = session["autonomous"]
    assert service.pause_autonomous(sid) is True
    assert auto["pause_gate"].is_set() is False
    assert auto["status"] == "paused"
    assert service.resume_autonomous(sid) is True
    assert auto["pause_gate"].is_set() is True
    assert auto["status"] == "running"
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)


@pytest.mark.asyncio
async def test_controls_return_false_for_non_autonomous_session():
    service = CopilotService(_FakeCtx())
    sid = service.new_session()                          # ordinary conversation
    assert service.stop_autonomous(sid) is False
    assert service.pause_autonomous(sid) is False
    assert service.resume_autonomous(sid) is False
    assert service.answer_guidance(sid, "x", "continue") is False


# ── need_human escalation (ask-and-continue) ──────────────────────────────────
@pytest.mark.asyncio
async def test_escalation_pauses_then_resumes_on_guidance():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 10})
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[
        _Reply("I need the admin token", "need_human"),
        _Reply("done", "complete"),
    ])
    # Wait until the driver parks on a guidance escalation.
    assert await _wait_for(
        lambda: (session.get("pause") or {}).get("kind") == "guidance")
    assert service.answer_guidance(sid, "token is abc123", "continue") is True
    await session["_task"]
    assert session["autonomous"]["status"] == "complete"
    # The operator's answer is threaded into the next turn's prompt.
    second_prompt = session["engine"].send.await_args_list[1].args[0]
    assert "token is abc123" in second_prompt


@pytest.mark.asyncio
async def test_escalation_abort_stops_the_run():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 10})
    session = service.get(sid)
    send = AsyncMock(side_effect=[_Reply("blocked", "need_human"),
                                  _Reply("should not reach", "complete")])
    session["engine"].send = send
    assert await _wait_for(
        lambda: (session.get("pause") or {}).get("kind") == "guidance")
    assert service.answer_guidance(sid, "", "abort") is True
    await session["_task"]
    assert session["autonomous"]["status"] == "stopped"
    assert "aborted" in session["autonomous"]["detail"]
    assert send.await_count == 1                         # never ran the second turn


@pytest.mark.asyncio
async def test_answer_guidance_rejected_when_not_paused():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    # No guidance pause is active right after start.
    assert service.answer_guidance(sid, "x", "continue") is False
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)


# ── Scope / auth policy ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_policy_auto_denies_out_of_scope_without_escalation():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"allow_scope_escalation": False})
    session = service.get(sid)
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)
    wait = service._make_autonomous_wait(sid, session)
    result = await wait("approve", {"host": "evil.com", "url": "https://evil.com/"})
    assert result == {"decision": "deny"}


@pytest.mark.asyncio
async def test_policy_serves_jar_session_on_auth_wall():
    store = _FakeStore(cookies=[{"name": "session", "value": "s3cr3t"},
                                {"name": "csrf", "value": "tok"}])
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"allow_scope_escalation": False})
    session = service.get(sid)
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)
    wait = service._make_autonomous_wait(sid, session)
    result = await wait("auth", {"host": "app.example.com",
                                 "url": "https://app.example.com/"})
    assert result == {"cookies": {"session": "s3cr3t", "csrf": "tok"}}


@pytest.mark.asyncio
async def test_policy_escalates_scope_when_enabled():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"allow_scope_escalation": True})
    session = service.get(sid)
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)
    wait = service._make_autonomous_wait(sid, session)

    # With escalation enabled, an out-of-scope host parks on an approve pause.
    task = asyncio.create_task(
        wait("approve", {"host": "evil.com", "url": "https://evil.com/"}))
    assert await _wait_for(
        lambda: (session.get("pause") or {}).get("kind") == "approve")
    session["_pause_result"] = {"decision": "allow_once"}
    session["_pause_event"].set()
    result = await task
    assert result == {"decision": "allow_once"}

"""Wrap-up pass tests (dast/ai/copilot/wrapup.py + its hook in CopilotSession.send).

The wrap-up runs ONLY on supervisor-forced endings (stuck_loop / need_direction):
Part A drives ``run_wrapup`` directly with fake callbacks to pin the loop contract
(bounded steps, record-only, fail-open, cancellation passthrough); Part B drives
real sessions through kill paths to prove the hook salvages a proven-but-unrecorded
finding and stays silent on model-initiated endings."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch

import pytest

from dast.ai.copilot.session import CopilotSession
from dast.ai.copilot.wrapup import WRAPUP_MAX_STEPS, run_wrapup
from tests.unit.test_copilot_session import (
    _TOOLS,
    _FakeCtx,
    _FakeTool,
    _collector,
    _deny_human,
)

_TOOLS_WITH_RECORD = _TOOLS + [_FakeTool("record_finding")]

_RECORD_ARGS = {
    "title": "SQLi in /search",
    "url": "https://in.scope/search?q=1",
    "method": "GET",
    "evidence": "error-based payload returned DB data",
    "severity": "high",
    "cwe": "89",
    "attack_type": "sqli",
    "parameter": "q",
    "reasoning": "payload changed the result set",
}
_RECORD_DECISION = {"action": "call_tool", "thought": "salvage", "tool_name": "record_finding",
                    "tool_args": dict(_RECORD_ARGS)}
_DONE_DECISION = {"action": "reply", "thought": "nothing pending", "message": "DONE"}


def _record_result(**overrides) -> Dict[str, Any]:
    return {"ok": True, "entry_id": "e1", "title": _RECORD_ARGS["title"],
            "severity": "high", **overrides}


def _same_probe(i: int) -> Dict[str, Any]:
    """A send_request decision whose EXACT args differ (fresh header) but whose
    NORMALIZED signature is identical — the shape the loop watchdog exists for
    (the exact-dedup misses it; the normalized no-progress counter catches it)."""
    return {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
            "tool_args": {"url": "https://in.scope/api", "method": "GET",
                          "headers": {"X-Request-Id": f"r{i}"}}}


# ── Part A: run_wrapup loop contract ────────────────────────────────────────

def _wrapup_events():
    events: List[Dict[str, Any]] = []

    async def on_event(payload: Dict[str, Any]) -> None:
        events.append(payload)

    return events, on_event


async def _drive_wrapup(side_effect, execute_record=None, transcript=None):
    events, on_event = _wrapup_events()
    llm_step = AsyncMock(side_effect=side_effect)
    record = execute_record or AsyncMock(return_value=_record_result())
    transcript = transcript if transcript is not None else []
    note = await run_wrapup(
        llm_step=llm_step, model="fast-model",
        execute_record=record,
        render_transcript=lambda _t: "TRANSCRIPT",
        transcript=transcript, on_event=on_event, base_step=7,
    )
    return note, llm_step, record, events, transcript


@pytest.mark.asyncio
async def test_wrapup_records_finding_then_stops_on_done():
    note, llm_step, record, events, transcript = await _drive_wrapup(
        [_RECORD_DECISION, _DONE_DECISION])

    record.assert_awaited_once_with(_RECORD_ARGS)
    assert note == ('\n\n---\n**Wrap-up before stop**: recorded 1 pending finding(s): '
                    '"SQLi in /search" (high).')
    assert llm_step.await_count == 2
    # The transcript gained the wrap-up steps (continuing numbering) and the
    # UI got step + observation events for them.
    assert [e["step"] for e in transcript] == [7, 8]
    assert transcript[0]["action"] == "wrapup_call_tool"
    assert transcript[1]["action"] == "wrapup_reply"
    assert any(e["type"] == "observation" and "Recorded:" in e["observation"]
               for e in events)


@pytest.mark.asyncio
async def test_wrapup_done_immediately_records_nothing():
    note, llm_step, record, _, _ = await _drive_wrapup([_DONE_DECISION])
    assert note == ""
    record.assert_not_awaited()


@pytest.mark.asyncio
async def test_wrapup_llm_none_is_fail_open():
    note, llm_step, record, _, _ = await _drive_wrapup([None])
    assert note == ""
    record.assert_not_awaited()
    assert llm_step.await_count == 1


@pytest.mark.asyncio
async def test_wrapup_llm_raise_is_fail_open():
    note, _, record, _, _ = await _drive_wrapup([RuntimeError("provider down")])
    assert note == ""
    record.assert_not_awaited()


@pytest.mark.asyncio
async def test_wrapup_refuses_non_record_tool_and_continues():
    wander = {"action": "call_tool", "thought": "keep probing",
              "tool_name": "send_request", "tool_args": {"url": "https://in.scope/x"}}
    note, _, record, events, _ = await _drive_wrapup(
        [wander, _DONE_DECISION])
    record.assert_not_awaited()  # the wandering call was NOT executed
    assert any("Wrap-up allows ONLY record_finding" in (e.get("observation") or "")
               for e in events)
    assert note == ""


@pytest.mark.asyncio
async def test_wrapup_lists_failed_records():
    record = AsyncMock(return_value={"ok": False, "error": "out of scope: host evil.com"})
    note, _, _, _, _ = await _drive_wrapup(
        [_RECORD_DECISION, _DONE_DECISION], execute_record=record)
    assert note == ("\n\n---\n**Wrap-up before stop**: could not record 1 other "
                    "finding(s) (out of scope: host evil.com).")


@pytest.mark.asyncio
async def test_wrapup_is_bounded_by_max_steps():
    note, llm_step, record, _, _ = await _drive_wrapup(
        [dict(_RECORD_DECISION) for _ in range(10)])  # never says DONE
    assert llm_step.await_count == WRAPUP_MAX_STEPS
    assert record.await_count == WRAPUP_MAX_STEPS
    assert "recorded 3 pending finding(s)" in note


@pytest.mark.asyncio
async def test_wrapup_passes_cancellation_through():
    # An operator stop must never be swallowed by the salvage pass.
    async def _cancel(*_a, **_k):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_wrapup(
            llm_step=AsyncMock(side_effect=_cancel), model="m",
            execute_record=AsyncMock(),
            render_transcript=lambda _t: "T",
            transcript=[], on_event=_wrapup_events()[1], base_step=1,
        )


# ── Part B: the hook in CopilotSession.send ─────────────────────────────────

def _jar_ctx() -> _FakeCtx:
    from tests.unit.test_copilot_session import _FakeStore
    ctx = _FakeCtx()
    ctx.store = _FakeStore(cookies=[{"name": "session", "value": "ACTIVE"}], entries=[])
    return ctx


async def _send(session, ctx, steps, run_tool):
    events, on_event = _collector()
    with patch("dast.tools.all_tools", return_value=_TOOLS_WITH_RECORD), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", ctx, on_event=on_event,
                                   wait_for_human=_deny_human())
    return reply, events


@pytest.mark.asyncio
async def test_stuck_loop_kill_salvages_pending_finding():
    # 3 identical-outcome probes trip the no-progress watchdog on the 4th
    # decision; the wrap-up then records the finding the model had proven.
    steps = [_same_probe(i) for i in range(4)] + [_RECORD_DECISION, _DONE_DECISION]
    run_tool = AsyncMock(side_effect=lambda _ctx, name, _args:
                         {"ok": True, "status": 200, "text": "A"} if name == "send_request"
                         else _record_result())
    reply, events = await _send(CopilotSession("s-wrap"), _jar_ctx(), steps, run_tool)

    assert reply.blocked_reason == "stuck_loop"
    called_findings = [c for c in run_tool.await_args_list if c.args[1] == "record_finding"]
    assert len(called_findings) == 1
    assert called_findings[0].args[2] == _RECORD_ARGS
    # The operator still sees the watchdog message, now annotated with the salvage.
    assert reply.message.startswith("Stopped: the same request")
    assert "**Wrap-up before stop**" in reply.message
    assert '"SQLi in /search" (high)' in reply.message
    # The forced ending now broadcasts its reply event (previously silent).
    assert any(e["type"] == "reply" and e["blocked_reason"] == "stuck_loop"
               for e in events)
    # The wrap-up steps are part of the turn transcript for the UI trace.
    assert any(e["action"] == "wrapup_call_tool" for e in reply.transcript)


@pytest.mark.asyncio
async def test_stuck_loop_kill_with_nothing_pending_keeps_message_clean():
    steps = [_same_probe(i) for i in range(4)] + [_DONE_DECISION]
    run_tool = AsyncMock(return_value={"ok": True, "status": 200, "text": "A"})
    reply, _ = await _send(CopilotSession("s-clean"), _jar_ctx(), steps, run_tool)
    assert reply.blocked_reason == "stuck_loop"
    assert "Wrap-up" not in reply.message  # nothing salvaged → no annotation


@pytest.mark.asyncio
async def test_model_initiated_reply_does_not_wrap_up():
    events, on_event = _collector()
    llm_step = AsyncMock(side_effect=[{"action": "reply", "thought": "t",
                                       "message": "done exploring"}])
    with patch("dast.tools.all_tools", return_value=_TOOLS_WITH_RECORD), \
         patch("dast.tools.run_tool", new=AsyncMock()), \
         patch("dast.ai.copilot.session._llm_step", new=llm_step):
        reply = await CopilotSession("s-own").send(
            "go", _FakeCtx(), on_event=on_event, wait_for_human=_deny_human())
    assert reply.blocked_reason == ""
    assert llm_step.await_count == 1  # the reply — no wrap-up call after it


@pytest.mark.asyncio
async def test_llm_error_ending_does_not_wrap_up():
    # Three decision-model failures end the turn with blocked_reason='error';
    # the wrap-up would call the same failing LLM, so it must NOT fire.
    llm_step = AsyncMock(side_effect=[None, None, None])
    with patch("dast.tools.all_tools", return_value=_TOOLS_WITH_RECORD), \
         patch("dast.tools.run_tool", new=AsyncMock()), \
         patch("dast.ai.copilot.session._llm_step", new=llm_step):
        reply = await CopilotSession("s-err").send(
            "go", _FakeCtx(), on_event=_collector()[1], wait_for_human=_deny_human())
    assert reply.blocked_reason == "error"
    assert llm_step.await_count == 3


@pytest.mark.asyncio
async def test_wrapup_record_out_of_scope_host_is_refused_not_executed():
    # Focus hosts are set, so the wrap-up closure's silent scope check refuses a
    # fabricated host WITHOUT an operator pause — and the tool never runs.
    steps = [_same_probe(i) for i in range(4)] + [
        {"action": "call_tool", "thought": "salvage", "tool_name": "record_finding",
         "tool_args": {**_RECORD_ARGS, "url": "https://evil.com/search?q=1"}},
        _DONE_DECISION,
    ]
    run_tool = AsyncMock(side_effect=lambda _ctx, name, _args:
                         {"ok": True, "status": 200, "text": "A"} if name == "send_request"
                         else _record_result())
    session = CopilotSession("s-scope", focus_hosts=["in.scope"])
    reply, events = await _send(session, _jar_ctx(), steps, run_tool)

    assert reply.blocked_reason == "stuck_loop"
    assert not any(c.args[1] == "record_finding" for c in run_tool.await_args_list)
    assert "**Wrap-up before stop**" in reply.message
    assert "out of scope: host evil.com" in reply.message
    assert any("Not recorded:" in (e.get("observation") or "") for e in events)


@pytest.mark.asyncio
async def test_wrapup_duplicate_record_is_deduped():
    # A finding recorded in the live loop must not be recorded again by the
    # wrap-up: the session dedup key is shared.
    live_record = {"action": "call_tool", "thought": "record now",
                   "tool_name": "record_finding", "tool_args": dict(_RECORD_ARGS)}
    steps = [live_record, _same_probe(0), _same_probe(1), _same_probe(2), _same_probe(3),
             dict(_RECORD_DECISION), _DONE_DECISION]
    run_tool = AsyncMock(side_effect=lambda _ctx, name, _args:
                         {"ok": True, "status": 200, "text": "A"} if name == "send_request"
                         else _record_result())
    reply, _ = await _send(CopilotSession("s-dup"), _jar_ctx(), steps, run_tool)

    recorded = [c for c in run_tool.await_args_list if c.args[1] == "record_finding"]
    assert len(recorded) == 1  # the live loop's record; the wrap-up's is deduped
    assert "could not record 1 other finding(s)" in reply.message
    assert "duplicate of a call already issued" in reply.message

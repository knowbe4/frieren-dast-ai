"""
Unit tests for the Exploration Copilot engine (dast/ai/copilot/session.py).

The LLM step decision (_llm_step) and the shared tool layer (all_tools/run_tool)
are mocked, so these exercise the loop's control flow: reply ends a turn, call_tool
drives a tool and records the observation, the scope/auth walls pause for a human,
identical calls are suppressed, copilot-tagged tools are hidden from the menu, and
the per-turn ceiling forces a reply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch

import pytest

from dast.ai.copilot.session import CopilotSession


@dataclass
class _FakeTool:
    name: str
    description: str = "does a thing"
    tags: List[str] = field(default_factory=list)


class _FakeCtx:
    def __init__(self, in_scope: bool = True) -> None:
        self._in_scope = in_scope
        self.approved_hosts: set = set()

    def is_in_scope(self, url: str) -> bool:
        return self._in_scope


def _collector():
    events: List[Dict[str, Any]] = []

    async def on_event(payload: Dict[str, Any]) -> None:
        events.append(payload)

    return events, on_event


def _deny_human():
    async def wait_for_human(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"decision": "deny"} if kind == "approve" else {"cookies": {}}

    return wait_for_human


_TOOLS = [_FakeTool("send_request"), _FakeTool("get_history"),
          _FakeTool("copilot_ask", tags=["copilot"])]


@pytest.mark.asyncio
async def test_reply_ends_turn_and_records_history():
    session = CopilotSession("s1")
    events, on_event = _collector()

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=AsyncMock()), \
         patch("dast.ai.copilot.session._llm_step",
               new=AsyncMock(side_effect=[{"action": "reply", "thought": "t",
                                           "message": "Here is what I found."}])):
        reply = await session.send("hi", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.message == "Here is what I found."
    assert reply.blocked_reason == ""
    assert session.messages == [
        {"role": "operator", "content": "hi"},
        {"role": "copilot", "content": "Here is what I found."},
    ]
    assert any(e["type"] == "reply" for e in events)


@pytest.mark.asyncio
async def test_call_tool_then_reply_runs_tool_and_observes():
    session = CopilotSession("s2")
    events, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200, "body": "pong"})

    steps = [
        {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
         "tool_args": {"url": "https://in.scope/x"}},
        {"action": "reply", "thought": "done", "message": "It responded 200."},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("probe it", _FakeCtx(in_scope=True),
                                   on_event=on_event, wait_for_human=_deny_human())

    run_tool.assert_awaited_once()
    assert reply.message == "It responded 200."
    assert len(reply.transcript) == 1
    assert reply.transcript[0]["observation"]
    assert any(e["type"] == "observation" for e in events)


@pytest.mark.asyncio
async def test_out_of_scope_denied_records_observation_not_call():
    session = CopilotSession("s3")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True})

    steps = [
        {"action": "call_tool", "thought": "hit evil", "tool_name": "send_request",
         "tool_args": {"url": "https://evil.example.com/x"}},
        {"action": "reply", "thought": "blocked", "message": "That host is out of scope.",
         "blocked_reason": "out_of_scope"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("hit it", _FakeCtx(in_scope=False),
                                   on_event=on_event, wait_for_human=_deny_human())

    run_tool.assert_not_awaited()  # denied before dispatch
    assert reply.blocked_reason == "out_of_scope"
    assert "Denied by operator" in reply.transcript[0]["observation"]


@pytest.mark.asyncio
async def test_allow_once_lets_out_of_scope_call_run():
    session = CopilotSession("s4")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200})

    async def allow_once(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"decision": "allow_once"}

    steps = [
        {"action": "call_tool", "thought": "hit", "tool_name": "send_request",
         "tool_args": {"url": "https://new.example.com/x"}},
        {"action": "reply", "thought": "done", "message": "ok"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        await session.send("go", _FakeCtx(in_scope=False),
                           on_event=on_event, wait_for_human=allow_once)

    run_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_identical_call_is_suppressed():
    session = CopilotSession("s5")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200})

    call = {"action": "call_tool", "thought": "again", "tool_name": "send_request",
            "tool_args": {"url": "https://in.scope/x"}}
    steps = [call, dict(call), {"action": "reply", "thought": "done", "message": "ok"}]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    run_tool.assert_awaited_once()  # second identical call suppressed
    assert "suppressed" in reply.transcript[1]["observation"]


@pytest.mark.asyncio
async def test_copilot_tagged_tool_is_hidden_from_menu():
    session = CopilotSession("s6")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True})

    steps = [
        {"action": "call_tool", "thought": "self", "tool_name": "copilot_ask",
         "tool_args": {"message": "loop"}},
        {"action": "reply", "thought": "done", "message": "ok"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    run_tool.assert_not_awaited()  # copilot_ask not in the menu -> treated as unknown
    assert "Unknown tool" in reply.transcript[0]["observation"]


@pytest.mark.asyncio
async def test_blank_action_with_tool_name_is_recovered():
    # The decision model sometimes omits/blanks `action` while still naming a tool.
    # That step carries clear intent and must run the tool, not be discarded.
    session = CopilotSession("s8")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200})

    steps = [
        {"action": "", "thought": "plan", "tool_name": "send_request",
         "tool_args": {"url": "https://in.scope/x"}},
        {"action": "reply", "thought": "done", "message": "ok"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    run_tool.assert_awaited_once()
    assert reply.message == "ok"


@pytest.mark.asyncio
async def test_blank_action_with_message_is_recovered_as_reply():
    session = CopilotSession("s9")
    _, on_event = _collector()

    steps = [{"action": "", "thought": "", "message": "I'm done here."}]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=AsyncMock()), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.message == "I'm done here."


@pytest.mark.asyncio
async def test_planning_only_steps_are_bounded_and_end_turn():
    # A step that commits to neither a tool call nor a reply must not loop forever:
    # consecutive planning-only steps hit the failure ceiling and hand back.
    session = CopilotSession("s10")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True})

    def planning_only(*_a, **_k):
        return {"action": "", "thought": "still thinking, no action yet"}

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step",
               new=AsyncMock(side_effect=planning_only)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    run_tool.assert_not_awaited()
    assert reply.blocked_reason == "need_direction"


@pytest.mark.asyncio
async def test_planning_steps_do_not_consume_tool_budget():
    # A planning-only step interleaved with real tool calls resets the failure
    # counter, so the copilot still gets its full per-turn tool-call budget rather
    # than losing half of it to empty steps (the pre-fix bug).
    from dast.ai.copilot.session import _MAX_TOOL_CALLS_PER_TURN

    session = CopilotSession("s11")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200})

    def alternate(*_a, **_k):
        alternate.n += 1
        if alternate.n % 2 == 1:
            return {"action": "", "thought": "plan next probe"}  # no tool, no reply
        return {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
                "tool_args": {"url": f"https://in.scope/{alternate.n}"}}
    alternate.n = 0

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=alternate)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.blocked_reason == "need_direction"
    assert run_tool.await_count == _MAX_TOOL_CALLS_PER_TURN


def test_summarize_result_keeps_reflections_ahead_of_body():
    # send_request returns a large body plus a compact `reflections` signal. The
    # summary must lead with reflections so a 2000-char truncation keeps it.
    from dast.ai.copilot.session import (
        _OBSERVATION_MAX_CHARS,
        _summarize_result,
    )

    result = {
        "ok": True,
        "status": 200,
        "length": 9500,
        "final_url": "https://in.scope/xss",
        "body": "A" * 9000,  # dominates the raw dump, would bury the signal
        "reflections": [{"parameter": "name", "location": "query",
                         "reflected_raw": True, "html_escaped_also_present": False,
                         "context": "Hello <script>alert('x')</script> world"}],
    }
    summary = _summarize_result(result)
    truncated = summary[:_OBSERVATION_MAX_CHARS]
    # The reflection signal survives the truncation the transcript will apply.
    assert "reflections" in truncated
    assert "reflected_raw" in truncated
    assert "<script>alert('x')</script>" in truncated
    # The bulky body is trimmed, not dumped whole.
    assert result["body"] not in summary


def test_summarize_result_passes_through_non_body_results():
    from dast.ai.copilot.session import _summarize_result

    assert _summarize_result({"ok": True, "count": 3}) == '{"ok": true, "count": 3}'


@pytest.mark.asyncio
async def test_turn_ceiling_forces_reply():
    session = CopilotSession("s7")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200})

    # Always call a tool, never reply: with a distinct URL each step it never
    # trips the anti-repeat guard, so only the ceiling stops it.
    def endless(*_a, **_k):
        endless.n += 1
        return {"action": "call_tool", "thought": "loop", "tool_name": "send_request",
                "tool_args": {"url": f"https://in.scope/{endless.n}"}}
    endless.n = 0

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=endless)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.blocked_reason == "need_direction"

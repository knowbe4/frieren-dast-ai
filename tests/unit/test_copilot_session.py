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

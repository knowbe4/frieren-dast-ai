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
    input_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class _FakeEntry:
    """Minimal ProxyEntry stand-in for auth-header sniffing."""

    host: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    source: str = "proxy"


class _FakeStore:
    """Minimal SessionStore stand-in exposing the cookie/entry accessors that
    CopilotSession._apply_session_auth reads."""

    def __init__(self, cookies: List[Dict[str, str]] | None = None,
                 entries: List[_FakeEntry] | None = None) -> None:
        self._cookies = cookies or []
        self._entries = entries or []

    def get_cookies_for_host(self, host: str) -> List[Dict[str, str]]:
        return list(self._cookies)

    def all_entries(self) -> List[_FakeEntry]:
        return list(self._entries)


class _FakeCtx:
    def __init__(self, in_scope: bool = True) -> None:
        self._in_scope = in_scope
        self.approved_hosts: set = set()
        self.store: Any = None

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
async def test_reply_with_empty_message_falls_back_to_thought():
    # The step schema only requires thought+action, so the model can commit to a
    # reply with all its substance in `thought` and `message` left blank. The turn
    # must surface that reasoning to the operator, not a useless placeholder.
    session = CopilotSession("s-empty")
    events, on_event = _collector()

    analysis = ("Both ldapToken and adiToken returned non-null values (redacted). "
                "Field-level access control appears missing for this session.")
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=AsyncMock()), \
         patch("dast.ai.copilot.session._llm_step",
               new=AsyncMock(side_effect=[{"action": "reply", "thought": analysis,
                                           "message": ""}])):
        reply = await session.send("test", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.message == analysis
    assert "empty reply" not in reply.message
    assert session.messages[-1] == {"role": "copilot", "content": analysis}


@pytest.mark.asyncio
async def test_reply_with_no_message_and_no_thought_uses_placeholder():
    session = CopilotSession("s-blank")
    _, on_event = _collector()

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=AsyncMock()), \
         patch("dast.ai.copilot.session._llm_step",
               new=AsyncMock(side_effect=[{"action": "reply", "thought": "",
                                           "message": ""}])):
        reply = await session.send("test", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.message == "(the copilot produced an empty reply)"


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
async def test_non_numeric_status_result_does_not_crash_turn():
    # The auth-wall gate runs on every tool result and reads ``status`` as an HTTP
    # code. Non-request tools (run_scan) put a non-numeric status here
    # ("vulnerable"/"scanning"/"safe"); it must be tolerated, not int()-crashed
    # into an "error" turn. Regression for the run_scan integration.
    session = CopilotSession("s-scan")
    events, on_event = _collector()
    run_tool = AsyncMock(return_value={
        "ok": True, "status": "vulnerable", "url": "https://in.scope/x",
        "findings": [{"vuln_type": "sqli"}],
    })

    steps = [
        {"action": "call_tool", "thought": "scan", "tool_name": "run_scan",
         "tool_args": {"url": "https://in.scope/x"}},
        {"action": "reply", "thought": "done", "message": "Scan found a vuln."},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS + [_FakeTool("run_scan", tags=["active"])]), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("scan it", _FakeCtx(in_scope=True),
                                   on_event=on_event, wait_for_human=_deny_human())

    run_tool.assert_awaited_once()
    assert reply.blocked_reason == ""          # not "error"
    assert reply.message == "Scan found a vuln."
    assert reply.transcript[0]["observation"]  # the scan result was observed


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


@pytest.mark.asyncio
async def test_repeated_failing_tool_calls_end_turn_early():
    # A model that keeps firing failing calls (e.g. validate_chain with bad args)
    # must not run to the 12-call ceiling: the tool-failure guard hands back after
    # _MAX_CONSECUTIVE_TOOL_FAILURES. Distinct URLs each step evade anti-repeat, so
    # the failure counter (not the dedup) is what stops the loop.
    from dast.ai.copilot.session import _MAX_CONSECUTIVE_TOOL_FAILURES

    session = CopilotSession("s-fail")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": False, "error": "bad args"})

    def failing(*_a, **_k):
        failing.n += 1
        return {"action": "call_tool", "thought": "retry", "tool_name": "send_request",
                "tool_args": {"url": f"https://in.scope/{failing.n}"}}
    failing.n = 0

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=failing)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.blocked_reason == "need_direction"
    assert run_tool.await_count == _MAX_CONSECUTIVE_TOOL_FAILURES  # not the 12 ceiling


@pytest.mark.asyncio
async def test_successful_calls_reset_the_failure_guard():
    # An occasional failure interleaved with successes must not accumulate toward
    # the failure ceiling — only a *consecutive* run of failures ends the turn.
    session = CopilotSession("s-mix")
    _, on_event = _collector()

    def outcome(ctx, name, args):
        # Odd calls fail, even calls succeed -> failures never reach the ceiling.
        outcome.n += 1
        return {"ok": outcome.n % 2 == 0, "status": 200}
    outcome.n = 0
    run_tool = AsyncMock(side_effect=outcome)

    def alternate(*_a, **_k):
        alternate.n += 1
        if alternate.n > 8:
            return {"action": "reply", "thought": "done", "message": "ok"}
        return {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
                "tool_args": {"url": f"https://in.scope/{alternate.n}"}}
    alternate.n = 0

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=alternate)):
        reply = await session.send("go", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.message == "ok"  # reached the reply, not the failure guard


@pytest.mark.asyncio
async def test_session_auth_injects_jar_cookies_and_borrowed_headers():
    # The copilot must reuse the operator's already-captured session: the proxy
    # cookie jar for the target host plus auth headers borrowed from the freshest
    # request to that host, applied when the model did not set them itself.
    session = CopilotSession("s-auth")
    _, on_event = _collector()

    store = _FakeStore(
        cookies=[{"name": "session", "value": "abc"}],
        entries=[_FakeEntry(host="in.scope",
                            request_headers={"Authorization": "Bearer XYZ",
                                             "Cookie": "old=1"})],
    )
    ctx = _FakeCtx()
    ctx.store = store

    captured: Dict[str, Any] = {}

    async def fake_run_tool(_ctx, _name, args):
        captured["args"] = args
        return {"ok": True, "status": 200}

    steps = [
        {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
         "tool_args": {"url": "https://in.scope/x"}},
        {"action": "reply", "thought": "done", "message": "ok"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=fake_run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        await session.send("go", ctx, on_event=on_event, wait_for_human=_deny_human())

    headers = captured["args"]["headers"]
    assert headers["Cookie"] == "session=abc"  # from the host-scoped jar
    assert headers["Authorization"] == "Bearer XYZ"  # borrowed from history


@pytest.mark.asyncio
async def test_session_auth_never_overwrites_model_set_headers():
    session = CopilotSession("s-auth2")
    _, on_event = _collector()

    store = _FakeStore(
        cookies=[{"name": "session", "value": "abc"}],
        entries=[_FakeEntry(host="in.scope",
                            request_headers={"Authorization": "Bearer STALE"})],
    )
    ctx = _FakeCtx()
    ctx.store = store

    captured: Dict[str, Any] = {}

    async def fake_run_tool(_ctx, _name, args):
        captured["args"] = args
        return {"ok": True, "status": 200}

    steps = [
        {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
         "tool_args": {"url": "https://in.scope/x",
                       "headers": {"Authorization": "Bearer MINE"}}},
        {"action": "reply", "thought": "done", "message": "ok"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=fake_run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        await session.send("go", ctx, on_event=on_event, wait_for_human=_deny_human())

    headers = captured["args"]["headers"]
    assert headers["Authorization"] == "Bearer MINE"  # model's header preserved
    assert headers["Cookie"] == "session=abc"  # jar cookie still added


def test_render_arg_signature_marks_required_and_anyof():
    from dast.ai.copilot.session import _render_arg_signature

    schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string"},
            "report_text": {"type": "string"},
            "chain": {"type": "object"},
        },
        "required": ["url"],
        "anyOf": [{"required": ["report_text"]}, {"required": ["chain"]}],
    }
    signature = _render_arg_signature(schema)
    assert "url*:string" in signature
    assert "method:string" in signature
    assert "report_text*:string" in signature  # required via anyOf
    assert "chain*:object" in signature
    assert _render_arg_signature({}) == ""
    assert _render_arg_signature(None) == ""


def test_tool_menu_includes_arg_signatures():
    from dast.ai.copilot.session import _render_tool_menu

    tool_defs = [{
        "name": "send_request",
        "description": "Send one HTTP request.\nMore detail here.",
        "input_schema": {"type": "object",
                         "properties": {"url": {"type": "string"}},
                         "required": ["url"]},
    }]
    menu = _render_tool_menu(tool_defs)
    assert "- send_request: Send one HTTP request." in menu
    assert "url*:string" in menu
    assert "More detail here." not in menu  # only the first description line

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
    assert "Denied" in reply.transcript[0]["observation"]


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


def test_summarize_result_flags_truncated_body_with_extract_hint():
    # A body larger than the observation cap must carry body_truncated + a hint pointing at
    # extract_response, ahead of the trimmed body so the truncation never eats them.
    from dast.ai.copilot.session import (
        _OBSERVATION_BODY_CHARS,
        _OBSERVATION_MAX_CHARS,
        _summarize_result,
    )

    big = {"ok": True, "status": 200, "final_url": "https://in.scope/list",
           "length": 104663, "body": "{" + "x" * (_OBSERVATION_BODY_CHARS + 5000)}
    summary = _summarize_result(big)[:_OBSERVATION_MAX_CHARS]
    assert '"body_truncated": true' in summary
    assert "extract_response" in summary and "https://in.scope/list" in summary

    # A small body carries neither field.
    small = {"ok": True, "status": 200, "body": "tiny"}
    s2 = _summarize_result(small)
    assert "body_truncated" not in s2 and "extract_response" not in s2


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
async def test_login_form_loop_hint_steers_to_browser_login():
    # The model hand-drives a login FORM, snapshotting the login page in a loop
    # (identical browser_snapshot calls get suppressed, 200 body — no 302/401 in
    # play). The spin-hint that fires before the kill must steer it to the
    # deterministic browser_login tool instead of more manual browser steps.
    tools = [_FakeTool("browser_snapshot"), _FakeTool("browser_login"),
             _FakeTool("send_request")]
    session = CopilotSession("s-loginloop")
    _, on_event = _collector()
    # The login page snapshot body carries the login signal (email/password form).
    run_tool = AsyncMock(return_value={
        "ok": True, "status": 200,
        "body": "Email Password Sign in to your account"})

    def drive_login(*_a, **_k):
        # Same browser_snapshot of the login page every step -> exact-dedup
        # suppression accumulates toward the consecutive-failure ceiling (snapshot
        # does not reset the anti-repeat set, unlike navigate/fill/click).
        return {"action": "call_tool", "thought": "read the login form",
                "tool_name": "browser_snapshot", "tool_args": {}}

    with patch("dast.tools.all_tools", return_value=tools), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step",
               new=AsyncMock(side_effect=drive_login)):
        reply = await session.send("log in and solve", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.blocked_reason == "need_direction"
    assert "browser_login" in reply.message
    assert "{url, email, password}" in reply.message


@pytest.mark.asyncio
async def test_non_login_browser_loop_keeps_generic_repeat_hint():
    # A browser_snapshot loop on a NON-login page must NOT be captured by the new
    # login-loop branch — it falls through to the generic repeat hint, which does
    # not mention browser_login. Guards the branch ordering against over-capture.
    tools = [_FakeTool("browser_snapshot"), _FakeTool("browser_login"),
             _FakeTool("send_request")]
    session = CopilotSession("s-dashloop")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={
        "ok": True, "status": 200, "body": "Dashboard widgets and metrics"})

    def drive_dash(*_a, **_k):
        return {"action": "call_tool", "thought": "look again",
                "tool_name": "browser_snapshot", "tool_args": {}}

    with patch("dast.tools.all_tools", return_value=tools), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step",
               new=AsyncMock(side_effect=drive_dash)):
        reply = await session.send("keep going", _FakeCtx(), on_event=on_event,
                                   wait_for_human=_deny_human())

    assert reply.blocked_reason == "need_direction"
    assert "browser_login" not in reply.message
    assert "repeating the same tool call" in reply.message


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
    # Authorization is NOT borrowed from the global history directly (that would
    # leak a token across concurrent sessions); it is captured into this engine's
    # own per-session _bearer_tokens cache and applied from there.
    assert headers["Authorization"] == "Bearer XYZ"


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


@pytest.mark.asyncio
async def test_session_auth_strips_model_pasted_stale_cookie():
    # The model must NOT be able to pin a stale/foreign session by pasting its own
    # Cookie/X-CSRF-Token — the tool replaces them with the ACTIVE jar session (this is
    # the loop that stalled the 2nd run).
    session = CopilotSession("s-auth3")
    _, on_event = _collector()

    store = _FakeStore(
        cookies=[{"name": "session", "value": "ACTIVE"},
                 {"name": "CSRF-TOKEN", "value": "FRESH"}],
        entries=[],
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
                       "headers": {"Cookie": "session=STALE; CSRF-TOKEN=old",
                                   "X-CSRF-Token": "oldtok"}}},
        {"action": "reply", "thought": "done", "message": "ok"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=fake_run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        await session.send("go", ctx, on_event=on_event, wait_for_human=_deny_human())

    headers = captured["args"]["headers"]
    # stale cookie replaced with the active jar session
    assert "STALE" not in headers["Cookie"]
    assert "session=ACTIVE" in headers["Cookie"]
    # stale CSRF refreshed from the active session cookie, not the model's "oldtok"
    assert headers["X-CSRF-Token"] == "FRESH"
    assert headers["x-dast-cookies-injected"] == "1"


@pytest.mark.asyncio
async def test_soft_auth_wall_with_profile_creds_relogins_and_retries():
    # A SOFT auth wall (200 login page, no 302/401) with profile relogin credentials
    # seeded (engine._last_login) must auto-relogin through the existing refresh ladder
    # and retry the identical call — never pausing for a human.
    from dast.ai.copilot.session import RefreshOutcome, RefreshTier
    session = CopilotSession("s-authrelogin")
    _, on_event = _collector()
    session._last_login = {"url": "https://app.example.com/login",
                           "email": "u@example.com", "password": "pw"}

    auth_wall = {"ok": True, "status": 200, "body": "Please log in to continue.",
                 "final_url": "https://app.example.com/login"}
    clean = {"ok": True, "status": 200, "body": "dashboard"}
    run_tool = AsyncMock(side_effect=[auth_wall, clean])

    relogin = AsyncMock(return_value=RefreshOutcome(None, RefreshTier.RELOGIN, acted=True))
    session.refresh_bearer = relogin

    human_kinds: List[str] = []

    async def wait_for_human(kind, payload):
        human_kinds.append(kind)
        return {"decision": "deny"} if kind == "approve" else {"cookies": {}}

    steps = [
        {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
         "tool_args": {"url": "https://app.example.com/dashboard"}},
        {"action": "call_tool", "thought": "retry", "tool_name": "send_request",
         "tool_args": {"url": "https://app.example.com/dashboard"}},
        {"action": "reply", "thought": "done", "message": "ok"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        await session.send("go", _FakeCtx(in_scope=True), on_event=on_event,
                           wait_for_human=wait_for_human)

    relogin.assert_awaited()                       # credential relogin was attempted
    assert "auth" not in human_kinds               # human was NEVER prompted for auth
    assert run_tool.await_count == 2               # the identical call was retried


@pytest.mark.asyncio
async def test_soft_auth_wall_without_creds_still_pauses():
    # No profile credentials (engine._last_login is None): the soft auth wall must still
    # hand off to the operator, and the relogin ladder must NOT be invoked.
    session = CopilotSession("s-authnopause")
    _, on_event = _collector()
    assert session._last_login is None

    auth_wall = {"ok": True, "status": 200, "body": "Please log in to continue.",
                 "final_url": "https://app.example.com/login"}
    run_tool = AsyncMock(return_value=auth_wall)

    relogin = AsyncMock()
    session.refresh_bearer = relogin

    human_kinds: List[str] = []

    async def wait_for_human(kind, payload):
        human_kinds.append(kind)
        return {"cookies": {}}

    steps = [
        {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
         "tool_args": {"url": "https://app.example.com/dashboard"}},
        {"action": "reply", "thought": "done", "message": "blocked on auth"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        await session.send("go", _FakeCtx(in_scope=True), on_event=on_event,
                           wait_for_human=wait_for_human)

    relogin.assert_not_awaited()                   # no creds → no relogin
    assert "auth" in human_kinds                   # still paused for the operator


@pytest.mark.asyncio
async def test_soft_auth_wall_relogin_respects_cooldown():
    # A relogin that JUST happened (within _RELOGIN_COOLDOWN_S) must NOT be retried on the
    # next auth wall — the real refresh ladder's tier-4 cooldown gates it, so _tier_relogin
    # is not called and the gate falls through to the operator.
    import time as _time

    from dast.ai.copilot.session import _RELOGIN_COOLDOWN_S
    session = CopilotSession("s-authcooldown")
    _, on_event = _collector()
    session._last_login = {"url": "https://app.example.com/login",
                           "email": "u@example.com", "password": "pw"}
    # Simulate a relogin that fired moments ago (the "first auth wall" of the run).
    session._last_relogin_ts = _time.time()
    assert _RELOGIN_COOLDOWN_S > 0

    tier_relogin = AsyncMock(return_value=True)
    session._tier_relogin = tier_relogin  # must stay uncalled while in cooldown

    auth_wall = {"ok": True, "status": 200, "body": "Please log in to continue.",
                 "final_url": "https://app.example.com/login"}
    run_tool = AsyncMock(return_value=auth_wall)

    human_kinds: List[str] = []

    async def wait_for_human(kind, payload):
        human_kinds.append(kind)
        return {"cookies": {}}

    ctx = _FakeCtx(in_scope=True)
    ctx.browser = object()  # tier-4 requires a browser; cooldown is the only gate left

    steps = [
        {"action": "call_tool", "thought": "probe", "tool_name": "send_request",
         "tool_args": {"url": "https://app.example.com/dashboard"}},
        {"action": "reply", "thought": "done", "message": "blocked on auth"},
    ]
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        await session.send("go", ctx, on_event=on_event, wait_for_human=wait_for_human)

    tier_relogin.assert_not_awaited()              # cooldown blocked the relogin
    assert "auth" in human_kinds                   # fell through to the operator


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


# ── B2: malformed args (missing required field) are repaired, not spun on ───────

_REQ_TOOLS = [
    _FakeTool("send_request", input_schema={
        "type": "object",
        "properties": {"url": {"type": "string"}, "method": {"type": "string"}},
        "required": ["url"],
    }),
    _FakeTool("get_history"),
]


@pytest.mark.asyncio
async def test_missing_required_arg_is_repaired_via_forced_schema():
    """When the model emits send_request with no url, the forced-schema repair
    supplies it and the call executes — no failure, no spin."""
    session = CopilotSession("s-repair")
    events, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200, "body": "ok"})
    repair = AsyncMock(return_value={"url": "https://in.scope/load", "method": "GET"})

    steps = [
        {"action": "call_tool", "thought": "read it", "tool_name": "send_request",
         "tool_args": {"method": "GET"}},  # url dropped by the model
        {"action": "reply", "thought": "done", "message": "done"},
    ]
    with patch("dast.tools.all_tools", return_value=_REQ_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._repair_tool_args", new=repair), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("probe", _FakeCtx(in_scope=True),
                                   on_event=on_event, wait_for_human=_deny_human())

    repair.assert_awaited_once()
    run_tool.assert_awaited_once()
    # the executed call carried the repaired url
    _ctx, name, args = run_tool.await_args.args
    assert name == "send_request" and args.get("url") == "https://in.scope/load"
    assert reply.message == "done"


@pytest.mark.asyncio
async def test_missing_required_arg_is_caught_before_execution_and_retried():
    """A send_request with no url must not reach run_tool, must not poison the
    anti-repeat set, and the corrected call (with url) must then execute."""
    session = CopilotSession("s-missing")
    events, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200, "body": "ok"})

    steps = [
        {"action": "call_tool", "thought": "go", "tool_name": "send_request",
         "tool_args": {"method": "GET"}},  # missing url
        {"action": "call_tool", "thought": "fixed", "tool_name": "send_request",
         "tool_args": {"url": "https://in.scope/load", "method": "GET"}},
        {"action": "reply", "thought": "done", "message": "done"},
    ]
    # Force the schema-repair to fail so this exercises the nudge fallback path.
    with patch("dast.tools.all_tools", return_value=_REQ_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._repair_tool_args", new=AsyncMock(return_value=None)), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("probe", _FakeCtx(in_scope=True),
                                   on_event=on_event, wait_for_human=_deny_human())

    # Only the corrected call reached run_tool.
    run_tool.assert_awaited_once()
    assert reply.message == "done"
    obs = [e.get("observation", "") for e in events if e.get("type") == "observation"]
    assert any("missing required" in o and "url" in o for o in obs)
    assert not any("suppressed" in o for o in obs)  # the empty call never deduped


# ── B3: a mutation clears the anti-repeat set so a confirming re-read runs ───────

@pytest.mark.asyncio
async def test_mutation_allows_repeated_read_to_observe_new_state():
    """GET load, DELETE, then the SAME GET load again (to confirm destruction):
    the post-mutation re-read must NOT be suppressed as a duplicate."""
    session = CopilotSession("s-mut")
    events, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 200, "body": "x"})

    load = {"url": "https://in.scope/load/u", "method": "GET"}
    steps = [
        {"action": "call_tool", "thought": "read", "tool_name": "send_request", "tool_args": dict(load)},
        {"action": "call_tool", "thought": "delete", "tool_name": "send_request",
         "tool_args": {"url": "https://in.scope/delete/u", "method": "DELETE"}},
        {"action": "call_tool", "thought": "confirm", "tool_name": "send_request", "tool_args": dict(load)},
        {"action": "reply", "thought": "done", "message": "confirmed"},
    ]
    with patch("dast.tools.all_tools", return_value=_REQ_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("retest", _FakeCtx(in_scope=True),
                                   on_event=on_event, wait_for_human=_deny_human())

    # All three request calls ran — the repeated GET was not suppressed.
    assert run_tool.await_count == 3
    assert reply.message == "confirmed"
    obs = [e.get("observation", "") for e in events if e.get("type") == "observation"]
    assert not any("suppressed" in o for o in obs)


def test_copilot_step_schema_does_not_require_action():
    """A gateway model sometimes omits `action` under schema forcing; the step
    must survive validation so the session can infer the action downstream from
    tool_name/message (regression for the 'missing required field(s): action'
    turn-abort loop)."""
    from dast.ai.schemas import COPILOT_STEP_SCHEMA
    from dast.ai.bedrock_client import _require_fields

    assert "action" not in COPILOT_STEP_SCHEMA["required"]
    assert COPILOT_STEP_SCHEMA["required"] == ["thought"]

    step_without_action = {"thought": "crawl the app next", "tool_name": "crawl",
                           "tool_args": {"url": "https://app.example.com/"}}
    # Must NOT raise now that `action` is optional.
    assert _require_fields(step_without_action, COPILOT_STEP_SCHEMA) == step_without_action


# ── coordinator watchdog: kill a turn looping on the same normalized call ─────

def test_normalized_call_sig_ignores_header_literals():
    from dast.ai.copilot.session import _normalized_call_sig
    a = {"url": "https://in.scope/x", "method": "POST", "body": "b",
         "headers": {"Cookie": "session=1", "X-CSRF-Token": "t1"}}
    b = {"url": "https://in.scope/x", "method": "POST", "body": "b",
         "headers": {"Cookie": "session=2", "X-CSRF-Token": "t2"}}
    assert _normalized_call_sig("send_request", a) == _normalized_call_sig("send_request", b)
    # a different endpoint is a different signature
    c = dict(a); c["url"] = "https://in.scope/y"
    assert _normalized_call_sig("send_request", c) != _normalized_call_sig("send_request", a)


@pytest.mark.asyncio
async def test_watchdog_kills_turn_repeating_same_normalized_call():
    # The model pastes a DIFFERENT Cookie literal each call (slips the exact-dedup) but
    # the intent is identical — the watchdog must break the turn with stuck_loop.
    session = CopilotSession("s-watchdog")
    _, on_event = _collector()
    store = _FakeStore(cookies=[{"name": "session", "value": "A"}], entries=[])
    ctx = _FakeCtx()
    ctx.store = store

    async def fake_run_tool(_ctx, _name, args):
        return {"ok": True, "status": 200}

    steps = [
        {"action": "call_tool", "thought": "p", "tool_name": "send_request",
         "tool_args": {"url": "https://in.scope/x", "method": "POST", "body": "b",
                       "headers": {"Cookie": f"session=STALE{i}"}}}
        for i in range(4)
    ] + [{"action": "reply", "thought": "d", "message": "ok"}]

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=fake_run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", ctx, on_event=on_event, wait_for_human=_deny_human())

    assert reply.blocked_reason == "stuck_loop"
    assert "cookie" in reply.message.lower()


@pytest.mark.asyncio
async def test_watchdog_kills_model_repeatedly_pasting_session_headers_across_endpoints():
    # The per-call watchdog misses this: the model pastes Cookie on DIFFERENT urls each time.
    # The cross-endpoint strip-counter must trip stuck_loop once it is clear the model keeps
    # supplying session headers the tool ignores.
    from dast.ai.copilot.session import _MAX_HEADER_STRIPS
    session = CopilotSession("s-strip")
    _, on_event = _collector()
    store = _FakeStore(cookies=[{"name": "session", "value": "ACTIVE"}], entries=[])
    ctx = _FakeCtx()
    ctx.store = store

    async def fake_run_tool(_ctx, _name, args):
        return {"ok": True, "status": 200}

    n = _MAX_HEADER_STRIPS * 2
    steps = [
        {"action": "call_tool", "thought": "p", "tool_name": "send_request",
         "tool_args": {"url": f"https://in.scope/e{i}", "headers": {"Cookie": "session=STALE"}}}
        for i in range(n)
    ] + [{"action": "reply", "thought": "d", "message": "ok"}]

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=fake_run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=steps)):
        reply = await session.send("go", ctx, on_event=on_event, wait_for_human=_deny_human())

    assert reply.blocked_reason == "stuck_loop"
    assert "cookie" in reply.message.lower()


# ── _ensure_fresh_bearer: wait for the SPA to mint a Bearer after navigate-commit ──

def _unexpired_jwt() -> str:
    """A structurally valid JWT with NO exp claim (so _decode_jwt_exp -> None -> treated
    fresh). Built at runtime so no eyJ... literal sits in the source (gitleaks)."""
    import base64 as _b64, json as _json

    def seg(obj):
        return _b64.urlsafe_b64encode(_json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'HS512'})}.{seg({'sub': '1', 'account_id': 999})}.{seg('sig1234567890')}"


@dataclass
class _BearerEntry:
    host: str
    request_headers: Dict[str, str]
    path: str = "/v1/dashboard"
    source: str = "proxy"
    id: str = "e1"


class _DelayedStore:
    """all_entries() returns the Bearer entry only from the Nth call onward — simulating
    the SPA's authenticated call landing shortly after navigate resolved on 'commit'."""

    def __init__(self, appears_on_call: int, entry):
        self._n = 0
        self._appears = appears_on_call
        self._entry = entry

    def all_entries(self):
        self._n += 1
        return [self._entry] if self._n >= self._appears else []


class _BrowserOnHost:
    current_url = "https://svc.example/"


@pytest.mark.asyncio
async def test_ensure_fresh_bearer_waits_for_spa_token():
    session = CopilotSession("s-bearer")
    entry = _BearerEntry(host="api.svc.example",
                         request_headers={"Authorization": f"Bearer {_unexpired_jwt()}"})
    store = _DelayedStore(appears_on_call=2, entry=entry)  # absent on the fast path, appears after a poll
    rec = await session._ensure_fresh_bearer(
        store, "api.svc.example", "/queries_api/v2/x",
        browser=_BrowserOnHost(), timeout_s=3.0)
    assert rec and rec.get("token")


@pytest.mark.asyncio
async def test_ensure_fresh_bearer_no_wait_when_browser_elsewhere():
    import time as _time
    session = CopilotSession("s-bearer2")

    class _Empty:
        def all_entries(self):
            return []

    class _Elsewhere:
        current_url = "https://unrelated.example.com/"

    t0 = _time.monotonic()
    rec = await session._ensure_fresh_bearer(
        _Empty(), "api.svc.example", "/queries_api/v2/x",
        browser=_Elsewhere(), timeout_s=5.0)
    assert rec is None
    assert _time.monotonic() - t0 < 1.0   # did NOT burn the timeout — browser not on this host


# ── refresh_bearer: the reactive escalation ladder (REFETCH / RELOAD tiers) ──

class _FetchResp:
    def __init__(self, token: str, status: int = 200):
        self.status = status
        self._token = token

    async def text(self) -> str:
        import json as _json
        return _json.dumps({"token": self._token})


class _FetchRequest:
    def __init__(self, token: str):
        self._token = token

    async def fetch(self, url: str, method: str = "GET"):
        return _FetchResp(self._token)


class _RefetchBrowser:
    """A browser parked on an unrelated host (so WAIT_SPA is skipped) whose
    page.request.fetch mints a fresh token — exercises the REFETCH tier."""

    current_url = "https://elsewhere.example/"

    class _Page:
        url = "https://elsewhere.example/"

    def __init__(self, token: str):
        self._page = self._Page()
        self._page.request = _FetchRequest(token)

    async def _ensure_page(self):
        return self._page


class _ReloadBrowser:
    """A browser on the target host that records whether reload() was called."""

    current_url = "https://api.svc.example/"

    class _Page:
        url = "https://api.svc.example/"

    def __init__(self):
        self._page = self._Page()
        self.reloaded = False

    async def _ensure_page(self):
        return self._page

    async def reload(self, timeout_ms: int = 20000):
        self.reloaded = True
        return {"ok": True, "url": self._page.url, "status": 200}


@pytest.mark.asyncio
async def test_refresh_bearer_refetch_tier_mints_token():
    import time as _time
    from dast.ai.copilot.session import RefreshTier
    session = CopilotSession("s-refetch")
    host = "api.svc.example"
    # A known Bearer host whose cached token has expired, with a re-usable auth endpoint.
    session._bearer_tokens[host] = {
        "token": "old", "exp": _time.time() - 10,
        "auth_endpoint": "/api/auth/token", "source_entry_id": "e1"}

    class _Empty:
        def all_entries(self):
            return []

    outcome = await session.refresh_bearer(
        _Empty(), host, "/queries_api/v2/x",
        browser=_RefetchBrowser(_unexpired_jwt()),
        max_tier=RefreshTier.RELOGIN)
    assert outcome.acted is True
    assert outcome.tier_reached == RefreshTier.REFETCH
    assert outcome.record and outcome.record["token"] == _unexpired_jwt()


@pytest.mark.asyncio
async def test_refresh_bearer_refetch_respects_cooldown():
    import time as _time
    from dast.ai.copilot.session import RefreshTier
    session = CopilotSession("s-refetch-cd")
    host = "api.svc.example"
    session._bearer_tokens[host] = {
        "token": "old", "exp": _time.time() - 10,
        "auth_endpoint": "/api/auth/token", "source_entry_id": "e1"}
    session._last_bearer_refresh_ts = _time.time()  # just refreshed -> cooldown active

    class _Empty:
        def all_entries(self):
            return []

    outcome = await session.refresh_bearer(
        _Empty(), host, "/x", browser=_RefetchBrowser(_unexpired_jwt()),
        max_tier=RefreshTier.REFETCH)
    assert outcome.acted is False               # REFETCH skipped by the 15s cooldown
    assert outcome.record["token"] == "old"     # the stale token is returned, unrefreshed


@pytest.mark.asyncio
async def test_refresh_bearer_reload_tier():
    import time as _time
    from dast.ai.copilot.session import RefreshTier
    session = CopilotSession("s-reload")
    host = "api.svc.example"
    # Known Bearer host (so RELOAD is allowed), cached token expired, NO auth endpoint
    # (so REFETCH no-ops and the ladder escalates to RELOAD).
    session._bearer_tokens[host] = {"token": "old", "exp": _time.time() - 10}
    browser = _ReloadBrowser()
    entry = _BearerEntry(host=host,
                         request_headers={"Authorization": f"Bearer {_unexpired_jwt()}"})

    class _ReloadMintStore:
        """Returns the SPA's fresh token only after the page has been reloaded."""
        def all_entries(self):
            return [entry] if browser.reloaded else []

    outcome = await session.refresh_bearer(
        _ReloadMintStore(), host, "/queries_api/v2/x", browser=browser,
        max_tier=RefreshTier.RELOAD, timeout_s=0.5)
    assert browser.reloaded is True
    assert outcome.acted is True
    assert outcome.tier_reached == RefreshTier.RELOAD
    assert outcome.record and outcome.record["token"] == _unexpired_jwt()


# ── Phase 2: auto API->browser transport fallback (_browser_fallback) ──

from types import SimpleNamespace  # noqa: E402


@pytest.mark.asyncio
async def test_browser_fallback_reissues_via_browser_and_seeds_store():
    session = CopilotSession("s-fb")
    captured: Dict[str, Any] = {}

    async def fake_run_tool(ctx, name, args):
        captured["name"] = name
        captured["args"] = args
        return {"ok": True, "status": 200, "body": "{}", "length": 2}

    tool_ctx = SimpleNamespace(read_only=False)
    tool_args = {
        "url": "https://api.svc.example/queries_api/v2/accounts/1",
        "method": "GET",
        "headers": {"Cookie": "x=1", "Authorization": "Bearer stale", "X-CSRF-Token": "t",
                    "Content-Type": "application/json", "x-dast-source": "copilot"},
    }
    result = await session._browser_fallback(tool_ctx, tool_args, fake_run_tool)

    assert captured["name"] == "browser_fetch"
    assert captured["args"]["url"] == tool_args["url"] and captured["args"]["method"] == "GET"
    hdrs = captured["args"].get("headers", {})
    assert "Cookie" not in hdrs and "Authorization" not in hdrs and "X-CSRF-Token" not in hdrs
    assert not any(k.lower().startswith("x-dast-") for k in hdrs)
    assert hdrs.get("Content-Type") == "application/json"   # non-session headers kept
    assert result["status"] == 200 and "transport=browser" in result["note"]

    from dast.session.transport_capability import capability_for
    rec = capability_for("api.svc.example", "/queries_api/v2/accounts/1")
    assert rec is not None and rec["prefer"] == "browser" and rec["reason"] == "api_401_browser_ok"


@pytest.mark.asyncio
async def test_browser_fallback_respects_read_only_for_unsafe_method():
    session = CopilotSession("s-ro")
    called = {"n": 0}

    async def fake_run_tool(ctx, name, args):
        called["n"] += 1
        return {"ok": True, "status": 200}

    tool_ctx = SimpleNamespace(read_only=True)
    result = await session._browser_fallback(
        tool_ctx, {"url": "https://api.x.example/thing", "method": "DELETE"}, fake_run_tool)
    assert result is None and called["n"] == 0   # a DELETE is never re-issued under read-only


@pytest.mark.asyncio
async def test_browser_fallback_read_only_allows_safe_get():
    session = CopilotSession("s-ro-get")
    called = {"n": 0}

    async def fake_run_tool(ctx, name, args):
        called["n"] += 1
        return {"ok": True, "status": 200}

    tool_ctx = SimpleNamespace(read_only=True)
    await session._browser_fallback(
        tool_ctx, {"url": "https://api.z.example/a", "method": "GET"}, fake_run_tool)
    assert called["n"] == 1   # a GET passes the read-only gate and is re-issued


@pytest.mark.asyncio
async def test_browser_fallback_non_2xx_returned_but_not_recorded():
    session = CopilotSession("s-fb2")

    async def fake_run_tool(ctx, name, args):
        return {"ok": True, "status": 403, "body": "denied"}

    tool_ctx = SimpleNamespace(read_only=False)
    result = await session._browser_fallback(
        tool_ctx, {"url": "https://api.y.example/z", "method": "GET"}, fake_run_tool)
    assert result["status"] == 403 and "transport=browser" in result["note"]
    from dast.session.transport_capability import capability_for
    assert capability_for("api.y.example", "/z") is None   # only 2xx/3xx seeds the store


# ── regression: the browser-location CONTRACT the refresh ladder depends on ──
# The Bearer-refresh ladder gates its re-mint tiers (WAIT_SPA / RELOAD) on _browser_on_host,
# which reads the browser's current URL. It used to reach into browser.page.url, but the real
# AgentBrowser stored the page as _page and exposed no .page -> the gate was always False ->
# the re-mint tiers never fired against a real browser (short-TTL tokens could not be
# re-minted). The earlier ladder tests masked this with fakes that happened to define .page.
# The fix made AgentBrowser.current_url the stable contract; this test runs the REAL
# AgentBrowser so an interface drift fails here.

def test_agent_browser_current_url_contract_drives_on_host_check():
    from dast.browser.agent_browser import AgentBrowser
    ab = AgentBrowser(proxy_port=0, store=None, headless=True)
    assert hasattr(type(ab), "current_url"), "AgentBrowser must expose the current_url contract"
    assert ab.current_url == ""  # not launched yet -> on-host is False, no crash
    assert CopilotSession._browser_on_host(ab, "api.svc.example") is False

    # A launched page on the host's registrable domain -> current_url reflects it -> on-host
    # is True (was False before the fix because the ladder read a non-existent .page).
    ab._page = SimpleNamespace(url="https://svc.example/")
    assert ab.current_url == "https://svc.example/"
    assert CopilotSession._browser_on_host(ab, "api.svc.example") is True
    ab._page = SimpleNamespace(url="https://unrelated.example/")
    assert CopilotSession._browser_on_host(ab, "api.svc.example") is False


# ── P2: single-field extract_response observation is exempt from the generic cap ──
from dast.ai.copilot.session import (  # noqa: E402
    _render_turn_transcript,
    _summarize_result,
    _OBSERVATION_MAX_CHARS,
    _EXTRACT_FULL_OBSERVATION_CHARS,
)


def test_turn_transcript_respects_per_step_observation_cap():
    """A large observation is truncated under the default cap, but a per-step
    observation_cap (set for a full_value extract) lets the full value through."""
    big = "V" * (_OBSERVATION_MAX_CHARS + 3000)
    assert len(big) < _EXTRACT_FULL_OBSERVATION_CHARS

    capped = _render_turn_transcript([
        {"step": 1, "thought": "t", "tool_name": "send_request",
         "tool_args": {}, "observation": big},
    ])
    assert big not in capped  # generic cap still trims an uncapped observation

    lifted = _render_turn_transcript([
        {"step": 1, "thought": "t", "tool_name": "extract_response",
         "tool_args": {}, "observation": big,
         "observation_cap": _EXTRACT_FULL_OBSERVATION_CHARS},
    ])
    assert big in lifted  # the exempt result reaches the model intact


def test_summarize_result_passes_full_value_result_through():
    """extract_response results carry no 'body' key, so _summarize_result serializes
    them verbatim (no internal body trim) — the full value survives."""
    token = "J" * 1500
    out = _summarize_result({"ok": True, "values": [token], "full_value": True})
    assert token in out


# --- 5-A-1: progress scratchpad (cross-turn memory) --------------------------


def test_note_step_extracts_method_path_and_status():
    """The scratchpad line is a compact `METHOD /path -> status` record."""
    session = CopilotSession("s-scratch")
    session._note_step("send_request", {"url": "https://h.test/api/x", "method": "post"},
                       {"status": 403})
    session._note_step("send_request", {"url": "https://h.test/api/y"},
                       {"error": "timeout"})
    session._note_step("get_history", {}, {"ok": True})
    lines = [e["line"] for e in session._scratchpad]
    assert lines[0] == "POST /api/x -> 403"
    assert lines[1] == "GET /api/y -> err (timeout)"
    assert lines[2] == "GET / -> ok"


def test_scratchpad_caps_entries_and_prompt_block():
    """The store caps at _SCRATCHPAD_MAX_ENTRIES; the prompt render caps at
    _SCRATCHPAD_PROMPT_ENTRIES lines / _SCRATCHPAD_PROMPT_CHARS."""
    from dast.ai.copilot.session import (
        _SCRATCHPAD_MAX_ENTRIES,
        _SCRATCHPAD_PROMPT_CHARS,
        _SCRATCHPAD_PROMPT_ENTRIES,
    )

    session = CopilotSession("s-cap")
    for i in range(_SCRATCHPAD_MAX_ENTRIES + 30):
        session._note_step("send_request", {"url": f"https://h.test/p{i}"}, {"status": 200})
    assert len(session._scratchpad) == _SCRATCHPAD_MAX_ENTRIES
    assert session._scratchpad[0]["line"].endswith("/p30 -> 200")  # oldest trimmed

    block = session._render_scratchpad()
    assert len(block) <= _SCRATCHPAD_PROMPT_CHARS
    assert block.count("\n") + 1 == _SCRATCHPAD_PROMPT_ENTRIES
    assert "/p149 -> 200" in block  # the most recent step is in view


@pytest.mark.asyncio
async def test_progress_ledger_reaches_the_step_prompt():
    """After a tool call, the NEXT step decision carries the progress-ledger
    section — the cross-turn memory the per-turn transcript lacks."""
    session = CopilotSession("s-ledger")
    _, on_event = _collector()
    run_tool = AsyncMock(return_value={"ok": True, "status": 403,
                                       "url": "https://in.scope/admin"})
    prompts: List[str] = []
    steps = [
        {"action": "call_tool", "thought": "probe admin", "tool_name": "send_request",
         "tool_args": {"url": "https://in.scope/admin", "method": "GET"}},
        {"action": "reply", "thought": "done", "message": "403 on /admin."},
    ]

    async def fake_step(system, user, model_override=None):
        prompts.append(user)
        return steps.pop(0)

    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step", new=AsyncMock(side_effect=fake_step)):
        await session.send("check admin", _FakeCtx(in_scope=True),
                           on_event=on_event, wait_for_human=_deny_human())

    assert "Progress ledger" in prompts[-1]
    assert "GET /admin -> 403" in prompts[-1]
    # The turn BEFORE any tool call has no ledger section at all.
    assert "Progress ledger" not in prompts[0]


@pytest.mark.asyncio
async def test_wrapup_persists_scratchpad_note_once():
    """A forced ending writes the scratchpad tail into app_knowledge for the
    focus host; a second pass must NOT re-write the same entries."""
    session = CopilotSession("s-salvage", focus_hosts=["target.test"])
    session._note_step("send_request", {"url": "https://target.test/a"}, {"status": 403})
    session._note_step("send_request", {"url": "https://target.test/b"},
                       {"status": 200})
    ctx = _FakeCtx(in_scope=True)
    notes: List[tuple] = []

    def fake_append(host, note):
        notes.append((host, note))
        return host

    with patch("dast.app_knowledge.store.append_note", side_effect=fake_append):
        session._persist_scratchpad_knowledge(ctx)
        session._persist_scratchpad_knowledge(ctx)  # idempotent on the same tail

    assert len(notes) == 1
    host, note = notes[0]
    assert host == "target.test"
    assert "copilot navigation (2 steps)" in note
    assert "GET /a -> 403" in note and "GET /b -> 200" in note


@pytest.mark.asyncio
async def test_wrapup_salvage_falls_back_to_sole_approved_host():
    """No focus hosts → the single approved host receives the note; several
    approved hosts → nothing is written (ambiguous)."""
    session = CopilotSession("s-salvage2")
    session._note_step("send_request", {"url": "https://x.test/p"}, {"status": 200})
    notes: List[str] = []

    def fake_append(host, note):
        notes.append(host)
        return host

    with patch("dast.app_knowledge.store.append_note", side_effect=fake_append):
        session._persist_scratchpad_knowledge(_FakeCtx(in_scope=True))
        assert notes == []  # empty approved set → nothing written

        ctx = _FakeCtx(in_scope=True)
        ctx.approved_hosts = {"x.test"}
        session._persist_scratchpad_knowledge(ctx)
        assert notes == ["x.test"]

"""
Unit tests for dast/ai/triage_agent.py — the agentic reproduction loop.

The LLM and the tool layer are both mocked (the SSRF loopback guard means there is
no live target), so these lock in the loop's control flow, not any network call:
  - call tools then finish; a confirmed verdict must survive the independent
    second-pass gate (and is downgraded to needs_manual when it disagrees),
  - the step ceiling and the anti-repeat guard,
  - each of the three human-in-the-loop pauses (approve / auth / question) and how
    an approved host relaxes scope for the rest of the run.
"""

from __future__ import annotations

from urllib.parse import urlparse

import pytest

from dast.ai import bedrock_client, triage_agent
from dast.ai.schemas import H1_VERDICT_SCHEMA
from dast.hackerone.parser import H1Report


class _FakeCtx:
    def __init__(self, in_scope: bool = True):
        self._in_scope = in_scope
        self.approved_hosts: set = set()

    def is_in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if host in self.approved_hosts:
            return True
        return self._in_scope


def _report() -> H1Report:
    return H1Report(
        vuln_type="idor", proof_url="https://target.example/v3/summary?crId=abc",
        payload="token=BOGUS", target_url="https://target.example/v3/summary",
        http_method="GET", raw_text="IDOR: token not validated on crId lookup.",
    )


def _install_llm(monkeypatch, steps, verdict=None):
    """Patch bedrock_client.invoke_json to script step decisions + second pass."""
    state = {"i": 0}
    default_verdict = {"reproduced": False, "confidence": 0.0, "severity": "info",
                       "exploit_scenario": "", "reasoning": "no evidence"}

    def fake(*, system, user, model_id=None, max_tokens=2048, temperature=None,
             schema=None, cache_system=False):
        if schema is H1_VERDICT_SCHEMA:
            return verdict or default_verdict
        i = state["i"]
        state["i"] += 1
        if callable(steps):
            return steps(i)
        if i < len(steps):
            return steps[i]
        return {"thought": "done", "action": "finish", "verdict": "needs_manual"}

    monkeypatch.setattr(bedrock_client, "invoke_json", fake)
    monkeypatch.setattr(bedrock_client, "get_fast_model", lambda: "fast")
    monkeypatch.setattr(bedrock_client, "get_validation_model", lambda: "validation")


def _install_tools(monkeypatch, results=None):
    """Patch dast.tools.run_tool; record calls; return scripted or default results."""
    import dast.tools as tools

    calls: list = []
    queue = list(results or [])

    async def fake_run_tool(ctx, name, args):
        calls.append({"name": name, "args": args})
        if queue:
            return queue.pop(0)
        return {"ok": True, "status": 200, "body": "response body",
                "final_url": args.get("url", "https://target.example/")}

    monkeypatch.setattr(tools, "run_tool", fake_run_tool)
    return calls


async def _noop_event(payload):
    pass


async def _deny_human(kind, payload):
    return {"approve": {"decision": "deny"}, "auth": {"cookies": {}},
            "question": {"text": "(no response)"}}[kind]


async def _run(report, monkeypatch, *, on_event=_noop_event, wait_for_human=_deny_human,
               ctx=None):
    return await triage_agent.run_triage_agent(
        report, report.raw_text, ctx or _FakeCtx(),
        on_event=on_event, wait_for_human=wait_for_human,
    )


# ── confirm / second-pass gate ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_two_calls_then_confirmed_second_pass_agrees(monkeypatch):
    steps = [
        {"thought": "probe a", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://target.example/a"}},
        {"thought": "probe b", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://target.example/b"}},
        {"thought": "confirmed", "action": "finish", "verdict": "confirmed",
         "severity": "medium", "evidence": "token ignored", "reasoning": "crId alone"},
    ]
    _install_llm(monkeypatch, steps,
                 verdict={"reproduced": True, "confidence": 0.9, "severity": "medium",
                          "exploit_scenario": "read any record", "reasoning": "agree"})
    calls = _install_tools(monkeypatch)

    verdict = await _run(_report(), monkeypatch)

    assert verdict.status == "confirmed"
    assert verdict.severity == "medium"
    assert len([c for c in calls if c["name"] == "send_request"]) == 2


@pytest.mark.asyncio
async def test_confirmed_downgraded_when_second_pass_rejects(monkeypatch):
    steps = [
        {"thought": "probe", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://target.example/a"}},
        {"thought": "confirmed", "action": "finish", "verdict": "confirmed",
         "severity": "high", "evidence": "looks bad", "reasoning": "hunch"},
    ]
    _install_llm(monkeypatch, steps,
                 verdict={"reproduced": False, "confidence": 0.2, "severity": "info",
                          "exploit_scenario": "", "reasoning": "no real evidence"})
    _install_tools(monkeypatch)

    verdict = await _run(_report(), monkeypatch)

    assert verdict.status == "needs_manual"      # independent gate refused it
    assert verdict.severity == ""


# ── ceiling / anti-repeat ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_step_ceiling_returns_needs_manual(monkeypatch):
    # Never finish — always issue a fresh (non-repeating) tool call.
    def step(i):
        return {"thought": "loop", "action": "call_tool", "tool_name": "send_request",
                "tool_args": {"url": f"https://target.example/{i}"}}

    _install_llm(monkeypatch, step)
    calls = _install_tools(monkeypatch)

    verdict = await _run(_report(), monkeypatch)

    assert verdict.status == "needs_manual"
    assert len(calls) == triage_agent._AGENT_STEP_CEILING


@pytest.mark.asyncio
async def test_identical_call_is_suppressed(monkeypatch):
    steps = [
        {"thought": "probe", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://target.example/a"}},
        {"thought": "same again", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://target.example/a"}},
        {"thought": "give up", "action": "finish", "verdict": "not_confirmed",
         "evidence": "no signal", "reasoning": "nothing"},
    ]
    _install_llm(monkeypatch, steps)
    calls = _install_tools(monkeypatch)

    verdict = await _run(_report(), monkeypatch)

    assert verdict.status == "not_confirmed"
    assert len(calls) == 1                        # the duplicate never dispatched


@pytest.mark.asyncio
async def test_unknown_tool_does_not_dispatch(monkeypatch):
    steps = [
        {"thought": "bad tool", "action": "call_tool", "tool_name": "nope",
         "tool_args": {}},
        {"thought": "done", "action": "finish", "verdict": "not_confirmed",
         "evidence": "n/a", "reasoning": "n/a"},
    ]
    _install_llm(monkeypatch, steps)
    calls = _install_tools(monkeypatch)

    verdict = await _run(_report(), monkeypatch)
    assert verdict.status == "not_confirmed"
    assert calls == []


# ── pauses ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_out_of_scope_triggers_approve_allow_once(monkeypatch):
    steps = [
        {"thought": "probe", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://out.example/x"}},
        {"thought": "done", "action": "finish", "verdict": "not_confirmed",
         "evidence": "n/a", "reasoning": "n/a"},
    ]
    _install_llm(monkeypatch, steps)
    calls = _install_tools(monkeypatch)

    seen = []

    async def human(kind, payload):
        seen.append((kind, payload.get("host")))
        return {"decision": "allow_once"}

    await _run(_report(), monkeypatch, wait_for_human=human,
               ctx=_FakeCtx(in_scope=False))

    assert ("approve", "out.example") in seen
    assert len(calls) == 1                        # dispatched after approval


@pytest.mark.asyncio
async def test_out_of_scope_denied_does_not_dispatch(monkeypatch):
    steps = [
        {"thought": "probe", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://out.example/x"}},
        {"thought": "done", "action": "finish", "verdict": "not_confirmed",
         "evidence": "n/a", "reasoning": "n/a"},
    ]
    _install_llm(monkeypatch, steps)
    calls = _install_tools(monkeypatch)

    await _run(_report(), monkeypatch, wait_for_human=_deny_human,
               ctx=_FakeCtx(in_scope=False))
    assert calls == []                            # denied, never sent


@pytest.mark.asyncio
async def test_always_host_relaxes_scope_for_rest_of_run(monkeypatch):
    steps = [
        {"thought": "probe a", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://out.example/a"}},
        {"thought": "probe b", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://out.example/b"}},
        {"thought": "done", "action": "finish", "verdict": "not_confirmed",
         "evidence": "n/a", "reasoning": "n/a"},
    ]
    _install_llm(monkeypatch, steps)
    calls = _install_tools(monkeypatch)

    approve_count = {"n": 0}

    async def human(kind, payload):
        if kind == "approve":
            approve_count["n"] += 1
        return {"decision": "always_host"}

    await _run(_report(), monkeypatch, wait_for_human=human,
               ctx=_FakeCtx(in_scope=False))

    assert approve_count["n"] == 1                # second call to same host not paused
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_auth_wall_pause_applies_session_cookie(monkeypatch):
    steps = [
        {"thought": "probe", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://target.example/x"}},
        {"thought": "retry with session", "action": "call_tool", "tool_name": "send_request",
         "tool_args": {"url": "https://target.example/x"}},
        {"thought": "done", "action": "finish", "verdict": "not_confirmed",
         "evidence": "n/a", "reasoning": "n/a"},
    ]
    _install_llm(monkeypatch, steps)
    calls = _install_tools(monkeypatch, results=[
        {"ok": True, "status": 401, "body": "please log in",
         "final_url": "https://target.example/x"},
        {"ok": True, "status": 200, "body": "authenticated content",
         "final_url": "https://target.example/x"},
    ])

    seen = []

    async def human(kind, payload):
        seen.append(kind)
        if kind == "auth":
            return {"cookies": {"session": "abc"}}
        return {"text": "(no response)"}

    await _run(_report(), monkeypatch, wait_for_human=human)

    assert "auth" in seen
    # The re-attempt carried the operator-supplied session cookie.
    assert len(calls) == 2
    assert "session=abc" in calls[1]["args"].get("headers", {}).get("Cookie", "")


@pytest.mark.asyncio
async def test_ask_human_question_answer_reaches_transcript(monkeypatch):
    steps = [
        {"thought": "need an id", "action": "ask_human", "question": "which crId?"},
        {"thought": "done", "action": "finish", "verdict": "not_confirmed",
         "evidence": "n/a", "reasoning": "n/a"},
    ]
    _install_llm(monkeypatch, steps)
    _install_tools(monkeypatch)

    seen = []

    async def human(kind, payload):
        seen.append(kind)
        return {"text": "crId=42"}

    verdict = await _run(_report(), monkeypatch, wait_for_human=human)

    assert "question" in seen
    ask_step = next(s for s in verdict.transcript if s["action"] == "ask_human")
    assert "crId=42" in ask_step["observation"]

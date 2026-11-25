"""Unit tests for the AttackSubagent (5-C-1) — the XBOW-style escalation loop.

The LLM (invoke_json) and the tool layer (run_tool) are both fake: a scripted
step sequence plays the subagent, and a recording fake registry answers the
tool calls. Focus: the deterministic close-outs (record_finding -> confirmed,
record_coverage ruled_out -> ruled_out), the budget/no-progress watchdogs, the
restricted menu, and the escalatability gate.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from dast.ai import attack_subagent
from dast.ai.attack_subagent import (
    ESCALATABLE_ATTACK_TYPES,
    AttackSubagent,
    is_escalatable,
)


def _candidate(attack_type="sqli"):
    return {
        "title": "SQLi candidate", "severity": "high", "attack_type": attack_type,
        "url": "https://shop.test/items?q=1", "parameter": "q",
        "payload": "' OR '1'='1", "evidence": "odd response lengths",
    }


class _FakeTool:
    def __init__(self, name, result):
        self.name = name
        self.description = f"{name} fake"
        self.input_schema = {"type": "object"}
        self.result = result
        self.calls = []


@pytest.fixture
def fake_tools(monkeypatch):
    """Registry double: recording fakes for every allowed tool name."""
    tools = {
        name: _FakeTool(name, {"ok": True, "fake": name})
        for name in [
            "send_request", "test_unauth", "diff_responses", "extract_response",
            "verify_reflection", "oob_generate", "oob_poll", "sqli_probe",
            "xss_probe", "idor_probe", "authz_differential_probe",
            "prototype_pollution_probe", "web_cache_deception_probe",
            "record_finding", "record_coverage",
        ]
    }

    async def fake_run_tool(ctx, name, args):
        tool = tools.get(name)
        if tool is None:
            return {"ok": False, "error": f"unknown tool: {name}"}
        tool.calls.append(args)
        return tool.result

    monkeypatch.setattr("dast.tools.base.run_tool", fake_run_tool)
    return tools


def _ctx():
    return SimpleNamespace(store=None, is_in_scope=lambda url: True,
                           proxy_url="http://127.0.0.1:8080",
                           dashboard_base_url="http://127.0.0.1:8088",
                           read_only=False)


def _script_llm(monkeypatch, steps):
    """invoke_json double returning the scripted steps in order."""
    calls = {"n": 0}

    async def fake_invoke_json(**kwargs):
        index = calls["n"]
        calls["n"] += 1
        if index < len(steps):
            return steps[index]
        return {"thought": "out of script", "action": "conclude",
                "conclusion": {"verdict": "cannot_confirm", "reasoning": "script ended"}}

    monkeypatch.setattr(attack_subagent.bedrock_client, "invoke_json", fake_invoke_json)
    return calls


def test_escalatable_gate():
    assert is_escalatable(_candidate("sqli")) is True
    assert is_escalatable(_candidate("sensitive_data")) is False
    assert is_escalatable({}) is False
    assert "sensitive_data" not in ESCALATABLE_ATTACK_TYPES


def test_menu_is_restricted_per_class(fake_tools):
    sub = AttackSubagent(_ctx(), _candidate("sqli"))
    names = [d["name"] for d in sub._tool_defs()]
    assert "send_request" in names and "sqli_probe" in names
    assert "xss_probe" not in names and "crawl" not in names and "browser_login" not in names

    xss_names = [d["name"] for d in AttackSubagent(_ctx(), _candidate("xss"))._tool_defs()]
    assert "xss_probe" in xss_names and "sqli_probe" not in xss_names


def test_record_finding_closes_confirmed(fake_tools, monkeypatch):
    _script_llm(monkeypatch, [
        {"thought": "probe it", "action": "call_tool", "tool_name": "sqli_probe",
         "tool_args": {"url": "https://shop.test/items"}},
        {"thought": "proved — record", "action": "call_tool",
         "tool_name": "record_finding",
         "tool_args": {"title": "SQLi", "severity": "high", "url": "https://shop.test/items",
                       "evidence": "probe oracle"}},
    ])
    out = asyncio.run(AttackSubagent(_ctx(), _candidate()).run())
    assert out["verdict"] == "confirmed"
    assert fake_tools["record_finding"].calls  # the probe + the record both ran
    assert fake_tools["sqli_probe"].calls


def test_record_coverage_ruled_out_closes_ruled_out(fake_tools, monkeypatch):
    _script_llm(monkeypatch, [
        {"thought": "probe", "action": "call_tool", "tool_name": "sqli_probe",
         "tool_args": {"url": "https://shop.test/items"}},
        {"thought": "refuted — close it", "action": "call_tool",
         "tool_name": "record_coverage",
         "tool_args": {"url": "https://shop.test/items", "risk_area": "sqli",
                       "outcome": "ruled_out", "reason": "oracle clean"}},
    ])
    out = asyncio.run(AttackSubagent(_ctx(), _candidate()).run())
    assert out["verdict"] == "ruled_out"


def test_no_progress_watchdog_stops_repeats(fake_tools, monkeypatch):
    """The same call proposed 3 times in a row is killed after the cap."""
    repeat = {"thought": "again", "action": "call_tool", "tool_name": "sqli_probe",
              "tool_args": {"url": "https://shop.test/items"}}
    _script_llm(monkeypatch, [repeat, dict(repeat), dict(repeat)])
    out = asyncio.run(AttackSubagent(_ctx(), _candidate()).run())
    assert out["verdict"] == "cannot_confirm"
    assert "no-progress" in out["reasoning"]
    assert len(fake_tools["sqli_probe"].calls) == 2  # cap: first + one repeat


def test_tool_budget_is_hard(fake_tools, monkeypatch):
    """More than MAX_TOOL_CALLS scripted call steps cannot exceed the budget."""
    step = {"thought": "keep probing", "action": "call_tool",
            "tool_name": "send_request",
            "tool_args": {"url": "https://shop.test/x", "method": "GET"}}
    _script_llm(monkeypatch, [dict(step, tool_args={"url": f"https://shop.test/{i}"})
                              for i in range(20)])
    out = asyncio.run(AttackSubagent(_ctx(), _candidate()).run())
    assert out["tool_calls"] <= attack_subagent.MAX_TOOL_CALLS
    assert out["verdict"] == "cannot_confirm"  # never concluded, budget honest


def test_unavailable_tool_counts_toward_failure_breaker(fake_tools, monkeypatch):
    """Proposing a tool outside the menu is a failure, not a call."""
    bad = {"thought": "crawl it", "action": "call_tool", "tool_name": "crawl",
           "tool_args": {"url": "https://shop.test/"}}
    _script_llm(monkeypatch, [dict(bad), dict(bad), dict(bad)])
    out = asyncio.run(AttackSubagent(_ctx(), _candidate()).run())
    assert out["verdict"] == "cannot_confirm"
    assert "unavailable tools" in out["reasoning"]
    assert out["tool_calls"] == 0


def test_conclude_directly_is_honored(fake_tools, monkeypatch):
    _script_llm(monkeypatch, [
        {"thought": "nothing to probe", "action": "conclude",
         "conclusion": {"verdict": "cannot_confirm",
                        "reasoning": "needs an authenticated session"}},
    ])
    out = asyncio.run(AttackSubagent(_ctx(), _candidate()).run())
    assert out["verdict"] == "cannot_confirm"
    assert "authenticated session" in out["reasoning"]
    assert out["tool_calls"] == 0


def test_attack_finding_tool_registered(fake_tools):
    import dast.tools  # noqa: F401
    from dast.tools.base import get_tool
    tool = get_tool("attack_finding")
    assert tool is not None
    assert "SUBAGENT" in tool.description.upper()

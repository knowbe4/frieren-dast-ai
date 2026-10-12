"""Unit tests for the race condition agent.

Locks in: non-state-changing endpoints are skipped, the LLM gate decides
race-worthiness (keyword fallback when the LLM is unavailable), the double-spend
signature (single-use op applied by >=2 concurrent successes) confirms with
bypass_validation=True, ambiguous divergence needs an LLM verdict, and 429s are
reported as observations instead of findings.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from dast.agents import race_condition_agent as rc


def _resp(status=200, body='{"status":"ok"}'):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.request = MagicMock()
    r.request.method = "POST"
    r.request.url = "https://in.scope/redeem"
    r.request.headers = {}
    r.request.content = b""
    return r


def _target(method="POST", params=None, body="coupon=SUMMER2024"):
    t = MagicMock()
    t.method = method
    t.url = "https://in.scope/redeem"
    t.path = "/redeem"
    t.headers = {"content-type": "application/json"}
    t.body = body
    t.params = params if params is not None else [{"name": "coupon", "value": "SUMMER2024", "location": "query"}]
    return t


def _run(agent, target, client=MagicMock()):
    return asyncio.run(agent.run(target, client))


def test_get_skipped():
    agent = rc.RaceConditionAgent()
    send = AsyncMock()
    with patch.object(rc, "_send", new=send):
        assert _run(agent, _target(method="GET")) == []
    assert send.call_count == 0


def test_failing_baseline_skipped():
    agent = rc.RaceConditionAgent()
    with patch.object(rc, "_send", new=AsyncMock(return_value=_resp(status=403))):
        assert _run(agent, _target()) == []


def test_llm_gate_rejects():
    agent = rc.RaceConditionAgent()
    gate = AsyncMock(return_value={"worth_racing": False, "single_use": False, "reason": "read-only"})
    with patch.object(rc, "_send", new=AsyncMock(return_value=_resp())), \
         patch.object(rc, "_llm_gate", new=gate):
        assert _run(agent, _target()) == []
    gate.assert_awaited_once()


def test_double_spend_confirmed_deterministically():
    agent = rc.RaceConditionAgent()
    gate = AsyncMock(return_value={"worth_racing": True, "single_use": True, "reason": "coupon redemption"})
    # Baseline + burst of identical successes.
    with patch.object(rc, "_send", new=AsyncMock(return_value=_resp())), \
         patch.object(rc, "_llm_gate", new=gate):
        findings = _run(agent, _target())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe == "CWE-362"
    assert finding.severity == "high"
    assert finding.bypass_validation is True


def test_all_failures_no_finding():
    agent = rc.RaceConditionAgent()
    gate = AsyncMock(return_value={"worth_racing": True, "single_use": True, "reason": "r"})
    used = _resp(status=200, body='{"error":"already been used"}')
    with patch.object(rc, "_send", new=AsyncMock(return_value=used)), \
         patch.object(rc, "_llm_gate", new=gate):
        # Baseline itself contains a failure word -> early return before the gate.
        assert _run(agent, _target()) == []


def test_divergence_needs_llm_verdict():
    agent = rc.RaceConditionAgent()
    gate = AsyncMock(return_value={"worth_racing": True, "single_use": False, "reason": "queue op"})
    responses = [
        _resp(body='{"status":"processed"}'),
        _resp(status=409, body='{"error":"duplicate"}'),
        _resp(body='{"status":"processed"}'),
        _resp(body='{"status":"processed"}'),
        _resp(body='{"status":"processed"}'),
        _resp(body='{"status":"processed"}'),
    ]
    verdict = AsyncMock(return_value={"confirmed": True, "confidence": 0.8, "reasoning": "applied twice"})
    with patch.object(rc, "_send", new=AsyncMock(side_effect=responses)), \
         patch.object(rc, "_llm_gate", new=gate), \
         patch.object(rc, "_llm_verdict", new=verdict):
        findings = _run(agent, _target())
    assert len(findings) == 1
    assert findings[0].bypass_validation is False  # red-team validator confirms
    verdict.assert_awaited_once()


def test_divergence_rejected_by_llm():
    agent = rc.RaceConditionAgent()
    gate = AsyncMock(return_value={"worth_racing": True, "single_use": False, "reason": "r"})
    responses = [_resp(body="a"), _resp(status=409, body="b"), _resp(body="a"), _resp(body="a"), _resp(body="a"), _resp(body="a")]
    verdict = AsyncMock(return_value={"confirmed": False, "confidence": 0.2, "reasoning": "interleaving only"})
    with patch.object(rc, "_send", new=AsyncMock(side_effect=responses)), \
         patch.object(rc, "_llm_gate", new=gate), \
         patch.object(rc, "_llm_verdict", new=verdict):
        assert _run(agent, _target()) == []


def test_no_llm_keyword_fallback():
    agent = rc.RaceConditionAgent()
    # LLM unavailable (None) + race-shaped param name -> keyword fallback fires.
    with patch.object(rc, "_send", new=AsyncMock(return_value=_resp())), \
         patch.object(rc, "_llm_gate", new=AsyncMock(return_value=None)):
        findings = _run(agent, _target())
    assert len(findings) == 1


def test_no_llm_and_no_keyword_skipped():
    agent = rc.RaceConditionAgent()
    with patch.object(rc, "_send", new=AsyncMock(return_value=_resp())), \
         patch.object(rc, "_llm_gate", new=AsyncMock(return_value=None)):
        assert _run(agent, _target(params=[{"name": "search", "value": "x", "location": "query"}], body="search=x")) == []


def test_rate_limit_observed_not_reported():
    agent = rc.RaceConditionAgent()
    gate = AsyncMock(return_value={"worth_racing": True, "single_use": True, "reason": "r"})
    responses = [
        _resp(),
        _resp(status=429, body="slow down"),
        _resp(status=429, body="slow down"),
        _resp(status=429, body="slow down"),
        _resp(status=429, body="slow down"),
        _resp(status=429, body="slow down"),
    ]
    with patch.object(rc, "_send", new=AsyncMock(side_effect=responses)), \
         patch.object(rc, "_llm_gate", new=gate):
        assert _run(agent, _target()) == []
    assert any(o.kind == "rate_limit" for o in agent.observations)

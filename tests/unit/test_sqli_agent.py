"""
Unit tests for SqliAgent — error-based and time-based blind SQL injection.

HTTP layer mocked via active_checks._send, following test_idor.py's pattern.
The mutator is patched to return None immediately so tests stay deterministic
and never touch the LLM gateway.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from urllib.parse import unquote

import pytest

from dast.agents.sqli_agent import SqliAgent, _build_error_re
from dast.scanners.active_checks import CheckTarget


def _target(url="https://api.example.com/search?id=1", method="GET", params=None, body=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=body,
        params=params or [{"name": "id", "location": "query", "value": "1"}],
    )


def _resp(status=200, text="", elapsed=None):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


@pytest.fixture(autouse=True)
def _no_mutation(monkeypatch):
    async def _none(*a, **k):
        return None
    monkeypatch.setattr("dast.agents.sqli_agent.next_payload", _none)


# ── positive: error-based ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_error_based_detection():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        if "'" in unquote(url):
            return _resp(500, "You have an error in your SQL syntax near ''1'='1'")
        return _resp(200, '{"ok": true}')

    with patch("dast.agents.sqli_agent._send", side_effect=fake_send):
        findings = await SqliAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "sqli"
    assert findings[0].cwe == "CWE-89"
    assert findings[0].severity == "critical"
    assert "SQL error" in findings[0].evidence


# ── negative: clean response ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return _resp(200, '{"results": []}')

    with patch("dast.agents.sqli_agent._send", side_effect=fake_send):
        findings = await SqliAgent().run(target, MagicMock())

    assert findings == []


# ── time-based blind ────────────────────────────────────────────────────────
# Real (small) delays are used instead of mocking time.monotonic, since the
# exact call count to monotonic() is an implementation detail we shouldn't
# have to track — a fast baseline vs. an artificially slow probe response is
# enough to exercise the "must be slower than baseline, not just over an
# absolute threshold" logic with a tiny, fast-running threshold.

@pytest.mark.asyncio
async def test_time_based_blind_detected_when_delay_exceeds_baseline_plus_threshold():
    import asyncio
    target = _target()

    async def fake_send(client, method, url, headers, body):
        if "SLEEP" in unquote(url) or "WAITFOR" in unquote(url) or "pg_sleep" in unquote(url):
            await asyncio.sleep(0.08)
        return _resp(200, "ok")

    with patch("dast.agents.sqli_agent._send", side_effect=fake_send):
        finding = await SqliAgent()._probe_time_based(
            target, MagicMock(), target.params[0], threshold_ms=50,
        )

    assert finding is not None
    assert finding.title == "SQL Injection (Time-Based Blind)"
    assert finding.attack_type == "sqli"


@pytest.mark.asyncio
async def test_time_based_blind_not_detected_within_baseline():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return _resp(200, "ok")

    with patch("dast.agents.sqli_agent._send", side_effect=fake_send):
        finding = await SqliAgent()._probe_time_based(
            target, MagicMock(), target.params[0], threshold_ms=4500,
        )

    assert finding is None


# ── WAF block then bypass via mutator ───────────────────────────────────────

@pytest.mark.asyncio
async def test_waf_block_then_bypass_records_waf_bypass(monkeypatch):
    from dast.ai.mutator import MutationResult

    target = _target(params=[{"name": "id", "location": "query", "value": "1"}])
    responses = iter([
        _resp(200, "ok"),                      # baseline
        _resp(403, "Request blocked by WAF"),  # last seed payload -> triggers mutation
        _resp(500, "SQL syntax error near 'bypass'"),  # mutated payload succeeds
    ])

    async def fake_send(client, method, url, headers, body):
        return next(responses)

    call_state = {"n": 0}
    async def fake_next_payload(*a, **k):
        call_state["n"] += 1
        if call_state["n"] == 1:
            return MutationResult(action="mutate", payload="bypass", rationale="WAF blocked quote")
        return None

    monkeypatch.setattr("dast.agents.sqli_agent.next_payload", fake_next_payload)
    monkeypatch.setattr("dast.agents.sqli_agent.get_filtered_payloads", lambda *a, **k: ["'"])

    agent = SqliAgent()
    observed = []
    agent.observe = lambda *a, **kw: observed.append((a, kw))

    with patch("dast.agents.sqli_agent._send", side_effect=fake_send):
        finding = await agent._probe_error_based(
            target, MagicMock(), target.params[0], _build_error_re(),
        )

    assert finding is not None
    assert any(a and a[0] == "waf_bypass" for a, _ in observed)


# ── body location injection ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_body_location_injection_detects_error():
    import json
    target = _target(
        url="https://api.example.com/account",
        method="POST",
        body=json.dumps({"accountId": "1"}),
        params=[{"name": "accountId", "location": "body", "value": "1"}],
    )

    async def fake_send(client, method, url, headers, body):
        if body and "'" in body:
            return _resp(500, "SQL syntax error near 'accountId'")
        return _resp(200, '{"ok": true}')

    with patch("dast.agents.sqli_agent._send", side_effect=fake_send):
        findings = await SqliAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].parameter == "accountId"

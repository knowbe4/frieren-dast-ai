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


# ── an error-based hit skips slow time-based probing of other params ────────

@pytest.mark.asyncio
async def test_error_based_hit_skips_time_based_on_other_params(monkeypatch):
    """Once error-based confirms injection on any parameter, the (slow) blind
    time-based probes must not run — a single confirmed injection proves the
    endpoint vulnerable, and leaving time-based sleeps running risks blowing the
    per-endpoint budget and forfeiting the finding already in hand. Regression
    for DVWA sqli timing out (kept_findings=0) despite an instant error-based
    hit on 'id'."""
    target = _target(params=[
        {"name": "id", "location": "query", "value": "1"},
        {"name": "Submit", "location": "query", "value": "Submit"},
    ])

    async def fake_send(client, method, url, headers, body):
        # 'id' injection triggers a SQL error; everything else is clean.
        if "id=1'" in unquote(url) or "id='" in unquote(url):
            return _resp(500, "You have an error in your SQL syntax near ''1'")
        return _resp(200, '{"ok": true}')

    time_based = MagicMock()
    with patch("dast.agents.sqli_agent._send", side_effect=fake_send), \
         patch.object(SqliAgent, "_probe_time_based", new=time_based):
        findings = await SqliAgent().run(target, MagicMock())

    assert len(findings) >= 1
    assert all(f.attack_type == "sqli" for f in findings)
    time_based.assert_not_called()


@pytest.mark.asyncio
async def test_error_based_short_circuits_after_first_param_confirms():
    """Once error-based confirms on the first parameter, the agent must RETURN
    immediately and NOT probe the remaining parameters. Probing a non-injectable
    param exhausts its seeds and drives the (slow) LLM mutator, delaying the
    agent's return past the coordinator's per-endpoint budget and forfeiting the
    finding it already has. Regression for DVWA sqli timing out to "safe" despite
    an instant error-based hit on the first param."""
    target = _target(params=[
        {"name": "id", "location": "query", "value": "1"},
        {"name": "Submit", "location": "query", "value": "Submit"},
    ])

    async def fake_send(client, method, url, headers, body):
        if "id=1'" in unquote(url) or "id='" in unquote(url):
            return _resp(500, "You have an error in your SQL syntax near ''1'")
        return _resp(200, '{"ok": true}')

    agent = SqliAgent()
    probed_params: list = []
    real_probe = SqliAgent._probe_error_based

    async def counting_error_probe(target, client, param, error_re, tech_context=None):
        probed_params.append(param["name"])
        return await real_probe(agent, target, client, param, error_re, tech_context)

    with patch("dast.agents.sqli_agent._send", side_effect=fake_send), \
         patch.object(agent, "_probe_error_based", side_effect=counting_error_probe):
        findings = await agent.run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].parameter == "id"
    # Only the first parameter must have been probed — no grind on 'Submit'.
    assert probed_params == ["id"]


# ── error-based mutator must NOT grind without a WAF block ──────────────────

@pytest.mark.asyncio
async def test_error_based_does_not_mutate_without_block(monkeypatch):
    """On an endpoint with no WAF block, the error-based phase must exhaust its
    seed payloads and STOP without ever calling the LLM mutator. The mutator is a
    WAF-bypass tool; invoking it when nothing was blocked burns the per-endpoint
    budget and starves the time-based blind probe that follows. Regression for
    DVWA sqli_blind timing out to "safe": the error-based mutator ground on 'id'
    (a 404 differential is NOT a block) and the SLEEP probes never ran."""
    target = _target(params=[{"name": "id", "location": "query", "value": "1"}])

    async def fake_send(client, method, url, headers, body):
        # Injecting into 'id' returns a 404 (a differential, but NOT a WAF block);
        # baseline is a clean 200. No SQL error signature anywhere.
        if "id=1" not in unquote(url):
            return _resp(404, "Not Found")
        return _resp(200, '{"ok": true}')

    mutator_calls = {"n": 0}
    async def counting_next_payload(*a, **k):
        mutator_calls["n"] += 1
        return None
    monkeypatch.setattr("dast.agents.sqli_agent.next_payload", counting_next_payload)

    agent = SqliAgent()
    # Time-based must still get to run (it is the only detector for blind SQLi).
    async def fake_time_based(*a, **k):
        return None
    with patch("dast.agents.sqli_agent._send", side_effect=fake_send), \
         patch.object(agent, "_probe_time_based", side_effect=fake_time_based) as tb:
        findings = await agent.run(target, MagicMock())

    assert findings == []
    # The mutator must never have been called — no block was observed.
    assert mutator_calls["n"] == 0
    # And control must have reached the time-based blind fallback.
    assert tb.called


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

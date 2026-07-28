"""
Unit tests for NosqlAgent — MongoDB operator injection and $where injection.

Deterministic agent, no mutator involvement. HTTP layer mocked via
dast.agents.nosql_agent._send.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from dast.agents.nosql_agent import NosqlAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/api/login", method="POST", params=None, body=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=body if body is not None else json.dumps({"username": "admin"}),
        params=params or [{"name": "username", "location": "body", "value": "admin"}],
    )


def _resp(status=200, text=""):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


# ── positive: error disclosure ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nosql_error_disclosure_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        if body and "$gt" in body:
            return _resp(500, "MongoError: unknown operator")
        return _resp(200, '{"data": []}')

    with patch("dast.agents.nosql_agent._send", side_effect=fake_send):
        findings = await NosqlAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "nosql"
    assert findings[0].cwe == "CWE-943"
    assert "Error Disclosure" in findings[0].title


# ── positive: filter bypass via response count diff ─────────────────────────

@pytest.mark.asyncio
async def test_filter_bypass_via_response_count_diff(monkeypatch):
    monkeypatch.setattr(
        "dast.agents.nosql_agent.get_payloads",
        lambda category, group: (['{"$gt": ""}'] if group == "mongodb_operator" else []),
    )
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        if body and "$gt" in body:
            return _resp(200, json.dumps({"data": [{"id": 1}, {"id": 2}, {"id": 3}]}))
        return _resp(200, json.dumps({"data": [{"id": 1}]}))

    with patch("dast.agents.nosql_agent._send", side_effect=fake_send):
        findings = await NosqlAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert "Filter Bypass" in findings[0].title
    assert findings[0].bypass_validation is True


# ── negative: clean response ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(200, json.dumps({"data": [{"id": 1}]}))

    with patch("dast.agents.nosql_agent._send", side_effect=fake_send):
        findings = await NosqlAgent().run(target, MagicMock())

    assert findings == []


# ── query-string operator injection ([$gt]= notation) ───────────────────────

@pytest.mark.asyncio
async def test_query_operator_injection_detects_error(monkeypatch):
    target = _target(
        url="https://example.com/api/search?q=admin",
        method="GET",
        body=None,
        params=[{"name": "q", "location": "query", "value": "admin"}],
    )
    monkeypatch.setattr(
        "dast.agents.nosql_agent.get_payloads",
        lambda category, group: (['[$gt]='] if group == "mongodb_operator" else []),
    )

    async def fake_send(client, method, url, headers, body, payload=None):
        if "%5B%24gt%5D" in url or "[$gt]" in url:
            return _resp(500, "MongoError: Cast to Number failed")
        return _resp(200, json.dumps({"data": []}))

    with patch("dast.agents.nosql_agent._send", side_effect=fake_send):
        findings = await NosqlAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].parameter == "q"

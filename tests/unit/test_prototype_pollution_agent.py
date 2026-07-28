"""
Unit tests for PrototypePollutionAgent — __proto__ / constructor.prototype injection.

Deterministic agent, no mutator involvement. HTTP layer mocked via
dast.agents.prototype_pollution_agent._send.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from dast.agents.prototype_pollution_agent import PrototypePollutionAgent, _MARKER
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/api/config?theme=dark", method="GET", params=None, body=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=body,
        params=params or [{"name": "theme", "location": "query", "value": "dark"}],
    )


def _resp(status=200, text=""):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


# ── positive: marker reflected via query string ─────────────────────────────

@pytest.mark.asyncio
async def test_marker_reflected_via_query_string():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        if "__proto__" in url:
            return _resp(200, json.dumps({"polluted": _MARKER}))
        return _resp(200, json.dumps({"theme": "dark"}))

    with patch("dast.agents.prototype_pollution_agent._send", side_effect=fake_send):
        findings = await PrototypePollutionAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "prototype_pollution"
    assert findings[0].cwe == "CWE-1321"
    assert "Property Injected" in findings[0].title


# ── positive: pollution persists on a subsequent clean GET ─────────────────

@pytest.mark.asyncio
async def test_persistent_pollution_detected_on_clean_get():
    target = _target()
    # Call sequence: 1=baseline, 2-4=the three query-string probes, 5=the
    # clean re-fetch (no query string at all) that checks for persistence.
    calls = {"n": 0}

    async def fake_send(client, method, url, headers, body, payload=None):
        calls["n"] += 1
        if calls["n"] == 5:
            return _resp(200, json.dumps({"polluted": _MARKER}))
        return _resp(200, json.dumps({"theme": "dark"}))

    with patch("dast.agents.prototype_pollution_agent._send", side_effect=fake_send):
        findings = await PrototypePollutionAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert "Persistent" in findings[0].title
    assert findings[0].confirmed is True


# ── positive: JSON body pollution ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_json_body_pollution_detected():
    target = _target(
        url="https://example.com/api/update",
        method="POST",
        body=json.dumps({"name": "alice"}),
        params=[{"name": "name", "location": "body", "value": "alice"}],
    )

    async def fake_send(client, method, url, headers, body, payload=None):
        if body and "__proto__" in body:
            return _resp(200, json.dumps({"polluted": _MARKER}))
        return _resp(200, json.dumps({"name": "alice"}))

    with patch("dast.agents.prototype_pollution_agent._send", side_effect=fake_send):
        findings = await PrototypePollutionAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "prototype_pollution"


# ── negative: server processes __proto__ but only echoes error ─────────────

@pytest.mark.asyncio
async def test_server_error_indicates_processing_but_lower_severity():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        if "__proto__" in url:
            return _resp(500, "TypeError: Cannot set property 'polluted' of undefined")
        return _resp(200, json.dumps({"theme": "dark"}))

    with patch("dast.agents.prototype_pollution_agent._send", side_effect=fake_send):
        findings = await PrototypePollutionAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert "Server Processes __proto__" in findings[0].title
    assert findings[0].severity == "medium"


# ── negative: no params, no json body ───────────────────────────────────────

@pytest.mark.asyncio
async def test_no_params_no_json_body_no_op():
    target = CheckTarget(
        method="GET",
        url="https://example.com/health",
        headers={"content-type": "text/plain"},
        body=None,
        params=[],
    )

    findings = await PrototypePollutionAgent().run(target, MagicMock())

    assert findings == []


# ── negative: clean response ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(200, json.dumps({"theme": "dark"}))

    with patch("dast.agents.prototype_pollution_agent._send", side_effect=fake_send):
        findings = await PrototypePollutionAgent().run(target, MagicMock())

    assert findings == []

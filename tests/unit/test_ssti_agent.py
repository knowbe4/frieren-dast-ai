"""
Unit tests for SstiAgent — server-side template injection with engine
fingerprinting. HTTP layer mocked via dast.agents.ssti_agent._send.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dast.agents.ssti_agent import SstiAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/render?name=alice", method="GET", params=None, discovery_context=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "text/html"},
        body=None,
        params=params or [{"name": "name", "location": "query", "value": "alice"}],
        discovery_context=discovery_context,
    )


def _resp(status=200, text=""):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


@pytest.fixture(autouse=True)
def _detection_payloads(monkeypatch):
    monkeypatch.setattr(
        "dast.agents.ssti_agent.get_payloads",
        lambda category, group: (["{{8887*8893}}"] if group == "detection" else []),
    )


# ── positive: arithmetic canary evaluated ───────────────────────────────────

@pytest.mark.asyncio
async def test_arithmetic_canary_evaluated_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        if payload == "{{8887*8893}}":
            return _resp(200, "<p>Result: 79014691</p>")
        return _resp(200, "<p>Hello alice</p>")

    with patch("dast.agents.ssti_agent._send", side_effect=fake_send):
        findings = await SstiAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "ssti"
    assert findings[0].cwe == "CWE-1336"
    assert findings[0].confirmed is True
    assert findings[0].bypass_validation is True


# ── negative: payload echoed, not evaluated ─────────────────────────────────

@pytest.mark.asyncio
async def test_payload_echoed_not_evaluated_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(200, "<p>Hello {{8887*8893}}</p>")

    with patch("dast.agents.ssti_agent._send", side_effect=fake_send):
        findings = await SstiAgent().run(target, MagicMock())

    assert findings == []


# ── negative: clean response ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(200, "<p>Hello alice</p>")

    with patch("dast.agents.ssti_agent._send", side_effect=fake_send):
        findings = await SstiAgent().run(target, MagicMock())

    assert findings == []


# ── positive: template engine error disclosure ──────────────────────────────

@pytest.mark.asyncio
async def test_engine_error_disclosure_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(500, "jinja2.exceptions.UndefinedError: 'x' is undefined")

    with patch("dast.agents.ssti_agent._send", side_effect=fake_send):
        findings = await SstiAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert "Error Disclosure" in findings[0].title
    assert findings[0].severity == "medium"


# ── engine fingerprint from tech stack restricts probes ─────────────────────

@pytest.mark.asyncio
async def test_known_jinja2_engine_skips_non_matching_evasive_canaries(monkeypatch):
    class _FakeDiscoveryContext:
        technologies = ["Flask", "Jinja2"]

    target = _target(discovery_context=_FakeDiscoveryContext())
    seen_payloads = []

    async def fake_send(client, method, url, headers, body, payload=None):
        seen_payloads.append(payload)
        return _resp(200, "<p>Hello alice</p>")

    with patch("dast.agents.ssti_agent._send", side_effect=fake_send):
        await SstiAgent().run(target, MagicMock())

    # Freemarker-only evasive canary must never be sent once jinja2 is known.
    assert "${8887?c?number * 8893}" not in seen_payloads


# ── no injectable params ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_injectable_params_no_op():
    target = _target(params=[{"name": "confirm", "location": "query", "value": "true", "type": "boolean"}])

    findings = await SstiAgent().run(target, MagicMock())

    assert findings == []

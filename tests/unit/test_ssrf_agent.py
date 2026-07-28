"""
Unit tests for SsrfAgent — OOB callback + inline internal-response detection.

HTTP layer mocked via dast.agents.ssrf_agent._send. The collaborator (OOB
listener) is a lightweight fake exposing issue_token/was_hit/host/port, since
the real one binds a real socket. The mutator is patched to return None by
default (bypass scenario overrides this per-test).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dast.agents.ssrf_agent import SsrfAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/fetch?url=http://example.com", method="GET", params=None, body=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=body,
        params=params or [{"name": "url", "location": "query", "value": "http://example.com"}],
    )


def _resp(status=200, text=""):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


class _FakeCollaborator:
    """Fake OOB listener — no real socket. Tracks hit tokens explicitly."""

    def __init__(self, hit_tokens=None):
        self._hit_tokens = set(hit_tokens or [])
        self._issued = 0
        self.host = "127.0.0.1"
        self.port = 9999

    def issue_token(self):
        self._issued += 1
        return f"tok{self._issued}"

    def was_hit(self, token):
        return token in self._hit_tokens


@pytest.fixture(autouse=True)
def _no_mutation(monkeypatch):
    async def _none(*a, **k):
        return None
    monkeypatch.setattr("dast.agents.ssrf_agent.next_payload", _none)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    async def _fast_sleep(*a, **k):
        return None
    monkeypatch.setattr("dast.agents.ssrf_agent.asyncio.sleep", _fast_sleep)


@pytest.fixture(autouse=True)
def _url_param_keywords(monkeypatch):
    monkeypatch.setattr("dast.agents.ssrf_agent.get_value", lambda category, key, *a, **k: (
        ["url", "callback", "webhook"] if key == "url_param_keywords" else None
    ))


# ── no collaborator: agent no-ops ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_collaborator_returns_no_findings():
    target = _target()
    findings = await SsrfAgent().run(target, MagicMock(), collaborator=None)
    assert findings == []


# ── no url-like params: agent no-ops ────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_url_like_params_returns_no_findings():
    target = _target(
        url="https://example.com/search?q=hello",
        params=[{"name": "q", "location": "query", "value": "hello"}],
    )
    collaborator = _FakeCollaborator()

    findings = await SsrfAgent().run(target, MagicMock(), collaborator=collaborator)

    assert findings == []


# ── positive: OOB callback received ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_oob_callback_confirms_ssrf(monkeypatch):
    target = _target()
    # First issued token ("tok1") is the one that gets "hit".
    collaborator = _FakeCollaborator(hit_tokens={"tok1"})
    monkeypatch.setattr(
        "dast.agents.ssrf_agent.get_filtered_payloads",
        lambda *a, **k: ["http://{{COLLAB_HOST}}:{{COLLAB_PORT}}/{{TOKEN}}"],
    )

    async def fake_send(client, method, url, headers, body):
        return _resp(200, "ok")

    with patch("dast.agents.ssrf_agent._send", side_effect=fake_send):
        findings = await SsrfAgent().run(target, MagicMock(), collaborator=collaborator)

    assert len(findings) == 1
    assert findings[0].attack_type == "ssrf"
    assert findings[0].cwe == "CWE-918"
    assert "OOB callback" in findings[0].evidence


# ── positive: inline internal response signature ────────────────────────────

@pytest.mark.asyncio
async def test_internal_response_signature_detected(monkeypatch):
    target = _target()
    collaborator = _FakeCollaborator(hit_tokens=set())  # never hit — force inline path
    monkeypatch.setattr(
        "dast.agents.ssrf_agent.get_filtered_payloads",
        lambda *a, **k: ["http://169.254.169.254/latest/meta-data/"],
    )
    monkeypatch.setattr(
        "dast.agents.ssrf_agent.get_value",
        lambda category, key, *a, **k: (
            ["url", "callback", "webhook"] if key == "url_param_keywords"
            else (["ami-id", "instance-id"] if key == "internal_response_signatures" else None)
        ),
    )

    async def fake_send(client, method, url, headers, body):
        return _resp(200, '{"data": "ami-id: ami-0abcd1234"}')

    with patch("dast.agents.ssrf_agent._send", side_effect=fake_send):
        findings = await SsrfAgent().run(target, MagicMock(), collaborator=collaborator)

    assert len(findings) == 1
    assert "Internal Response Detected" in findings[0].title
    assert findings[0].bypass_validation is False


# ── negative: clean response, no callback ───────────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding(monkeypatch):
    target = _target()
    collaborator = _FakeCollaborator(hit_tokens=set())
    monkeypatch.setattr(
        "dast.agents.ssrf_agent.get_filtered_payloads",
        lambda *a, **k: ["http://{{COLLAB_HOST}}:{{COLLAB_PORT}}/{{TOKEN}}"],
    )

    async def fake_send(client, method, url, headers, body):
        return _resp(200, "ok")

    with patch("dast.agents.ssrf_agent._send", side_effect=fake_send):
        findings = await SsrfAgent().run(target, MagicMock(), collaborator=collaborator)

    assert findings == []


# ── WAF block then bypass via mutator ───────────────────────────────────────

@pytest.mark.asyncio
async def test_waf_block_then_bypass_records_waf_bypass(monkeypatch):
    from dast.ai.mutator import MutationResult

    target = _target()
    collaborator = _FakeCollaborator(hit_tokens={"tok2"})  # 2nd issued token (mutated payload) hits
    monkeypatch.setattr(
        "dast.agents.ssrf_agent.get_filtered_payloads",
        lambda *a, **k: ["http://{{COLLAB_HOST}}:{{COLLAB_PORT}}/{{TOKEN}}"],
    )

    async def fake_send(client, method, url, headers, body):
        return _resp(403, "Request blocked by WAF")

    monkeypatch.setattr(
        "dast.agents.ssrf_agent.next_payload",
        lambda *a, **k: _mutation_coro(),
    )

    async def _mutation_coro():
        return MutationResult(action="mutate", payload="http://{{COLLAB_HOST}}:{{COLLAB_PORT}}/{{TOKEN}}", rationale="decimal-encode IP")

    agent = SsrfAgent()
    observed = []
    agent.observe = lambda *a, **kw: observed.append((a, kw))

    with patch("dast.agents.ssrf_agent._send", side_effect=fake_send):
        findings = await agent.run(target, MagicMock(), collaborator=collaborator)

    assert len(findings) == 1
    assert any(a and a[0] == "waf_bypass" for a, _ in observed)


# ── body location injection ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_body_location_injection_oob_callback(monkeypatch):
    import json
    target = _target(
        url="https://example.com/api/webhook",
        method="POST",
        body=json.dumps({"webhook": "http://example.com"}),
        params=[{"name": "webhook", "location": "body", "value": "http://example.com"}],
    )
    collaborator = _FakeCollaborator(hit_tokens={"tok1"})
    monkeypatch.setattr(
        "dast.agents.ssrf_agent.get_filtered_payloads",
        lambda *a, **k: ["http://{{COLLAB_HOST}}:{{COLLAB_PORT}}/{{TOKEN}}"],
    )

    async def fake_send(client, method, url, headers, body):
        return _resp(200, "ok")

    with patch("dast.agents.ssrf_agent._send", side_effect=fake_send):
        findings = await SsrfAgent().run(target, MagicMock(), collaborator=collaborator)

    assert len(findings) == 1
    assert findings[0].parameter == "webhook"

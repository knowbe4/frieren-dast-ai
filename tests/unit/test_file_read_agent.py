"""
Unit tests for FileReadAgent — path traversal / local file inclusion.

HTTP layer mocked via dast.agents.file_read_agent._send. The mutator is
patched to return None by default so tests stay deterministic.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dast.agents.file_read_agent import FileReadAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/download?file=report.pdf", method="GET", params=None, body=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=body,
        params=params or [{"name": "file", "location": "query", "value": "report.pdf"}],
    )


def _resp(status=200, text=""):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


@pytest.fixture(autouse=True)
def _no_mutation(monkeypatch):
    async def _none(*a, **k):
        return None
    monkeypatch.setattr("dast.agents.file_read_agent.next_payload", _none)


# ── positive: /etc/passwd content ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_lfi_detected_with_passwd_content():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        if "etc" in url and "passwd" in url:
            return _resp(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
        return _resp(200, "normal file content")

    with patch("dast.agents.file_read_agent._send", side_effect=fake_send):
        findings = await FileReadAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "lfi"
    assert findings[0].cwe == "CWE-22"
    assert findings[0].severity == "high"


# ── negative: no file content leaked ────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_finding_when_no_file_content_leaked():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return _resp(404, "File not found")

    with patch("dast.agents.file_read_agent._send", side_effect=fake_send):
        findings = await FileReadAgent().run(target, MagicMock())

    assert findings == []


# ── WAF block then bypass ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_waf_block_then_bypass_records_waf_bypass(monkeypatch):
    from dast.ai.mutator import MutationResult

    target = _target()
    responses = iter([
        _resp(403, "Request blocked by WAF"),  # last seed payload blocked
        _resp(200, "root:x:0:0:root:/root:/bin/bash"),  # mutated payload succeeds
    ])

    async def fake_send(client, method, url, headers, body):
        return next(responses)

    monkeypatch.setattr("dast.agents.file_read_agent.get_filtered_payloads", lambda *a, **k: ["../../../../etc/passwd"])

    call_state = {"n": 0}
    async def fake_next_payload(*a, **k):
        call_state["n"] += 1
        if call_state["n"] == 1:
            return MutationResult(action="mutate", payload="..%2f..%2f..%2fetc/passwd", rationale="../ was stripped")
        return None
    monkeypatch.setattr("dast.agents.file_read_agent.next_payload", fake_next_payload)

    agent = FileReadAgent()
    observed = []
    agent.observe = lambda *a, **kw: observed.append((a, kw))

    with patch("dast.agents.file_read_agent._send", side_effect=fake_send):
        findings = await agent.run(target, MagicMock())

    assert len(findings) == 1
    assert any(a and a[0] == "waf_bypass" for a, _ in observed)


# ── body location injection ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_body_location_injection_detects_file_content():
    import json
    target = _target(
        url="https://example.com/api/report",
        method="POST",
        body=json.dumps({"template": "report.pdf"}),
        params=[{"name": "template", "location": "body", "value": "report.pdf"}],
    )

    async def fake_send(client, method, url, headers, body):
        if body and "etc" in body and "passwd" in body:
            return _resp(200, "root:x:0:0:root:/root:/bin/bash")
        return _resp(200, "normal content")

    with patch("dast.agents.file_read_agent._send", side_effect=fake_send):
        findings = await FileReadAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].parameter == "template"

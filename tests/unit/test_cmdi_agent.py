"""
Unit tests for CmdiAgent — OS command injection (output-based, time-based blind,
and shell-error disclosure). Deterministic, no mutator. HTTP layer mocked via
dast.agents.cmdi_agent._send.
"""

from __future__ import annotations

import re
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from dast.agents.cmdi_agent import CmdiAgent
from dast.scanners.active_checks import CheckTarget


def _target(url="https://example.com/ping?host=example.com", method="GET", params=None):
    return CheckTarget(
        method=method,
        url=url,
        headers={"content-type": "application/json"},
        body=None,
        params=params or [{"name": "host", "location": "query", "value": "example.com"}],
    )


def _resp(status=200, text="", elapsed=0.0):
    m = MagicMock()
    m.status_code = status
    m.text = text
    # Time-based detection reads server round-trip via resp.elapsed.total_seconds()
    # (active_checks.response_elapsed_ms), not wall-clock. Model it as a real
    # timedelta so a slow SLEEP response is simulated deterministically.
    m.elapsed = timedelta(seconds=elapsed)
    return m


# ── positive: output reflected ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_output_reflected_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        if payload and payload.strip(";|&$()`") == "id":
            return _resp(200, "ping ok\nuid=0(root) gid=0(root) groups=0(root)")
        return _resp(200, "ping ok")

    with patch("dast.agents.cmdi_agent._send", side_effect=fake_send):
        findings = await CmdiAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "cmdi"
    assert findings[0].cwe == "CWE-78"
    assert "Output Reflected" in findings[0].title


# ── positive: shell error disclosure ────────────────────────────────────────

@pytest.mark.asyncio
async def test_shell_error_disclosure_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        if payload == ";id":
            return _resp(500, "sh: 1: id: command not found")
        return _resp(200, "ping ok")

    with patch("dast.agents.cmdi_agent._send", side_effect=fake_send):
        findings = await CmdiAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert "Shell Error Disclosure" in findings[0].title


# ── positive: time-based blind ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_time_based_blind_detected():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        # Injectable endpoint: the response time TRACKS the requested `sleep N`
        # (delay scaling). `sleep 0` control is fast, `sleep 2` confirm ~2s, `sleep 4`
        # probe ~4s — so both the candidate and the sqlmap-style scaling confirmation
        # succeed. Detection compares resp.elapsed (server round-trip), not wall-clock.
        requested_s = 0.0
        if payload:
            m = re.search(r"sleep\s+(\d+)", payload, re.IGNORECASE)
            if m:
                requested_s = float(m.group(1))
        return _resp(200, "ping ok", elapsed=0.05 + requested_s)

    with patch("dast.agents.cmdi_agent._send", side_effect=fake_send):
        findings = await CmdiAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert "Time-Based Blind" in findings[0].title


# ── regression: body-location params are injected into the body, not the query ─
# DVWA /exec/ reads `ip` from the POST body ($_POST['ip']); the agent used to
# hardcode query-string injection (POST /exec/?ip=;id), which never reaches the
# vulnerable code path, so command injection went undetected.

@pytest.mark.asyncio
async def test_body_location_param_injected_into_body():
    target = CheckTarget(
        method="POST",
        url="https://example.com/exec/",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body="ip=127.0.0.1&Submit=Submit",
        params=[{"name": "ip", "location": "body", "value": "127.0.0.1"}],
    )

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        # `id` executes (uid output) ONLY when the payload landed in the body. If the
        # agent (wrongly) injected into the query string, the body still carries the
        # untouched value and no output leaks.
        if payload and payload.strip(";|&$()`") == "id" and body and payload in body:
            return _resp(200, "ping ok\nuid=33(www-data) gid=33(www-data)")
        return _resp(200, "ping ok")

    with patch("dast.agents.cmdi_agent._send", side_effect=fake_send):
        findings = await CmdiAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "cmdi"
    assert findings[0].parameter == "ip"
    assert "Output Reflected" in findings[0].title


# ── regression: WAF-bypass payloads are exercised and detected ───────────────
# Guards against the "bypass" payload group being loaded but never fed to a
# probe loop (Phase 3 was documented but unimplemented).

@pytest.mark.asyncio
async def test_waf_bypass_detected_when_direct_payloads_filtered():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        # Simulate a WAF: direct output/blind payloads are filtered (clean
        # response), but an IFS/encoding bypass variant still executes `id`.
        if payload and ("${IFS}" in payload or "$IFS" in payload or "%0a" in payload or "%00" in payload):
            return _resp(200, "uid=0(root) gid=0(root) groups=0(root)")
        return _resp(200, "filtered")

    with patch("dast.agents.cmdi_agent._send", side_effect=fake_send):
        findings = await CmdiAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert "WAF Bypass" in findings[0].title
    assert findings[0].cwe == "CWE-78"
    assert findings[0].confirmed is True


# ── negative: clean response ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_response_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        return _resp(200, "ping ok, no output leaked")

    with patch("dast.agents.cmdi_agent._send", side_effect=fake_send):
        findings = await CmdiAgent().run(target, MagicMock())

    assert findings == []


# ── negative: no injectable params ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_injectable_params_no_op():
    target = _target(params=[{"name": "confirm", "location": "query", "value": "true", "type": "boolean"}])

    findings = await CmdiAgent().run(target, MagicMock())

    assert findings == []

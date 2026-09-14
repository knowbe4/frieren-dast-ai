"""
Unit tests for CsrfAgent — focused on the hardened tokenless-request check
(Check 4), which must fire ONLY when every affirmative CSRF precondition holds
(ambient cookie auth + no token + no SameSite=Strict/Lax + server ignores
Origin/Referer), not on the weak "forged Origin returned 200" signal alone.
HTTP layer mocked via dast.agents.csrf_agent._send.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dast.agents.csrf_agent import (
    CsrfAgent,
    _request_carries_cookie_auth,
    _samesite_protects,
)
from dast.scanners.active_checks import CheckTarget


def _target(headers=None, body="ip=127.0.0.1&Submit=Submit", params=None):
    return CheckTarget(
        method="POST",
        url="https://example.com/exec/",
        headers=headers if headers is not None else {"cookie": "PHPSESSID=abc; security=low"},
        body=body,
        params=params or [{"name": "ip", "location": "body", "value": "127.0.0.1"}],
    )


def _resp(status=200, text="ok", set_cookie=None):
    m = MagicMock()
    m.status_code = status
    m.content = text.encode()
    m.text = text
    hdrs = MagicMock()
    hdrs.get_list.return_value = [set_cookie] if set_cookie else []
    m.headers = hdrs
    return m


# ── helper: cookie-auth detection ────────────────────────────────────────────

def test_request_carries_cookie_auth_true_with_cookie_header():
    assert _request_carries_cookie_auth(_target(headers={"cookie": "sid=1"})) is True


def test_request_carries_cookie_auth_false_without_cookie():
    assert _request_carries_cookie_auth(
        _target(headers={"authorization": "Bearer x"})
    ) is False


# ── helper: SameSite protection detection ────────────────────────────────────

@pytest.mark.parametrize("cookie,protected", [
    ("sid=1; SameSite=Strict", True),
    ("sid=1; samesite=lax", True),
    ("sid=1; SameSite=None", False),
    ("sid=1", False),
    (None, False),
])
def test_samesite_protects(cookie, protected):
    assert _samesite_protects(_resp(set_cookie=cookie)) is protected


# ── Check 4: positive — all preconditions hold (DVWA /exec/ shape) ───────────

@pytest.mark.asyncio
async def test_tokenless_cookie_auth_no_samesite_flags_csrf():
    target = _target()  # cookie auth, no token param/header

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        return _resp(200, "ping ok")  # server ignores Origin -> similar response

    with patch("dast.agents.csrf_agent._send", side_effect=fake_send):
        findings = await CsrfAgent().run(target, MagicMock())

    assert len(findings) == 1
    assert findings[0].attack_type == "csrf"
    assert findings[0].cwe == "CWE-352"
    assert "SameSite" in findings[0].title


# ── Check 4: negative — no cookie (header/bearer auth) is not CSRF ───────────

@pytest.mark.asyncio
async def test_no_cookie_auth_does_not_flag_csrf():
    target = _target(headers={"authorization": "Bearer token", "content-type": "text/plain"})

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        return _resp(200, "ping ok")

    with patch("dast.agents.csrf_agent._send", side_effect=fake_send):
        findings = await CsrfAgent().run(target, MagicMock())

    assert findings == []


# ── Check 4: negative — SameSite=Strict session cookie mitigates CSRF ────────

@pytest.mark.asyncio
async def test_samesite_strict_session_cookie_does_not_flag_csrf():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        # Baseline re-sets the session cookie as SameSite=Strict -> protected.
        return _resp(200, "ping ok", set_cookie="PHPSESSID=abc; SameSite=Strict")

    with patch("dast.agents.csrf_agent._send", side_effect=fake_send):
        findings = await CsrfAgent().run(target, MagicMock())

    assert findings == []


# ── Check 4: negative — server validates Origin/Referer (forged Origin blocked) ─

@pytest.mark.asyncio
async def test_origin_validation_blocks_finding():
    target = _target()
    calls = {"n": 0}

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        calls["n"] += 1
        # First call = baseline (200). Second = cross-origin probe rejected (403).
        if headers.get("Origin") == "https://evil.example.com":
            return _resp(403, "forbidden")
        return _resp(200, "ping ok")

    with patch("dast.agents.csrf_agent._send", side_effect=fake_send):
        findings = await CsrfAgent().run(target, MagicMock())

    assert findings == []
    assert calls["n"] == 2  # baseline + cross-origin probe both sent


# ── negative — non-state-changing method is skipped entirely ─────────────────

@pytest.mark.asyncio
async def test_get_method_is_skipped():
    target = CheckTarget(
        method="GET", url="https://example.com/x", headers={"cookie": "sid=1"},
        body=None, params=[],
    )
    findings = await CsrfAgent().run(target, MagicMock())
    assert findings == []

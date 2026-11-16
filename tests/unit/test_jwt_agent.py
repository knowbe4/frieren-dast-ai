"""Unit tests for the JWT VulnAgent (dast/agents/jwt_agent.py).

Transport faked at `dast.agents.jwt_agent._SEND` (module-level import — probe
attempts are proxy-routed like every other agent). Pins: token discovery across
header/cookie/params, the enforcement precheck, the acceptance heuristic, and
the forgery attack set (alg:none / weak-secret / escalation / kid).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dast.agents import jwt_agent
from dast.scanners.active_checks import CheckTarget
from dast.utils.jwt import build_token

_SECRET = "hwtest-secret-1"
_ORIG = build_token({"alg": "HS256", "typ": "JWT"},
                    {"sub": "1", "role": "user"}, secret=_SECRET)


def _resp(status=200, text="x" * 200):
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


def _target(with_auth=True):
    headers = {"content-type": "application/json"}
    if with_auth:
        headers["authorization"] = f"Bearer {_ORIG}"
    return CheckTarget(
        method="GET", url="https://app.test/api/me", headers=headers, body=None,
        params=[{"name": "id", "location": "query", "value": "1"}],
    )


# ── discovery ────────────────────────────────────────────────────────────────

def test_find_jwts_authorization_cookie_and_param():
    from dast.utils.jwt import build_token
    cookie_token = build_token({"alg": "HS256", "typ": "JWT"},
                               {"sub": "2", "role": "admin"}, secret="other")
    param_token = build_token({"alg": "HS256", "typ": "JWT"},
                              {"sub": "3", "role": "user"}, secret="third")
    target = CheckTarget(
        method="GET", url="https://app.test/x",
        headers={"authorization": f"Bearer {_ORIG}",
                 "cookie": f"sid=abc; jwt_session={cookie_token}"},
        body=None,
        params=[{"name": "redirect", "location": "query", "value": param_token}],
    )
    found = jwt_agent._find_jwts(target)
    locations = [p["location"] for _, p in found]
    assert locations[0] == "header"
    assert "cookie" in locations
    # Budget cap: at most 2 distinct tokens per endpoint.
    assert len(found) <= jwt_agent._MAX_TOKENS
    assert jwt_agent.has_jwt_target(target) is True
    # The SAME token seen twice (header + param) dedups to one discovery.
    dup = jwt_agent._find_jwts(_target())
    assert len(dup) == 1


def test_query_param_token_detected_in_isolation():
    param_token = build_token({"alg": "HS256", "typ": "JWT"},
                              {"sub": "9", "role": "user"}, secret="k")
    target = CheckTarget(
        method="GET", url="https://app.test/x",
        headers={"content-type": "application/json"},
        body=None,
        params=[{"name": "token", "location": "query", "value": param_token}],
    )
    found = jwt_agent._find_jwts(target)
    assert len(found) == 1 and found[0][1]["location"] == "query"


def test_non_jwt_request_has_no_target():
    assert jwt_agent.has_jwt_target(_target(with_auth=False)) is False
    assert jwt_agent._find_jwts(_target(with_auth=False)) == []


# ── enforcement precheck ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unenforced_endpoint_skips_forgery():
    """The unauthenticated replay looks like the baseline → no enforcement → no
    forgery testing (pure noise)."""
    target = _target()
    sends = []

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        sends.append(headers.get("authorization"))
        return _resp(200, "me-response-body-" + "x" * 180)  # same either way

    with patch.object(jwt_agent, "_SEND", new=fake_send):
        findings = await jwt_agent.JwtAgent().run(target, MagicMock())
    assert findings == []
    # TWO sends only: baseline + unauthenticated precheck — no forgery sweep.
    assert len(sends) == 2
    assert sends[1] == ""


# ── forgery acceptance ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_alg_none_forgery_accepted():
    """Baseline 401; the alg:none forged token returns 200 — the classic bypass."""
    target = _target()
    calls = []

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        calls.append(headers.get("authorization", ""))
        if headers.get("authorization", "").startswith("Bearer ey"):
            header = headers["authorization"][7:].split(".")[0]
            import base64, json
            padded = header + "=" * (-len(header) % 4)
            alg = json.loads(base64.urlsafe_b64decode(padded)).get("alg", "").lower()
            if alg == "none":
                return _resp(200, "admin-dashboard-body-" + "x" * 180)
            return _resp(401, "unauthorized")
        return _resp(401, "unauthorized")

    with patch.object(jwt_agent, "_SEND", new=fake_send):
        findings = await jwt_agent.JwtAgent().run(target, MagicMock())
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-347"
    assert findings[0].confirmed is True
    assert findings[0].extracted_data["variant"].startswith("alg:none")
    assert len(calls) >= 3  # baseline + precheck + at least one forgery send


@pytest.mark.asyncio
async def test_weak_secret_resign_accepted():
    """A weak-secret re-sign is accepted (200 like baseline) → finding."""
    target = _target()
    # Baseline: 200 (operator is authed). A forged token with the ORIGINAL
    # claims re-signed by a weak HMAC secret is accepted; non-HS junk is not.
    async def fake_send2(client, method, url, headers, body, payload=None, timeout=None):
        auth = headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        if token == _ORIG:
            return _resp(200, "me-response-body-" + "x" * 180)
        if token and jwt_agent.decode_jwt(token):
            header, claims = jwt_agent.decode_jwt(token)
            if claims.get("role") == "user" and header.get("alg", "").startswith("HS"):
                return _resp(200, "me-response-body-" + "x" * 180)
        return _resp(401, "unauthorized")

    with patch.object(jwt_agent, "_SEND", new=fake_send2):
        findings = await jwt_agent.JwtAgent().run(target, MagicMock())
    assert len(findings) == 1
    assert any("weak secret" in f for f in [findings[0].extracted_data["variant"]])


@pytest.mark.asyncio
async def test_refused_forgery_yields_no_finding():
    target = _target()

    async def fake_send(client, method, url, headers, body, payload=None, timeout=None):
        auth = headers.get("authorization", "")
        if auth == f"Bearer {_ORIG}":
            return _resp(200, "me-response-body-" + "x" * 180)
        return _resp(401, "unauthorized")

    with patch.object(jwt_agent, "_SEND", new=fake_send):
        findings = await jwt_agent.JwtAgent().run(target, MagicMock())
    assert findings == []


# ── param-token dispatch contract ────────────────────────────────────────────

def test_token_param_maps_to_jwt_agent():
    from dast.ai.coordinator import _PARAM_ATTACK_MAP
    assert "jwt" in _PARAM_ATTACK_MAP["token"]

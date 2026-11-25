"""Unit tests for AuthzLadderAgent (5-B-3) — role-ladder differential.

HTTP layer mocked via dast.agents.authz_ladder_agent._send. Sessions are
lightweight stand-ins for NamedSession (name/role/cookies/auth_headers). The
oracle under test: privileged 200 + low-priv 200 + unauth 401/403 = confirmed
CWE-862; any other shape (low-priv denied, unauth allowed, no roles) = no
finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict
from unittest.mock import MagicMock, patch


from dast.agents.authz_ladder_agent import AuthzLadderAgent
from dast.scanners.active_checks import CheckTarget


@dataclass
class _FakeSession:
    name: str
    role: str
    cookies: Dict = field(default_factory=dict)
    auth_headers: Dict = field(default_factory=dict)


_ADMIN_BODY = "<html>" + "admin dashboard content " * 20 + "</html>"


def _target(url="https://app.test/admin/users", method="GET",
            sessions=None, headers=None):
    return CheckTarget(
        method=method,
        url=url,
        headers=headers or {"content-type": "text/html", "cookie": "sid=admin-jwt"},
        body=None,
        params=[],
        named_sessions=sessions or [],
    )


def _resp(status=200, text="", reason=""):
    m = MagicMock()
    m.status_code = status
    m.text = text
    m.reason = reason
    return m


def _sessions():
    return [
        _FakeSession(name="admin", role="admin",
                     auth_headers={"authorization": "Bearer admin-tok"}),
        _FakeSession(name="user_a", role="member",
                     auth_headers={"authorization": "Bearer user-tok"}),
    ]


def test_ladder_differential_confirms():
    """privileged 200 + low-priv 200 (substantial) + unauth 403 → confirmed."""
    async def fake_send(client, method, url, headers, body):
        auth = (headers or {}).get("authorization", "")
        cookie = (headers or {}).get("cookie", "")
        if auth == "Bearer user-tok":
            return _resp(200, _ADMIN_BODY)          # ladder gap
        if not auth and not cookie:
            return _resp(403, "forbidden")          # 403 control
        return _resp(200, _ADMIN_BODY)              # privileged read

    with patch("dast.agents.authz_ladder_agent._send", side_effect=fake_send):
        findings = asyncio_run(AuthzLadderAgent().run(_target(sessions=_sessions()), MagicMock()))

    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-862"
    assert f.severity == "high"
    assert f.confirmed is True and f.bypass_validation is True
    assert "user_a" in f.evidence
    assert "403" in (f.extracted_data or {}).get("ladder", "")


def test_low_priv_denied_no_finding():
    """The ladder holds (low-priv session gets 403) → no finding."""
    async def fake_send(client, method, url, headers, body):
        auth = (headers or {}).get("authorization", "")
        if auth == "Bearer user-tok":
            return _resp(403, "forbidden")
        if not auth:
            return _resp(403, "forbidden")
        return _resp(200, _ADMIN_BODY)

    with patch("dast.agents.authz_ladder_agent._send", side_effect=fake_send):
        findings = asyncio_run(AuthzLadderAgent().run(_target(sessions=_sessions()), MagicMock()))
    assert findings == []


def test_unauth_allowed_means_not_a_ladder_gap():
    """Auth stripped also gets 200 → no authorization control at all; that is
    auth_bypass territory, so the ladder agent stays silent."""
    async def fake_send(client, method, url, headers, body):
        return _resp(200, _ADMIN_BODY)

    with patch("dast.agents.authz_ladder_agent._send", side_effect=fake_send):
        findings = asyncio_run(AuthzLadderAgent().run(_target(sessions=_sessions()), MagicMock()))
    assert findings == []


def test_requires_two_distinct_roles():
    """One session, or two sessions on the SAME role → no ladder, no probes."""
    same_role = [
        _FakeSession(name="user_a", role="member"),
        _FakeSession(name="user_b", role="member"),
    ]
    for sessions in ([_FakeSession(name="admin", role="admin")], same_role, []):
        with patch("dast.agents.authz_ladder_agent._send", side_effect=AssertionError) as _:
            findings = asyncio_run(AuthzLadderAgent().run(
                _target(sessions=sessions), MagicMock()))
        assert findings == []


def test_never_sends_state_changing_methods():
    with patch("dast.agents.authz_ladder_agent._send", side_effect=AssertionError) as _:
        findings = asyncio_run(AuthzLadderAgent().run(
            _target(method="DELETE", sessions=_sessions()), MagicMock()))
    assert findings == []


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)


# ── dispatch rule ────────────────────────────────────────────────────────────

def test_dispatch_requires_distinct_roles():
    from dast.ai.coordinator import _select_attack_types_for_params

    distinct = _target(sessions=_sessions())
    assert "authz_ladder" in _select_attack_types_for_params(distinct, None)

    same = _target(sessions=[
        _FakeSession(name="user_a", role="member"),
        _FakeSession(name="user_b", role="member"),
    ])
    assert "authz_ladder" not in _select_attack_types_for_params(same, None)


def test_registry_counts_authz_ladder():
    import dast.agents  # noqa: F401 — trigger registrations
    from dast.ai.coordinator import Coordinator
    assert "authz_ladder" in Coordinator._registry

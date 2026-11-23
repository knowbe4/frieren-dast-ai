"""BFLA agent tests (4-B).

SAFETY pin: the agent performs GET/HEAD only — no state-changing method is
ever sent. Findings are honest-by-default (confirmed=False: role semantics
need operator judgment) unless structural equivalence says otherwise.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import dast.agents  # noqa: F401 — populates the Coordinator registry
import pytest

from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget

_ADMIN_BODY = "x" * 500 + "admin console dashboard"
_USER_BODY = "y" * 500 + "user dashboard"


def _target(url="https://app.example.com/admin/users", method="GET"):
    return CheckTarget(method=method, url=url,
                       headers={"cookie": "sid=operator"}, body=None, params=[])


def _session(name="user_a", role="member"):
    return SimpleNamespace(name=name, role=role, cookies={}, auth_headers={})


def _r(status=200, body=_ADMIN_BODY, url="https://app.example.com/admin/users"):
    return SimpleNamespace(
        status_code=status, text=body, headers={}, content=body.encode(),
        request=SimpleNamespace(method="GET", url=url, headers={}, content=b""),
    )


def _install(monkeypatch, responder):
    import dast.agents.bfla_agent as mod

    sent: list = []

    async def fake_send(client, method, url, headers, body, **kw):
        sent.append({"method": method, "url": url})
        return responder(url, method)

    monkeypatch.setattr(mod, "_send", fake_send)
    return sent


@pytest.fixture(autouse=True)
def _fresh_registry():
    from dast.ai import provider_health

    provider_health.reset()
    yield
    provider_health.reset()


def test_registered():
    assert "bfla" in Coordinator._registry


@pytest.mark.asyncio
async def test_admin_page_served_to_member_session(monkeypatch):
    from dast.agents.bfla_agent import BflaAgent

    sent = _install(monkeypatch, lambda url, method: _r(200, _ADMIN_BODY))
    target = _target()
    target.named_sessions = [_session("user_a", "member")]
    findings = await BflaAgent().run(target, MagicMock(), None)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-862"
    assert findings[0].severity == "high"
    assert findings[0].confirmed is False
    assert all(s["method"] in ("GET", "HEAD") for s in sent)  # safety pin


@pytest.mark.asyncio
async def test_admin_session_role_is_skipped(monkeypatch):
    from dast.agents.bfla_agent import BflaAgent

    sent = _install(monkeypatch, lambda url, method: _r(200, _ADMIN_BODY))
    target = _target()
    target.named_sessions = [_session("the_admin", "admin")]
    findings = await BflaAgent().run(target, MagicMock(), None)
    assert findings == []
    assert sent == []  # no non-admin session to replay with


@pytest.mark.asyncio
async def test_version_downgrade_v2_forbidden_v1_served(monkeypatch):
    from dast.agents.bfla_agent import BflaAgent

    def responder(url, method):
        if "/v2/" in url:
            return _r(403, "forbidden", url=url)
        if "/v1/" in url:
            return _r(200, _ADMIN_BODY, url=url)
        return _r(200, _ADMIN_BODY, url=url)

    sent = _install(monkeypatch, responder)
    target = _target(url="https://app.example.com/v2/admin/users")
    findings = await BflaAgent().run(target, MagicMock(), None)

    assert len(findings) == 1
    assert "v1" in findings[0].evidence
    assert findings[0].confirmed is False
    assert all(s["method"] == "GET" for s in sent)


@pytest.mark.asyncio
async def test_state_changing_target_is_never_probed(monkeypatch):
    from dast.agents.bfla_agent import BflaAgent

    sent = _install(monkeypatch, lambda url, method: _r(200, _ADMIN_BODY))
    target = _target(url="https://app.example.com/admin/users", method="DELETE")
    target.named_sessions = [_session("user_a", "member")]
    findings = await BflaAgent().run(target, MagicMock(), None)
    assert findings == []
    assert sent == []  # hard gate: DELETE targets are not touched at all


@pytest.mark.asyncio
async def test_non_admin_path_skipped(monkeypatch):
    from dast.agents.bfla_agent import BflaAgent

    _install(monkeypatch, lambda url, method: _r(200, _ADMIN_BODY))
    target = _target(url="https://app.example.com/v2/admin/users")  # downgrade path only
    findings = await BflaAgent().run(target, MagicMock(), None)
    assert findings == []

"""Tests for autonomous-run profile authentication.

Covers the two halves of the credential-only-profile login fix:
  * ``_activate_profile`` seeds ``engine._last_login`` from a profile that has
    credentials but no captured session (so 401 auto-relogin is armed), and
  * ``_ensure_profile_login`` performs a real login at run start using those
    credentials (never exposing them to the model), syncing cookies on success and
    degrading gracefully — not deadlocking — otherwise.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import dast.browser.login_cascade as login_cascade
import dast.profiles.store as profiles_store
from dast.profiles.models import Credential, LoginProfile
from dast.proxy.api.copilot_service import CopilotService


class _FakeStore:
    ai_mode = False

    def get_cookies_for_host(self, host):
        return []

    def in_scope_entries(self):
        return []


class _FakeCtx:
    def __init__(self) -> None:
        self.proxy_port = 8080
        self.dashboard_port = 8088
        self.store = _FakeStore()
        self.settings = None
        self.broadcast_copilot = AsyncMock()


def test_activate_profile_seeds_last_login_from_credential_only_profile(monkeypatch):
    service = CopilotService(_FakeCtx())
    sid = service.new_session()
    session = service.get(sid)
    engine = session["engine"]
    assert engine._last_login is None

    profile = LoginProfile(
        slug="p", name="P", auth_url="https://app.example.com/login",
        credentials=[Credential(username="u@example.com", secret="pw")],
        saved_session=None,  # credential-only: no captured session
    )
    monkeypatch.setattr(profiles_store, "load_profile", lambda slug: profile)

    service._activate_profile("p", session)

    assert engine._last_login == {
        "url": "https://app.example.com/login",
        "email": "u@example.com",
        "password": "pw",
    }


@pytest.mark.asyncio
async def test_ensure_profile_login_noop_without_credentials():
    service = CopilotService(_FakeCtx())
    sid = service.new_session()
    session = service.get(sid)
    session["autonomous"] = {"profile": None, "hosts": []}
    session["engine"]._last_login = None

    await service._ensure_profile_login(sid, session)

    assert session["autonomous"].get("_proactive_login_done") is not True


@pytest.mark.asyncio
async def test_ensure_profile_login_logs_in_and_syncs_cookies(monkeypatch):
    service = CopilotService(_FakeCtx())
    sid = service.new_session()
    session = service.get(sid)
    session["autonomous"] = {"profile": "p", "hosts": []}
    engine = session["engine"]
    engine._last_login = {"url": "https://app.example.com/login",
                          "email": "u@example.com", "password": "pw"}
    engine._session_cookies = {}

    class _FakeBrowser:
        async def export_cookies(self):
            return {"_session": "abc"}

        async def export_cookies_full(self):
            return []

        async def api_get(self, url, headers=None):
            # Gate-check sees a real, provisioned account.
            return {"ok": True, "status": 200,
                    "text": '{"user": {"id": 5}, "account": {"id": 42}}', "headers": {}}

    fake_ctx = SimpleNamespace(browser=_FakeBrowser(), is_in_scope=lambda u: True)
    monkeypatch.setattr(service, "_build_tool_ctx", lambda s: fake_ctx)
    service._broadcast_autonomous = AsyncMock()
    login_mock = AsyncMock(return_value=SimpleNamespace(
        ok=True, engine="deterministic", error=None))
    monkeypatch.setattr(login_cascade, "adaptive_login", login_mock)

    await service._ensure_profile_login(sid, session)

    assert login_mock.await_count == 1
    args, _ = login_mock.await_args
    assert args[1] == "https://app.example.com/login"
    assert args[2] == "u@example.com"
    assert args[3] == "pw"
    assert engine._session_cookies.get("_session") == "abc"
    assert session["autonomous"]["_proactive_login_done"] is True
    assert "authenticated via profile" in session["autonomous"]["detail"]


@pytest.mark.asyncio
async def test_ensure_profile_login_flags_guest_session_as_not_provisioned(monkeypatch):
    # Login "succeeds" but the account endpoint reports a guest account (id -1):
    # the run must NOT declare authenticated — it surfaces a not-provisioned status.
    service = CopilotService(_FakeCtx())
    sid = service.new_session()
    session = service.get(sid)
    session["autonomous"] = {"profile": "p", "hosts": []}
    engine = session["engine"]
    engine._last_login = {"url": "https://app.example.com/login",
                          "email": "u@example.com", "password": "pw"}
    engine._session_cookies = {}

    class _GuestBrowser:
        async def export_cookies(self):
            return {"_session": "abc"}

        async def api_get(self, url, headers=None):
            return {"ok": True, "status": 200,
                    "text": '{"account": {"id": -1}, "user": null}', "headers": {}}

    fake_ctx = SimpleNamespace(browser=_GuestBrowser(), is_in_scope=lambda u: True)
    monkeypatch.setattr(service, "_build_tool_ctx", lambda s: fake_ctx)
    broadcasts = []
    async def _record(sid_, event, payload=None):
        broadcasts.append((event, payload))
    service._broadcast_autonomous = _record  # type: ignore[assignment]
    login_mock = AsyncMock(return_value=SimpleNamespace(
        ok=True, engine="deterministic", error=None))
    monkeypatch.setattr(login_cascade, "adaptive_login", login_mock)

    await service._ensure_profile_login(sid, session)

    detail = session["autonomous"]["detail"].lower()
    assert "not provisioned" in detail or "guest" in detail
    assert "authenticated via profile" not in session["autonomous"]["detail"]
    assert any(event == "auth_failed" for event, _ in broadcasts)
    assert not any(event == "authenticated" for event, _ in broadcasts)


def test_session_is_provisioned_classification():
    from dast.proxy.api.copilot_service import _session_is_provisioned

    assert _session_is_provisioned({"account": {"id": 42}, "user": {"id": 5}}) is True
    assert _session_is_provisioned({"account": {"id": -1}, "user": None}) is False
    assert _session_is_provisioned({"guest": True}) is False
    assert _session_is_provisioned({"user": {"account_id": 7}}) is True
    # Unknown shape -> None (fail open).
    assert _session_is_provisioned({"something": "else"}) is None
    assert _session_is_provisioned([]) is None


@pytest.mark.asyncio
async def test_ensure_profile_login_degrades_on_failure(monkeypatch):
    service = CopilotService(_FakeCtx())
    sid = service.new_session()
    session = service.get(sid)
    session["autonomous"] = {"profile": "p", "hosts": []}
    engine = session["engine"]
    engine._last_login = {"url": "https://app.example.com/login",
                          "email": "u@example.com", "password": "pw"}
    engine._session_cookies = {}

    fake_ctx = SimpleNamespace(browser=object(), is_in_scope=lambda u: True)
    monkeypatch.setattr(service, "_build_tool_ctx", lambda s: fake_ctx)
    service._broadcast_autonomous = AsyncMock()
    login_mock = AsyncMock(return_value=SimpleNamespace(
        ok=False, engine=None, error="no email field"))
    monkeypatch.setattr(login_cascade, "adaptive_login", login_mock)

    # Must not raise — a failed login reports a blocker, it does not deadlock.
    await service._ensure_profile_login(sid, session)

    assert session["autonomous"]["_proactive_login_done"] is True
    assert "failed" in session["autonomous"]["detail"].lower()


# ── autonomous start race + validation methodology/guardrail prompt presence ─────

@pytest.mark.asyncio
async def test_run_autonomous_sets_top_level_status_synchronously(monkeypatch):
    # Regression: the top-level session["status"] was left "idle" at launch (only the
    # nested autonomous.status was set), so a poll saw a false "idle/turns=0" terminal.
    service = CopilotService(_FakeCtx())

    async def _noop(sid):  # keep the driver from doing real work in the test
        return None
    monkeypatch.setattr(service, "_drive_autonomous", _noop)

    sid = service.run_autonomous("map the api", focus_hosts=["app.example.com"])
    session = service.get(sid)
    assert session["status"] == "running"                       # top-level, synchronous
    assert (session.get("autonomous") or {}).get("turns") == 0


def test_system_prompt_has_validation_and_secret_rules():
    from dast.ai.copilot.session import _SYSTEM_COPILOT
    assert "GROUND THE REAL ROUTE" in _SYSTEM_COPILOT
    assert "BASELINE ON YOUR OWN ID" in _SYSTEM_COPILOT
    assert "NEVER paste a raw secret" in _SYSTEM_COPILOT


def test_validation_playbook_constant_present():
    from dast.proxy.api.copilot_service import _AUTONOMOUS_VALIDATION_PLAYBOOK
    assert "GROUND THE REAL ROUTE" in _AUTONOMOUS_VALIDATION_PLAYBOOK
    assert "BASELINE on your OWN id" in _AUTONOMOUS_VALIDATION_PLAYBOOK

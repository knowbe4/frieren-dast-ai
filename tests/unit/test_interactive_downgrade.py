"""Unit 2 — refusal-resilient interactive copilot + record_finding host defaulting.

- A: `_arm_profile_downgrade` arms the per-profile refusal downgrade only under --authorized AND
  profile opt-in; otherwise clears it (never global).
- B: an interactive session binds to a profile (`new_session(profile_slug=...)`) and `start_turn`
  arms the downgrade once.
- C: the `send()` decision loop retries once with the downgrade model on ANY failed decision (a
  clean content block OR the generic None that a chain-fallback refusal surfaces as), and keeps
  today's behavior when no downgrade is armed.
- D: a `record_finding` call with a missing / placeholder host is backfilled from the most recent
  in-scope request (dispatch + tool safety net).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, patch

import pytest

from dast.ai.copilot.session import (
    CopilotSession,
    _is_placeholder_url,
    _last_in_scope_url,
)
from dast.proxy.api.copilot_service import CopilotService
from tests.unit.test_copilot_autonomous import _FakeCtx as _SvcCtx
from tests.unit.test_copilot_session import (
    _TOOLS,
    _FakeCtx,
    _FakeStore,
    _FakeTool,
    _collector,
    _deny_human,
)

_REPLY = {"action": "reply", "thought": "d", "message": "ok"}


def _profile(allow: bool, model: str = "claude-opus-4-6", slug: str = "p") -> SimpleNamespace:
    return SimpleNamespace(allow_model_downgrade=allow, downgrade_model=model, slug=slug)


# ── A: _arm_profile_downgrade ────────────────────────────────────────────────

def test_arm_downgrade_opt_in_authorized(monkeypatch):
    monkeypatch.setattr("dast.authorization.is_full_authorization", lambda: True)
    svc = CopilotService(_SvcCtx())
    eng = SimpleNamespace(_downgrade_model="")
    svc._arm_profile_downgrade(eng, _profile(True, "claude-opus-4-6"))
    assert eng._downgrade_model == "claude-opus-4-6"


def test_arm_downgrade_defaults_model_when_blank(monkeypatch):
    monkeypatch.setattr("dast.authorization.is_full_authorization", lambda: True)
    svc = CopilotService(_SvcCtx())
    eng = SimpleNamespace(_downgrade_model="")
    svc._arm_profile_downgrade(eng, _profile(True, model=""))
    assert eng._downgrade_model == "claude-opus-4-6"


def test_arm_downgrade_off_when_flag_false(monkeypatch):
    monkeypatch.setattr("dast.authorization.is_full_authorization", lambda: True)
    svc = CopilotService(_SvcCtx())
    eng = SimpleNamespace(_downgrade_model="stale")
    svc._arm_profile_downgrade(eng, _profile(False))
    assert eng._downgrade_model == ""  # cleared — never inherited by another profile/session


def test_arm_downgrade_off_when_unauthorized(monkeypatch):
    monkeypatch.setattr("dast.authorization.is_full_authorization", lambda: False)
    svc = CopilotService(_SvcCtx())
    eng = SimpleNamespace(_downgrade_model="")
    svc._arm_profile_downgrade(eng, _profile(True))
    assert eng._downgrade_model == ""  # opt-in needs full authorization


# ── B: interactive profile binding ───────────────────────────────────────────

def test_new_session_binds_profile(monkeypatch):
    monkeypatch.setattr("dast.profiles.store.load_profile", lambda slug: None)
    svc = CopilotService(_SvcCtx())
    sid = svc.new_session(profile_slug="kmsat-tenant-a")
    assert svc.get(sid)["profile_slug"] == "kmsat-tenant-a"
    assert svc.session_dict(sid)["profile"] == "kmsat-tenant-a"


def test_new_session_unbound_by_default():
    svc = CopilotService(_SvcCtx())
    sid = svc.new_session()
    assert svc.get(sid)["profile_slug"] is None


def test_start_turn_arms_downgrade_for_bound_profile(monkeypatch):
    monkeypatch.setattr("dast.authorization.is_full_authorization", lambda: True)
    monkeypatch.setattr("dast.profiles.store.load_profile",
                        lambda slug: _profile(True, "claude-opus-4-6", slug))

    class _DummyTask:
        def done(self) -> bool:
            return True

    def _fake_spawn(coro, name: str = ""):
        coro.close()  # do not actually run the turn — we only assert the arming
        return _DummyTask()

    monkeypatch.setattr("dast.proxy.api.copilot_service.spawn_tracked", _fake_spawn)

    svc = CopilotService(_SvcCtx())
    sid = svc.new_session(profile_slug="p")
    eng = svc.get(sid)["engine"]
    svc.start_turn(sid, "go")
    assert eng._downgrade_model == "claude-opus-4-6"
    assert svc.get(sid)["_downgrade_armed"] is True


# ── C: downgrade retry in the decision loop ──────────────────────────────────

async def _drive(session: CopilotSession, ctx: Any, fake_step) -> Any:
    events, on_event = _collector()
    with patch("dast.tools.all_tools", return_value=_TOOLS), \
         patch("dast.tools.run_tool", new=AsyncMock()), \
         patch("dast.ai.copilot.session._llm_step", new=fake_step):
        return await session.send("go", ctx, on_event=on_event, wait_for_human=_deny_human())


@pytest.mark.asyncio
async def test_downgrade_recovers_generic_failed_decision():
    # The real refusal shape: primary model fails generically (chain fell back to a model that
    # returned a refusal-shaped malformed output → None). The armed downgrade retry recovers it.
    session = CopilotSession("s-dg")
    session._downgrade_model = "claude-opus-4-6"

    async def fake_step(system: str, user: str, model_override: Optional[str] = None):
        return _REPLY if model_override == "claude-opus-4-6" else None

    reply = await _drive(session, _FakeCtx(), fake_step)
    assert reply.message == "ok" and reply.blocked_reason == ""


@pytest.mark.asyncio
async def test_no_downgrade_keeps_failure_behavior():
    # No downgrade armed → a failing decision still ends the turn as an error (no regression).
    session = CopilotSession("s-nodg")

    async def fake_step(system: str, user: str, model_override: Optional[str] = None):
        return None

    reply = await _drive(session, _FakeCtx(), fake_step)
    assert reply.blocked_reason == "error"


@pytest.mark.asyncio
async def test_clean_block_without_downgrade_is_safety_blocked():
    from dast.ai import bedrock_client
    session = CopilotSession("s-blk")

    async def fake_step(system: str, user: str, model_override: Optional[str] = None):
        raise bedrock_client.AiContentBlockedError("blocked")

    reply = await _drive(session, _FakeCtx(), fake_step)
    assert reply.blocked_reason == "safety_blocked"


@pytest.mark.asyncio
async def test_clean_block_then_downgrade_succeeds():
    from dast.ai import bedrock_client
    session = CopilotSession("s-blk2")
    session._downgrade_model = "claude-opus-4-6"

    async def fake_step(system: str, user: str, model_override: Optional[str] = None):
        if model_override == "claude-opus-4-6":
            return _REPLY
        raise bedrock_client.AiContentBlockedError("blocked")

    reply = await _drive(session, _FakeCtx(), fake_step)
    assert reply.message == "ok" and reply.blocked_reason == ""


# ── D: record_finding host defaulting ────────────────────────────────────────

def test_is_placeholder_url():
    assert _is_placeholder_url("")
    assert _is_placeholder_url("<unknown>")
    assert _is_placeholder_url("https://unknown/x")
    assert _is_placeholder_url("https://example.com/x")
    assert _is_placeholder_url("https://localhost/x")
    assert not _is_placeholder_url("https://app.target.test/reports/graphql")


def test_last_in_scope_url_returns_most_recent():
    ctx = _FakeCtx(in_scope=True)
    ctx.store = _FakeStore(entries=[SimpleNamespace(url="https://a.scope/1"),
                                    SimpleNamespace(url="https://b.scope/2")])
    assert _last_in_scope_url(ctx, []) == "https://b.scope/2"


def test_last_in_scope_url_none_when_nothing_in_scope():
    ctx = _FakeCtx(in_scope=False)
    ctx.store = _FakeStore(entries=[SimpleNamespace(url="https://a.scope/1")])
    assert _last_in_scope_url(ctx, []) is None


@pytest.mark.asyncio
async def test_record_finding_url_backfilled_at_dispatch():
    session = CopilotSession("s-rf", focus_hosts=["in.scope"])
    ctx = _FakeCtx(in_scope=True)
    ctx.store = _FakeStore(entries=[SimpleNamespace(url="https://in.scope/api/x")])
    run_tool = AsyncMock(return_value={"ok": True, "entry_id": "e1"})
    step: Dict[str, Any] = {
        "action": "call_tool", "thought": "t", "tool_name": "record_finding",
        "tool_args": {"title": "T", "evidence": "E", "url": "<unknown>"},
    }
    tools = _TOOLS + [_FakeTool("record_finding")]
    events, on_event = _collector()
    with patch("dast.tools.all_tools", return_value=tools), \
         patch("dast.tools.run_tool", new=run_tool), \
         patch("dast.ai.copilot.session._llm_step",
               new=AsyncMock(side_effect=[step, _REPLY])):
        await session.send("go", ctx, on_event=on_event, wait_for_human=_deny_human())

    run_tool.assert_awaited()
    passed_args = run_tool.call_args.args[2]
    assert passed_args["url"] == "https://in.scope/api/x"  # backfilled from in-scope history


class _RecCtx:
    def __init__(self, store: Any, in_scope: bool = True) -> None:
        self.store = store
        self._in_scope = in_scope

    def is_in_scope(self, url: str) -> bool:
        return self._in_scope


@pytest.mark.asyncio
async def test_record_finding_tool_defaults_url_from_history():
    from dast.tools import record_finding_tools as rft

    class _Store:
        def __init__(self) -> None:
            self.rec: Any = None

        def all_entries(self):
            return [SimpleNamespace(url="https://in.scope/api/y")]

        def record_manual_finding(self, finding, url, method="GET"):
            self.rec = (finding, url, method)
            return "e9"

    store = _Store()
    out = await rft._record_finding(_RecCtx(store), {
        "title": "T", "evidence": "E", "url": "<unknown>", "severity": "high",
    })
    assert out["ok"] is True
    assert store.rec[1] == "https://in.scope/api/y"  # tool defaulted the placeholder host


@pytest.mark.asyncio
async def test_record_finding_tool_rejects_placeholder_without_history():
    from dast.tools import record_finding_tools as rft

    class _Store:
        def all_entries(self):
            return []

        def record_manual_finding(self, *a, **k):  # pragma: no cover - must not be reached
            raise AssertionError("must not record under a placeholder host")

    out = await rft._record_finding(_RecCtx(_Store(), in_scope=False),
                                    {"title": "T", "evidence": "E", "url": "<unknown>"})
    assert out["ok"] is False and "url is required" in out["error"]

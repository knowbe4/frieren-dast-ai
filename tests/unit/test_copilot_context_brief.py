"""Unit tests for the Exploration Copilot's project-context grounding.

The copilot must reason from what the scanner already learned about a target
(CLAUDE.md rule 7: understand before acting) rather than starting blind. These
tests cover the three seams that deliver that:

  * ``build_context_brief`` (dast/ai/copilot/context_brief.py) — assembles a
    compact, per-host brief from the app-context profile and session intelligence.
  * ``SessionIntelligence.peek`` — read-only host lookup that never creates an
    empty entry (so building a brief cannot pollute the store).
  * ``CopilotSession`` — normalises seeded focus hosts and injects the brief into
    the turn prompt.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dast.ai.copilot.context_brief import build_context_brief
from dast.ai.copilot.session import CopilotSession
from dast.ai.session_intelligence import SessionIntelligence
from dast.discovery.app_context import AppProfile, VulnHypothesis


def _profile(host: str) -> AppProfile:
    profile = AppProfile(host=host, app_type="e-commerce API", auth_model="JWT Bearer")
    profile.vuln_hypotheses.append(
        VulnHypothesis(attack_type="idor", endpoint="GET /api/orders/{id}",
                       parameter="id", rationale="sequential ids", priority="high")
    )
    return profile


class _Engine:
    """Discovery engine stub returning one fixed profile keyed by host."""

    def __init__(self, profile: AppProfile) -> None:
        self._profile = profile

    def get_app_profile(self, host: str):
        return self._profile if self._profile.host == host else None


class _AnyEngine:
    """Returns a (non-empty) profile for every host — for cap/dedup tests."""

    def get_app_profile(self, host: str) -> AppProfile:
        return _profile(host)


class _BoomEngine:
    def get_app_profile(self, host: str):
        raise RuntimeError("boom")


class _Store:
    def __init__(self, engine=None, intelligence=None) -> None:
        self.discovery_engine = engine
        self.session_intelligence = intelligence


# ── build_context_brief ───────────────────────────────────────────────────────
def test_brief_empty_without_store_or_hosts():
    assert build_context_brief(None, ["h"]) == ""
    assert build_context_brief(_Store(), []) == ""


def test_brief_includes_app_and_intel_hints():
    intelligence = SessionIntelligence()
    intel = intelligence.get("api.example.com")
    intel.app_summary = "shopping cart API"
    intel.effective_attack_types.add("xss")
    store = _Store(engine=_Engine(_profile("api.example.com")), intelligence=intelligence)

    # Host is upper-cased on input — the brief must key it lowercase.
    brief = build_context_brief(store, ["API.example.com"])
    assert "Host api.example.com" in brief
    assert "idor" in brief                       # from the app-context hypothesis
    assert "shopping cart API" in brief          # from the session-intel planner hint
    assert "xss" in brief                        # effective attack type


def test_brief_dedupes_and_caps_hosts():
    store = _Store(engine=_AnyEngine())
    brief = build_context_brief(store, ["a", "A", "b", "c"], max_hosts=2)
    assert "Host a:" in brief and "Host b:" in brief
    assert "Host c:" not in brief


def test_brief_survives_a_host_lookup_failure():
    # A raising engine must be swallowed and logged, never crash the turn.
    assert build_context_brief(_Store(engine=_BoomEngine()), ["h"]) == ""


def test_brief_empty_when_store_knows_nothing():
    store = _Store(engine=None, intelligence=SessionIntelligence())
    assert build_context_brief(store, ["unknown.example.com"]) == ""


# ── SessionIntelligence.peek ────────────────────────────────────────────────────
def test_peek_does_not_create_entry():
    intelligence = SessionIntelligence()
    assert intelligence.peek("h") is None
    # Peeking twice still must not have created the host.
    assert intelligence.peek("h") is None
    created = intelligence.get("h")
    assert intelligence.peek("h") is created


# ── CopilotSession ───────────────────────────────────────────────────────────────
def test_focus_hosts_are_normalised():
    session = CopilotSession("s1", focus_hosts=["  API.example.com ", "", "b"])
    assert session._focus_hosts == ["api.example.com", "b"]


@pytest.mark.asyncio
async def test_send_injects_project_context_into_prompt():
    intelligence = SessionIntelligence()
    intelligence.get("api.example.com").app_summary = "shopping cart API"
    store = _Store(engine=_Engine(_profile("api.example.com")), intelligence=intelligence)
    tool_ctx = SimpleNamespace(store=store, approved_hosts=set())

    captured: dict = {}

    async def fake_step(system: str, user: str):
        captured["user"] = user
        return {"action": "reply", "message": "done", "thought": "t"}

    async def on_event(_payload: dict) -> None:
        return None

    async def wait_for_human(_kind: str, _payload: dict) -> dict:
        return {}

    session = CopilotSession("s1", focus_hosts=["api.example.com"])
    with patch("dast.ai.copilot.session._llm_step", new=fake_step):
        reply = await session.send("investigate the orders endpoint", tool_ctx,
                                   on_event=on_event, wait_for_human=wait_for_human)

    assert reply.message == "done"
    assert "project_context" in captured["user"]       # fenced as untrusted
    assert "api.example.com" in captured["user"]
    assert "shopping cart API" in captured["user"]

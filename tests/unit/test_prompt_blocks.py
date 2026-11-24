"""Unit tests for the shared copilot prompt blocks (dast/ai/copilot/prompt_blocks.py).

Round 5-A-3: the leads/router/coverage builders the autonomous driver always
injected, extracted as pure functions so the INTERACTIVE step prompt gets them
too. All builders fail-open to "".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from dast.ai.copilot.prompt_blocks import (
    coverage_block,
    guidance_blocks,
    leads_block,
    router_block,
)
from dast.ai.session_intelligence import SessionIntelligence
from dast.coverage import ledger as coverage_ledger
from dast.discovery.app_context import AppProfile, VulnHypothesis


def _profile(host: str, attack: str = "idor") -> AppProfile:
    profile = AppProfile(host=host, app_type="e-commerce API", auth_model="JWT Bearer")
    profile.vuln_hypotheses.append(
        VulnHypothesis(attack_type=attack, endpoint="GET /api/orders/{id}",
                       parameter="id", rationale="sequential ids", priority="high")
    )
    return profile


class _Engine:
    """Profiles for two hosts; router evidence lookups return None/nothing."""

    def __init__(self) -> None:
        self._profiles = {"api.shop.test": _profile("api.shop.test"),
                          "other.test": _profile("other.test", "sqli")}

    def all_app_profiles(self):
        return dict(self._profiles)

    def get_app_profile(self, host: str):
        return self._profiles.get(host)

    def context_for_host(self, host: str):
        return None


@dataclass
class _FakeEntry:
    host: str
    path: str
    url: str = ""
    method: str = "POST"
    request_body: bytes | None = None
    scan_result: dict | None = None


class _FakeStore:
    def __init__(self, entries: List[_FakeEntry] | None = None,
                 engine: _Engine | None = None,
                 intelligence: SessionIntelligence | None = None) -> None:
        self.discovery_engine = engine
        self.session_intelligence = intelligence
        self._entries = entries or []
        self.graphql_tested_ops = {}

    def in_scope_entries(self):
        return list(self._entries)


# ── leads ─────────────────────────────────────────────────────────────────────
def test_leads_block_lists_focus_host_hypotheses():
    store = _FakeStore(engine=_Engine())
    block = leads_block(store, ["api.shop.test"])
    assert "App-context leads" in block
    assert "api.shop.test" in block
    assert "idor" in block
    assert "other.test" not in block  # focus filter drops non-focus hosts


def test_leads_block_empty_when_nothing_profiled():
    assert leads_block(_FakeStore(engine=_Engine()), ["unknown.test"]) == ""
    assert leads_block(_FakeStore(engine=None), ["api.shop.test"]) == ""
    assert leads_block(None, ["api.shop.test"]) == ""


# ── router ────────────────────────────────────────────────────────────────────
def test_router_block_recommends_llm_injection_for_ai_endpoint():
    # A captured POST to an LLM-completions path routes to llm_injection probing.
    store = _FakeStore(
        entries=[_FakeEntry(host="api.shop.test", path="/v1/chat/completions",
                            url="https://api.shop.test/v1/chat/completions")],
        intelligence=SessionIntelligence(),
    )
    block = router_block(store, ["api.shop.test"])
    assert block
    assert "llm_injection" in block


def test_router_block_empty_for_quiet_host():
    store = _FakeStore(intelligence=SessionIntelligence())
    assert router_block(store, ["api.shop.test"]) == ""


# ── coverage ──────────────────────────────────────────────────────────────────
def test_coverage_block_lists_outcomes_and_open_followups():
    coverage_ledger.reset()
    try:
        coverage_ledger.record_scan_outcome(
            "GET", "api.shop.test", "/api/orders/{id}", "", "idor",
            probe_count=12)  # ran clean → no_issue_found with evidence
        coverage_ledger.record(
            "GET", "api.shop.test", "/api/admin", "", "authz",
            "needs_follow_up", reason="401 on control probe")
        block = coverage_block(_FakeStore(), ["api.shop.test"])
        assert "UNEXAMINED" in block
        assert "no_issue_found: 1" in block
        assert "coverage_follow_ups" in block          # fenced (target-derived)
        assert "/api/admin authz" in block
    finally:
        coverage_ledger.reset()


def test_coverage_block_empty_without_rows():
    coverage_ledger.reset()
    try:
        assert coverage_block(_FakeStore(), ["api.shop.test"]) == ""
    finally:
        coverage_ledger.reset()


# ── combined ──────────────────────────────────────────────────────────────────
def test_guidance_blocks_joins_available_and_fails_open():
    coverage_ledger.reset()
    try:
        store = _FakeStore(engine=_Engine(), intelligence=SessionIntelligence())
        out = guidance_blocks(store, ["api.shop.test"])
        assert "App-context leads" in out      # leads present
        assert "UNEXAMINED" not in out         # ledger empty → coverage absent

        assert guidance_blocks(None, ["api.shop.test"]) == ""
        # Empty focus = no filter (same as the driver): every profile qualifies.
        all_hosts = guidance_blocks(_FakeStore(engine=_Engine()), [])
        assert "api.shop.test" in all_hosts and "other.test" in all_hosts
    finally:
        coverage_ledger.reset()

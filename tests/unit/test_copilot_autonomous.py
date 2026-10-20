"""
Unit tests for the autonomous Exploration Copilot orchestrator
(``CopilotService.run_autonomous`` + ``_drive_autonomous``).

The driver self-continues turns commanding the arsenal until a stop condition
trips. These tests mock the copilot engine's ``send`` so no LLM/network call
happens, and drive the loop deterministically to cover:

  * self-continue across turns (a plain reply is a checkpoint, not a stop),
  * each stop condition: self-declared complete, tool-call budget, wall-clock
    budget, stuck detector, and the operator kill switch,
  * a ``need_human`` escalation that pauses then resumes on operator guidance
    (continue / abort),
  * the scope/auth policy (auto-deny out of scope vs. serve the jar session).

The engine's ``send`` is patched on the live instance (an instance attribute is
returned as-is, so it is NOT bound as a method and receives no ``self``), which
lets a plain ``async def`` stand in and inspect the prompts the driver builds.
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Optional
from unittest.mock import AsyncMock

import pytest

from dast.proxy.api.copilot_service import CopilotService


class _Reply:
    """Stand-in for CopilotReply — only .message and .blocked_reason are read."""

    def __init__(self, message: str = "", blocked_reason: str = "") -> None:
        self.message = message
        self.blocked_reason = blocked_reason


class _Entry:
    def __init__(self, findings: Optional[List[dict]] = None) -> None:
        self.findings = findings or []


class _FakeStore:
    def __init__(self, entries: Optional[List[_Entry]] = None,
                 cookies: Optional[List[dict]] = None) -> None:
        self.ai_mode = False
        self._entries = entries if entries is not None else []
        self._cookies = cookies if cookies is not None else []

    def in_scope_entries(self) -> List[_Entry]:
        return self._entries

    def get_cookies_for_host(self, host: str) -> List[dict]:
        return self._cookies


class _FakeCtx:
    def __init__(self, store: Optional[_FakeStore] = None) -> None:
        self.proxy_port = 8080
        self.dashboard_port = 8088
        self.store = store if store is not None else _FakeStore()
        self.settings = None
        self.broadcast_copilot = AsyncMock()


async def _wait_for(predicate, timeout: float = 2.0) -> bool:
    """Poll until predicate() is truthy or the timeout elapses."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.005)
    return False


# ── run_autonomous basics ─────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_run_autonomous_requires_objective():
    service = CopilotService(_FakeCtx())
    with pytest.raises(ValueError):
        service.run_autonomous("   ")


@pytest.mark.asyncio
async def test_run_autonomous_enables_ai_mode_and_records_config():
    store = _FakeStore()
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("find BAC", focus_hosts=["Api.Example.com"],
                                 budget={"max_tool_calls": 42})
    session = service.get(sid)
    # Ambient auto-scan is turned on for the run.
    assert store.ai_mode is True
    auto = session["autonomous"]
    assert auto["objective"] == "find BAC"
    assert auto["hosts"] == ["api.example.com"]          # normalized lower-case
    assert auto["config"]["max_tool_calls"] == 42
    assert session["origin"] == "autonomous"
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)


@pytest.mark.asyncio
async def test_ai_mode_restored_to_prior_value_when_run_finishes():
    # The operator had AI mode OFF; the run turns it on for ambient scan, and it
    # must be restored to OFF when the run ends — not left permanently on.
    store = _FakeStore()
    assert store.ai_mode is False
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    assert store.ai_mode is True  # forced on for the run

    session["engine"].send = AsyncMock(side_effect=[_Reply("done", "complete")])
    await session["_task"]

    assert session["autonomous"]["status"] == "complete"
    assert store.ai_mode is False  # restored to the operator's prior setting


@pytest.mark.asyncio
async def test_ai_mode_left_on_if_operator_had_it_on():
    store = _FakeStore()
    store.ai_mode = True  # operator already had ambient scan enabled
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)

    session["engine"].send = AsyncMock(side_effect=[_Reply("done", "complete")])
    await session["_task"]

    assert store.ai_mode is True  # prior True preserved, not clobbered off


@pytest.mark.asyncio
async def test_run_autonomous_clamps_out_of_range_budget():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", budget={
        "max_tool_calls": 0, "max_wall_clock_seconds": 1, "max_stuck_turns": 0,
    })
    session = service.get(sid)
    cfg = session["autonomous"]["config"]
    assert cfg["max_tool_calls"] == 1                    # clamped up from 0
    assert cfg["max_wall_clock_seconds"] == 30           # clamped up from 1
    assert cfg["max_stuck_turns"] == 1                   # clamped up from 0
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)


# ── Stop conditions ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_driver_stops_on_self_declared_complete():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[_Reply("done", "complete")])
    await session["_task"]
    assert session["autonomous"]["status"] == "complete"
    assert session["engine"].send.await_count == 1


@pytest.mark.asyncio
async def test_driver_self_continues_then_completes():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 10})
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[
        _Reply("progress 1"), _Reply("progress 2"), _Reply("all done", "complete"),
    ])
    await session["_task"]
    assert session["autonomous"]["status"] == "complete"
    assert session["engine"].send.await_count == 3
    # Turn 1 is the autonomous preamble; later turns are continuation prompts.
    prompts = [c.args[0] for c in session["engine"].send.await_args_list]
    assert "AUTONOMOUS PENTEST" in prompts[0]
    assert "Continue autonomously" in prompts[1]


@pytest.mark.asyncio
async def test_driver_stops_on_tool_call_budget():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_tool_calls": 1, "max_stuck_turns": 99})
    session = service.get(sid)
    calls = {"n": 0}

    async def fake_send(text: str, tool_ctx: Any, *, on_event, wait_for_human) -> _Reply:
        calls["n"] += 1
        # Emit one tool-call step event so the driver's counter ticks.
        await on_event({"type": "step", "action": "call_tool", "step": calls["n"]})
        return _Reply("working")

    session["engine"].send = fake_send
    await session["_task"]
    assert session["autonomous"]["status"] == "stopped"
    assert "tool-call budget" in session["autonomous"]["detail"]
    # One turn ran (tool_calls hit 1), then the budget gate stopped the next.
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_driver_stops_on_wall_clock_budget():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    # The task has not run yet (no await since run_autonomous). Backdate the start
    # so the deadline is already in the past when the driver computes it.
    session["autonomous"]["started_at"] -= 100_000
    send = AsyncMock(side_effect=[_Reply("should not run")])
    session["engine"].send = send
    await session["_task"]
    assert session["autonomous"]["status"] == "stopped"
    assert "wall-clock" in session["autonomous"]["detail"]
    assert send.await_count == 0                         # stopped before any turn


@pytest.mark.asyncio
async def test_driver_stops_on_stuck_detector():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 2, "max_tool_calls": 999})
    session = service.get(sid)
    # Progress never changes (store stays empty), so every turn is "no progress".
    session["engine"].send = AsyncMock(side_effect=[_Reply("nothing new")] * 10)
    await session["_task"]
    assert session["autonomous"]["status"] == "stopped"
    assert "no progress" in session["autonomous"]["detail"]
    # Two turns run, then the stuck gate trips before the third.
    assert session["engine"].send.await_count == 2


@pytest.mark.asyncio
async def test_progress_resets_stuck_counter():
    store = _FakeStore()
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 2, "max_tool_calls": 999})
    session = service.get(sid)
    turn = {"n": 0}

    async def fake_send(text: str, tool_ctx: Any, *, on_event, wait_for_human) -> _Reply:
        turn["n"] += 1
        if turn["n"] == 2:
            # A new finding appears on turn 2 — progress, so stuck resets to 0.
            store._entries.append(_Entry(findings=[{"title": "x"}]))
        if turn["n"] >= 4:
            return _Reply("done", "complete")
        return _Reply("working")

    session["engine"].send = fake_send
    await session["_task"]
    # Turn 1 is stuck=1; turn 2's progress resets it to 0; turn 3 is stuck=1
    # again; turn 4 completes. Without the reset, the stuck gate (2) would have
    # fired before turn 3 ever ran.
    assert session["autonomous"]["status"] == "complete"
    assert turn["n"] == 4


# ── Operator controls ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_stop_autonomous_kills_the_run():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)

    async def slow_send(text: str, tool_ctx: Any, *, on_event, wait_for_human) -> _Reply:
        await asyncio.sleep(0.05)
        return _Reply("working")

    session["engine"].send = slow_send
    assert await _wait_for(lambda: session["autonomous"]["turns"] >= 1)
    assert service.stop_autonomous(sid) is True
    await asyncio.gather(session["_task"], return_exceptions=True)
    assert session["autonomous"]["status"] == "stopped"


@pytest.mark.asyncio
async def test_pause_and_resume_toggle_the_gate():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    auto = session["autonomous"]
    assert service.pause_autonomous(sid) is True
    assert auto["pause_gate"].is_set() is False
    assert auto["status"] == "paused"
    assert service.resume_autonomous(sid) is True
    assert auto["pause_gate"].is_set() is True
    assert auto["status"] == "running"
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)


@pytest.mark.asyncio
async def test_controls_return_false_for_non_autonomous_session():
    service = CopilotService(_FakeCtx())
    sid = service.new_session()                          # ordinary conversation
    assert service.stop_autonomous(sid) is False
    assert service.pause_autonomous(sid) is False
    assert service.resume_autonomous(sid) is False
    assert service.answer_guidance(sid, "x", "continue") is False


# ── need_human escalation (ask-and-continue) ──────────────────────────────────
@pytest.mark.asyncio
async def test_escalation_pauses_then_resumes_on_guidance():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 10})
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[
        _Reply("I need the admin token", "auth_required"),
        _Reply("done", "complete"),
    ])
    # Wait until the driver parks on a guidance escalation.
    assert await _wait_for(
        lambda: (session.get("pause") or {}).get("kind") == "guidance")
    assert service.answer_guidance(sid, "token is abc123", "continue") is True
    await session["_task"]
    assert session["autonomous"]["status"] == "complete"
    # The operator's answer is threaded into the next turn's prompt.
    second_prompt = session["engine"].send.await_args_list[1].args[0]
    assert "token is abc123" in second_prompt


@pytest.mark.asyncio
async def test_escalation_abort_stops_the_run():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 10})
    session = service.get(sid)
    send = AsyncMock(side_effect=[_Reply("blocked", "auth_required"),
                                  _Reply("should not reach", "complete")])
    session["engine"].send = send
    assert await _wait_for(
        lambda: (session.get("pause") or {}).get("kind") == "guidance")
    assert service.answer_guidance(sid, "", "abort") is True
    await session["_task"]
    assert session["autonomous"]["status"] == "stopped"
    assert "aborted" in session["autonomous"]["detail"]
    assert send.await_count == 1                         # never ran the second turn


@pytest.mark.asyncio
async def test_soft_escalation_auto_nudges_instead_of_pausing():
    # A soft escalation (need_human/need_value) in an autonomous run is the copilot
    # asking permission for a step it can take — the driver auto-nudges it to proceed
    # rather than pausing the operator. Here it "asks" once, is nudged, then completes
    # on the next turn WITHOUT ever parking on a guidance pause.
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"], budget={"max_stuck_turns": 10})
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[
        _Reply("can I scan the API next?", "need_human"),
        _Reply("done", "complete"),
    ])
    await session["_task"]
    assert session["autonomous"]["status"] == "complete"
    assert session.get("pause") is None                 # never paused the operator
    assert session["autonomous"]["auto_guidance_nudges"] >= 1
    # The nudge prompt pushed it to proceed autonomously.
    second_prompt = session["engine"].send.await_args_list[1].args[0]
    assert "not a genuine blocker" in second_prompt.lower() or "proceed" in second_prompt.lower()


@pytest.mark.asyncio
async def test_soft_escalation_pauses_after_nudge_budget_exhausted():
    # If the copilot keeps softly escalating without progress, the nudges run out and
    # it finally surfaces to the operator — a genuinely stuck loop is not hidden forever.
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"], budget={"max_stuck_turns": 50})
    session = service.get(sid)
    session["engine"].send = AsyncMock(
        side_effect=[_Reply("still unsure", "need_value")] * 10
    )
    assert await _wait_for(
        lambda: (session.get("pause") or {}).get("kind") == "guidance")
    # It took the full nudge budget before pausing.
    assert session["autonomous"]["auto_guidance_nudges"] == 3
    service.stop_autonomous(sid)
    await asyncio.gather(session["_task"], return_exceptions=True)


@pytest.mark.asyncio
async def test_answer_guidance_rejected_when_not_paused():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    # No guidance pause is active right after start.
    assert service.answer_guidance(sid, "x", "continue") is False
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)


# ── Scope / auth policy ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_policy_auto_denies_out_of_scope_without_escalation():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"allow_scope_escalation": False})
    session = service.get(sid)
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)
    wait = service._make_autonomous_wait(sid, session)
    result = await wait("approve", {"host": "evil.com", "url": "https://evil.com/"})
    assert result == {"decision": "deny"}


@pytest.mark.asyncio
async def test_policy_serves_jar_session_on_auth_wall():
    store = _FakeStore(cookies=[{"name": "session", "value": "s3cr3t"},
                                {"name": "csrf", "value": "tok"}])
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"allow_scope_escalation": False})
    session = service.get(sid)
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)
    wait = service._make_autonomous_wait(sid, session)
    result = await wait("auth", {"host": "app.example.com",
                                 "url": "https://app.example.com/"})
    assert result == {"cookies": {"session": "s3cr3t", "csrf": "tok"}}


@pytest.mark.asyncio
async def test_policy_escalates_scope_when_enabled():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"allow_scope_escalation": True})
    session = service.get(sid)
    session["_task"].cancel()
    await asyncio.gather(session["_task"], return_exceptions=True)
    wait = service._make_autonomous_wait(sid, session)

    # With escalation enabled, an out-of-scope host parks on an approve pause.
    task = asyncio.create_task(
        wait("approve", {"host": "evil.com", "url": "https://evil.com/"}))
    assert await _wait_for(
        lambda: (session.get("pause") or {}).get("kind") == "approve")
    session["_pause_result"] = {"decision": "allow_once"}
    session["_pause_event"].set()
    result = await task
    assert result == {"decision": "allow_once"}


# ── Tool-first + pentester prompts, and app-context leads feed ──────────────────
class _FakeProfile:
    """Stand-in for AppProfile — only to_coordinator_hint() is read by _leads_label."""

    def __init__(self, hint: str) -> None:
        self._hint = hint

    def to_coordinator_hint(self) -> str:
        return self._hint


class _FakeDiscoveryEngine:
    def __init__(self, profiles: Optional[dict] = None, raises: bool = False) -> None:
        self._profiles = profiles or {}
        self._raises = raises

    def all_app_profiles(self) -> dict:
        if self._raises:
            raise RuntimeError("discovery engine unavailable")
        return self._profiles


class _StoreWithProfiles(_FakeStore):
    def __init__(self, profiles: Optional[dict] = None, raises: bool = False,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.discovery_engine = _FakeDiscoveryEngine(profiles, raises=raises)


def _service_with_profiles(profiles: Optional[dict] = None,
                           raises: bool = False) -> CopilotService:
    return CopilotService(_FakeCtx(_StoreWithProfiles(profiles=profiles, raises=raises)))


@pytest.mark.asyncio
async def test_start_prompt_mandates_internal_tools_and_active_testing():
    service = CopilotService(_FakeCtx())
    sid = service.run_autonomous("obj", focus_hosts=["h"])
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[_Reply("done", "complete")])
    await session["_task"]
    start = session["engine"].send.await_args_list[0].args[0]
    # Tool-first mandate — drive Frieren's own instruments, not raw HTTP.
    assert "USE THE INTERNAL TOOLS" in start
    assert "graphql_introspect" in start
    assert "run_scan" in start
    # Pentester-not-reader mandate — form hypotheses and actively TEST them.
    assert "BE A PENTESTER" in start
    assert "IDOR" in start


def test_leads_label_nudge_when_no_profiles():
    label = _service_with_profiles({})._leads_label(["h"])
    assert "none from app-context analysis yet" in label


def test_leads_label_survives_discovery_error():
    # A broken discovery engine must never crash the run — degrade to the nudge.
    label = _service_with_profiles(raises=True)._leads_label(["h"])
    assert "none from app-context analysis yet" in label


def test_leads_label_returns_hint_for_focus_host():
    service = _service_with_profiles(
        {"api.example.com": _FakeProfile("HIGH: IDOR on /lx/profile — swap user id")})
    label = service._leads_label(["api.example.com"])
    assert "chase and TEST" in label
    assert "HIGH: IDOR on /lx/profile — swap user id" in label
    assert "[api.example.com]" in label


def test_leads_label_filters_out_non_focus_hosts():
    service = _service_with_profiles({
        "api.example.com": _FakeProfile("in-focus lead"),
        "other.example.com": _FakeProfile("off-focus lead"),
    })
    label = service._leads_label(["api.example.com"])
    assert "in-focus lead" in label
    assert "off-focus lead" not in label


@pytest.mark.asyncio
async def test_app_context_leads_are_injected_into_start_and_continue_prompts():
    store = _StoreWithProfiles({"h": _FakeProfile("HIGH: BOLA on /users/{id}")})
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("obj", focus_hosts=["h"],
                                 budget={"max_stuck_turns": 10})
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[
        _Reply("progress"), _Reply("done", "complete")])
    await session["_task"]
    prompts = [c.args[0] for c in session["engine"].send.await_args_list]
    assert "HIGH: BOLA on /users/{id}" in prompts[0]      # start prompt carries leads
    assert "HIGH: BOLA on /users/{id}" in prompts[1]      # continuation carries them too


# ── complete-mode: UI-route coverage dimension ───────────────────────────────

from dast.proxy.ui_route_graph import UiRouteGraph, normalise_route_key  # noqa: E402


class _UiStore(_FakeStore):
    """FakeStore that also carries a real UI-route graph (and no GraphQL)."""

    def __init__(self, entries=None, cookies=None):
        super().__init__(entries, cookies)
        self.ui_route_graph = UiRouteGraph()


def test_surface_coverage_incomplete_while_ui_frontier_nonempty():
    store = _UiStore()
    store.ui_route_graph.add_discovered("https://app.example.com/dashboard")
    service = CopilotService(_FakeCtx(store))
    cov = service._surface_coverage(["app.example.com"])
    assert cov["has_surface"] is True          # a discovered route is surface
    assert cov["ui_total"] == 1 and cov["ui_visited"] == 0
    assert cov["ui_frontier"]                   # non-empty
    assert cov["complete"] is False             # frontier not drained


@pytest.mark.asyncio
async def test_run_autonomous_defers_identity_then_restores():
    store = _FakeStore()
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("obj", focus_hosts=["app.example.com"])
    # Deferral is armed synchronously at run start.
    assert store.defer_identity_hosts is True
    session = service.get(sid)
    session["engine"].send = AsyncMock(side_effect=[_Reply("done", "complete")])
    await session["_task"]
    # ...and lifted when the run ends, so it never leaks into manual use.
    assert store.defer_identity_hosts is False


def test_surface_coverage_excludes_deferred_identity_hosts():
    store = _UiStore()
    store.ui_route_graph.add_discovered("https://app.example.com/dashboard")
    store.ui_route_graph.add_discovered("https://login.identity.example.com/signin")
    service = CopilotService(_FakeCtx(store))
    hosts = ["app.example.com", "login.identity.example.com"]

    store.defer_identity_hosts = True
    cov = service._surface_coverage(hosts)
    assert cov["ui_total"] == 1          # IdP route excluded while deferred

    store.defer_identity_hosts = False
    cov2 = service._surface_coverage(hosts)
    assert cov2["ui_total"] == 2         # both counted once deferral is lifted


@pytest.mark.asyncio
async def test_final_identity_phase_lifts_deferral_and_runs_once():
    store = _FakeStore()
    service = CopilotService(_FakeCtx(store))
    store.defer_identity_hosts = True
    session = {"autonomous": {"hosts": ["app.example.com"], "read_only": True,
                              "stop_event": asyncio.Event()}}
    await service._final_identity_phase("sid", session)
    assert store.defer_identity_hosts is False
    assert session["autonomous"]["identity_phase_done"] is True


def test_surface_coverage_complete_when_frontier_drained():
    store = _UiStore()
    store.ui_route_graph.add_discovered("https://app.example.com/dashboard")
    store.ui_route_graph.mark_visited(normalise_route_key("https://app.example.com/dashboard"))
    service = CopilotService(_FakeCtx(store))
    cov = service._surface_coverage(["app.example.com"])
    assert cov["ui_total"] == 1 and cov["ui_visited"] == 1
    assert cov["ui_frontier"] == []
    assert cov["complete"] is True              # no REST/GQL/UI gaps


def test_progress_snapshot_advances_on_ui_discovery():
    store = _UiStore()
    service = CopilotService(_FakeCtx(store))
    before = service._progress_snapshot()
    store.ui_route_graph.add_discovered("https://app.example.com/new-route")
    after = service._progress_snapshot()
    assert len(after) == 4
    assert after != before                      # discovery alone counts as progress


@pytest.mark.asyncio
async def test_complete_mode_defaults_raise_budget_and_record_mode():
    store = _UiStore()
    service = CopilotService(_FakeCtx(store))
    # Avoid the up-front explore + driver doing real work: no hosts, and stop fast.
    sid = service.run_autonomous("map everything", focus_hosts=[], mode="complete",
                                 submit_forms=True, read_only=True, auto_ai_mode=False)
    auto = service._sessions[sid]["autonomous"]
    assert auto["mode"] == "complete"
    # submit_forms is forced off under read_only.
    assert auto["submit_forms"] is False
    assert auto["config"]["max_tool_calls"] == 2000
    assert auto["config"]["max_wall_clock_seconds"] == 86400
    service.stop_autonomous(sid)


@pytest.mark.asyncio
async def test_complete_mode_submit_forms_kept_when_active():
    store = _UiStore()
    service = CopilotService(_FakeCtx(store))
    sid = service.run_autonomous("pentest", focus_hosts=[], mode="complete",
                                 submit_forms=True, read_only=False, auto_ai_mode=False)
    assert service._sessions[sid]["autonomous"]["submit_forms"] is True
    service.stop_autonomous(sid)


# ── effective-host expansion (focus host -> all in-scope hosts in traffic) ──────
class _HostEntry:
    def __init__(self, host: str) -> None:
        self.host = host


def test_effective_hosts_expands_to_in_scope_subdomains():
    # Operator typed only the SPA host; the real API lives on sibling subdomains
    # whose traffic is already captured in scope. The working set must include them.
    store = _FakeStore(entries=[
        _HostEntry("console.example.com"),
        _HostEntry("api.console.example.com"),
        _HostEntry("bff.console.example.com:443"),   # port stripped
        _HostEntry("api.console.example.com"),        # dup collapsed
    ])
    service = CopilotService(_FakeCtx(store))
    assert service._effective_hosts(["console.example.com"]) == [
        "api.console.example.com", "bff.console.example.com", "console.example.com",
    ]


def test_effective_hosts_includes_focus_even_without_traffic():
    service = CopilotService(_FakeCtx(_FakeStore(entries=[])))
    assert service._effective_hosts(["Only.Focus.Com:8443"]) == ["only.focus.com"]


def test_effective_hosts_degrades_when_store_missing():
    ctx = _FakeCtx()
    ctx.store = None
    service = CopilotService(ctx)
    assert service._effective_hosts(["h.example.com"]) == ["h.example.com"]


def test_effective_hosts_survives_enumeration_error():
    class _RaisingStore(_FakeStore):
        def in_scope_entries(self):
            raise RuntimeError("boom")

    service = CopilotService(_FakeCtx(_RaisingStore()))
    # Falls back to the focus hosts rather than crashing the run.
    assert service._effective_hosts(["h.example.com"]) == ["h.example.com"]


def test_effective_hosts_puts_identity_providers_last():
    # Probing the IdP kills the shared SSO session, so identity/login hosts must be
    # ordered after the rest of the surface — the sweep then tests them last.
    store = _FakeStore(entries=[
        _HostEntry("identity.example.com"),
        _HostEntry("login.sso.example.com"),
        _HostEntry("api.example.com"),
        _HostEntry("app.example.com"),
    ])
    service = CopilotService(_FakeCtx(store))
    ordered = service._effective_hosts(["app.example.com"])
    assert ordered == [
        "api.example.com", "app.example.com",       # non-IdP first, alphabetical
        "identity.example.com", "login.sso.example.com",  # IdP hosts last
    ]

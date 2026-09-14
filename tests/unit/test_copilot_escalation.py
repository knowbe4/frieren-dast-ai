"""
Unit tests for WAF-block escalation into the Exploration Copilot (phase 2).

Covers the two seams that let the scanner hand a WAF-disabled attack type to the
conversational agent instead of silently dropping it:

  * ``_waf_suppressed_attack_types`` (dast/ai/coordinator.py) — deterministic
    selection of the attack types the coordinator would otherwise disable.
  * ``CopilotService.escalate_block`` (dast/proxy/api/copilot_service.py) — the
    in-process sink that seeds a new conversation, deduped per (host, attack_type).

The copilot engine's ``send`` is mocked so no LLM/network call happens.
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import AsyncMock, patch

import pytest

from dast.ai.coordinator import _WAF_BLOCK_DISABLE_THRESHOLD, _waf_suppressed_attack_types
from dast.ai.session_intelligence import SessionIntelligence
from dast.proxy.api.copilot_service import CopilotService


def _host_with_blocks(host: str, blocks: Dict[str, int],
                      effective: Any = None) -> Any:
    """Build a HostIntel whose waf_observations carry the given per-type counts."""
    intel = SessionIntelligence().get(host)
    for attack_type, count in blocks.items():
        for _ in range(count):
            intel.waf_observations.append(("payload", "403 blocked by waf", attack_type))
    if effective:
        intel.effective_attack_types.update(effective)
    return intel


# ── _waf_suppressed_attack_types ────────────────────────────────────────────────
def test_suppressed_types_returns_only_types_over_threshold():
    intel = _host_with_blocks("h", {"sqli": _WAF_BLOCK_DISABLE_THRESHOLD,
                                     "xss": _WAF_BLOCK_DISABLE_THRESHOLD - 1})
    assert _waf_suppressed_attack_types(intel) == ["sqli"]


def test_suppressed_types_excludes_effective_types():
    intel = _host_with_blocks("h", {"sqli": _WAF_BLOCK_DISABLE_THRESHOLD + 3},
                              effective={"sqli"})
    assert _waf_suppressed_attack_types(intel) == []


def test_suppressed_types_none_host_intel():
    assert _waf_suppressed_attack_types(None) == []


def test_suppressed_types_sorted_and_deduped():
    intel = _host_with_blocks("h", {"xss": _WAF_BLOCK_DISABLE_THRESHOLD,
                                     "sqli": _WAF_BLOCK_DISABLE_THRESHOLD})
    assert _waf_suppressed_attack_types(intel) == ["sqli", "xss"]


# ── CopilotService.escalate_block ────────────────────────────────────────────────
class _FakeCtx:
    def __init__(self) -> None:
        self.proxy_port = 8080
        self.dashboard_port = 8088
        self.store = object()
        self.settings = None
        self.broadcast_copilot = AsyncMock()


@pytest.mark.asyncio
async def test_escalate_block_seeds_session_and_dedupes():
    ctx = _FakeCtx()
    service = CopilotService(ctx)
    intel = _host_with_blocks("api.example.com", {"sqli": _WAF_BLOCK_DISABLE_THRESHOLD})

    # Mock the engine so scheduling the turn does not touch the LLM.
    with patch("dast.ai.copilot.session.CopilotSession.send",
               new=AsyncMock(return_value=None)):
        sid = service.escalate_block("api.example.com", "sqli", intel)
        assert sid is not None
        session = service.get(sid)
        assert session["origin"] == "block_escalation"
        assert session["escalation"]["host"] == "api.example.com"
        assert session["escalation"]["attack_type"] == "sqli"
        # The seeded escalation signal comes from the latest matching observation.
        assert "blocked by waf" in session["escalation"]["signal"]

        # Same (host, attack_type) does not open a second conversation.
        assert service.escalate_block("api.example.com", "sqli", intel) is None
        # A different attack type on the same host does escalate.
        other = service.escalate_block("api.example.com", "xss", intel)
        assert other is not None and other != sid

        # Clean up scheduled turns before the loop closes.
        for candidate in (sid, other):
            task = service.get(candidate).get("_task")
            if task:
                task.cancel()


@pytest.mark.asyncio
async def test_escalate_block_scheduling_failure_is_retryable():
    """A transient scheduling failure must not permanently suppress the pair:
    the dedup mark is only set after the turn is scheduled, and the half-built
    session is dropped."""
    ctx = _FakeCtx()
    service = CopilotService(ctx)
    intel = _host_with_blocks("h", {"sqli": _WAF_BLOCK_DISABLE_THRESHOLD})

    with patch.object(CopilotService, "start_turn", side_effect=RuntimeError("no loop")):
        assert service.escalate_block("h", "sqli", intel) is None
    assert service._escalated == set()          # pair not marked
    assert service.list_summaries() == []       # half-built session removed

    # With scheduling working again, the same pair still escalates.
    with patch("dast.ai.copilot.session.CopilotSession.send",
               new=AsyncMock(return_value=None)):
        sid = service.escalate_block("h", "sqli", intel)
        assert sid is not None
        task = service.get(sid).get("_task")
        if task:
            task.cancel()


@pytest.mark.asyncio
async def test_escalate_block_without_observations_still_escalates():
    """A host_intel with no matching WAF observation escalates with an empty
    signal (the seeded message falls back to a placeholder), never crashing."""
    ctx = _FakeCtx()
    service = CopilotService(ctx)
    intel = SessionIntelligence().get("h")  # no waf_observations at all

    with patch("dast.ai.copilot.session.CopilotSession.send",
               new=AsyncMock(return_value=None)):
        sid = service.escalate_block("h", "sqli", intel)
        assert sid is not None
        assert service.get(sid)["escalation"]["signal"] == ""
        task = service.get(sid).get("_task")
        if task:
            task.cancel()


@pytest.mark.asyncio
async def test_escalate_block_seeds_operator_message():
    ctx = _FakeCtx()
    service = CopilotService(ctx)
    intel = _host_with_blocks("h", {"lfi": _WAF_BLOCK_DISABLE_THRESHOLD})

    with patch("dast.ai.copilot.session.CopilotSession.send",
               new=AsyncMock(return_value=None)) as mock_send:
        sid = service.escalate_block("h", "lfi", intel)
        task = service.get(sid).get("_task")
        assert task is not None
        await task  # let _run_turn call engine.send once
        assert mock_send.await_count == 1
        seeded_text = mock_send.await_args.args[0]
        assert "lfi" in seeded_text and "h" in seeded_text

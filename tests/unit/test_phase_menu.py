"""Unit tests for the phase-aware tool menu (5-C-3).

Pure-function tests over ``infer_phase`` and ``_render_phased_menu`` plus a
drift guard: the phase buckets must cover (nearly) the whole registry, or new
tools silently fall out of every phase's priority list.
"""

from __future__ import annotations

from dast.ai.copilot.session import (
    _ALWAYS_PRIORITY,
    _FULL_MENU_TOOL_COUNT,
    _TOOL_PHASES,
    _render_phased_menu,
    _render_tool_menu,
    infer_phase,
)
from dast.tools.base import all_tools


# ── infer_phase ──────────────────────────────────────────────────────────────

def test_phase_from_recent_tools():
    assert infer_phase(["crawl", "explore"]) == "recon"
    assert infer_phase(["run_scan", "sqli_probe"]) == "scan"
    # the MOST RECENT call carries double weight: record_finding last -> report,
    # send_request last after a record -> back to escalation.
    assert infer_phase(["send_request", "record_finding"]) == "report"
    assert infer_phase(["record_finding", "send_request"]) == "escalate"
    assert infer_phase([]) is None
    assert infer_phase(["totally_unknown_tool"]) is None


def test_phase_recency_dominates():
    """An escalation call after a recon burst pivots the phase — the stuck-loop
    escape hatch (prove it or rule it out) must win."""
    burst = ["crawl", "crawl", "explore", "get_history"]
    assert infer_phase(burst + ["attack_finding"]) == "escalate"
    assert infer_phase(["sqli_probe", "run_scan", "record_coverage"]) == "report"


# ── the phased rendering ─────────────────────────────────────────────────────

def _big_menu():
    return [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema}
        for t in all_tools() if "copilot" not in (t.tags or [])
    ]


def test_small_registry_renders_full_menu():
    small = _big_menu()[:_FULL_MENU_TOOL_COUNT]
    text = _render_phased_menu(small, "scan")
    assert "Current phase:" not in text      # full menu is the clean menu here
    assert text == _render_tool_menu(small)


def test_phased_menu_prioritizes_current_phase():
    menu = _big_menu()
    assert len(menu) > _FULL_MENU_TOOL_COUNT
    text = _render_phased_menu(menu, "scan")
    assert "Current phase: SCAN" in text
    # scan-phase tools render with descriptions
    assert "- run_scan:" in text
    assert "- sqli_probe:" in text
    # escalation core stays fully rendered in every phase
    for name in _ALWAYS_PRIORITY:
        assert f"- {name}:" in text
    # off-phase tools compress to the compact line
    assert "Also available" in text
    assert "- crawl:" not in text            # recon tool demoted to the name line
    assert "crawl" in text                   # ...but still discoverable


def test_phase_none_renders_full_menu():
    menu = _big_menu()
    assert _render_phased_menu(menu, None) == _render_tool_menu(menu)


# ── drift guard ──────────────────────────────────────────────────────────────

def test_phase_buckets_cover_the_registry():
    """Every non-copilot tool must live in at least one phase bucket — a new
    tool registered without a phase silently falls out of every priority list
    and only ever appears in the compact line."""
    registered = {t.name for t in all_tools() if "copilot" not in (t.tags or [])}
    covered = set().union(*_TOOL_PHASES.values())
    missing = registered - covered
    assert not missing, f"tools without a phase bucket: {sorted(missing)}"

"""Project-context briefing for the Exploration Copilot.

The copilot's turn prompt otherwise carries only the conversation and the tool
menu, so it begins an analysis blind to what the scanner already learned about
the target. This module assembles a compact, per-host brief — the app-context
profile plus accumulated session intelligence (app/auth model, WAF blocks,
attack types already proven effective or dead) — so the agent understands the
endpoint before it acts (CLAUDE.md rule 7) instead of re-deriving everything from
scratch or re-firing payloads a WAF already blocks.

It reuses the very summaries the coordinator already trusts
(``AppProfile.to_coordinator_hint`` and ``HostIntel.to_planner_hint``), so the
copilot and the scanner reason from the same ground truth. Kept out of
``session.py`` so the concern is isolated and independently testable; the engine
reaches it with the ``store`` it already receives on ``tool_ctx``, so ``dast.ai``
never imports the dashboard.
"""

from __future__ import annotations

from typing import Any, List, Sequence

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Bound how many hosts and how much text the brief carries so a long-lived
# session cannot blow the model's context budget with accumulated intelligence.
_MAX_BRIEF_HOSTS = 3
_MAX_BRIEF_CHARS = 4000


def _host_block(store: Any, host: str) -> str:
    """One host's brief, or "" if the store has nothing to say. Never raises —
    a lookup failure on one host must not break the copilot turn."""
    try:
        parts: List[str] = []

        engine = getattr(store, "discovery_engine", None)
        profile = engine.get_app_profile(host) if engine is not None else None
        if profile is not None:
            hint = profile.to_coordinator_hint()
            if hint:
                parts.append(hint)

        intelligence = getattr(store, "session_intelligence", None)
        intel = intelligence.peek(host) if intelligence is not None else None
        if intel is not None:
            hint = intel.to_planner_hint("", [])
            if hint:
                parts.append(hint)

        if not parts:
            return ""
        return f"Host {host}:\n" + "\n".join(parts)
    except Exception as exc:
        logger.warning("copilot context brief failed for host", host=host, error=str(exc))
        return ""


def _named_sessions_block() -> str:
    """Compact block listing login profiles that have a saved session.
    Each line includes the privilege level so the copilot can reason about
    which session to use for privilege-escalation tests. Returns "" when no
    profiles with sessions exist. Never raises."""
    try:
        from dast.profiles.store import list_profiles
        profiles = [p for p in list_profiles() if p.saved_session]
    except Exception as exc:
        logger.warning("context brief: could not load login profiles", error=str(exc))
        return ""
    if not profiles:
        return ""
    lines = []
    for p in profiles:
        level = p.privilege_level or "unset"
        host = p.host_pattern or "(no host)"
        lines.append(f"  - {p.name} (slug={p.slug}, privilege={level}, host={host})")
    return "Named sessions with saved credentials:\n" + "\n".join(lines)


def build_context_brief(
    store: Any,
    hosts: Sequence[str],
    *,
    max_hosts: int = _MAX_BRIEF_HOSTS,
) -> str:
    """Assemble a compact, per-host project-context brief for the copilot turn.

    ``hosts`` is de-duplicated and lowercased, preserving order, and capped at
    ``max_hosts``. Returns "" when there is no store, no hosts, or nothing the
    scanner has learned about them. Never raises.
    """
    if store is None or not hosts:
        return ""

    ordered: List[str] = []
    for raw in hosts:
        host = (raw or "").strip().lower()
        if host and host not in ordered:
            ordered.append(host)
        if len(ordered) >= max_hosts:
            break

    blocks = [block for block in (_host_block(store, host) for host in ordered) if block]

    sessions_block = _named_sessions_block()
    if sessions_block:
        blocks.append(sessions_block)

    if not blocks:
        return ""

    brief = "\n\n".join(blocks)
    if len(brief) > _MAX_BRIEF_CHARS:
        brief = brief[:_MAX_BRIEF_CHARS] + "\n... (context truncated)"
    return brief

"""Reusable copilot prompt blocks — app-context leads, evidence router, coverage.

The autonomous driver (``copilot_service``) has always injected these blocks
into its turn templates; the INTERACTIVE step prompt did not, so a chat session
got none of the routing intelligence the driver took for granted. The builders
were extracted here as PURE functions of ``(store, hosts)`` so both callers
share one implementation and neither imports the other (``copilot_service``
pulls the dashboard layer; ``session.py`` must not).

All builders fail-open to "" — a missing block is a byte saving for the prompt,
never an error. Content derived from observed target traffic (endpoint paths,
risk-area names) is attacker-influenceable, so it is fenced with
``prompt_safety.wrap_untrusted`` where it is interpolated.
"""

from __future__ import annotations

from typing import Any, List, Sequence

from dast.ai.prompt_safety import wrap_untrusted
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_LEAD_PROFILES = 3
_MAX_FOLLOW_UP_LINES = 6


def _host_names(hosts: Sequence[str]) -> set:
    """Focus set as bare lowercase hostnames ('host:port' tolerated)."""
    return {h.split(":")[0].lower() for h in (hosts or []) if h}


def leads_block(store: Any, hosts: Sequence[str]) -> str:
    """App-context leads for the focus hosts — concrete vuln hypotheses from the
    discovery engine's profiles, so the copilot chases them ITSELF instead of
    asking the operator. "" when nothing is profiled yet."""
    if store is None:
        return ""
    try:
        profiles = store.discovery_engine.all_app_profiles()
    except Exception as exc:  # noqa: BLE001 — leads are best-effort
        logger.debug("leads block unavailable", error=str(exc))
        return ""
    focus = _host_names(hosts)
    blocks: List[str] = []
    for host, profile in profiles.items():
        if focus and host.split(":")[0].lower() not in focus:
            continue
        try:
            hint = profile.to_coordinator_hint()
        except Exception as exc:  # noqa: BLE001
            logger.debug("lead hint unavailable", host=host, error=str(exc))
            continue
        if hint:
            blocks.append(f"[{host}]\n{hint}")
    if not blocks:
        return ""
    return "App-context leads — chase and TEST these first:\n" + "\n\n".join(
        blocks[:_MAX_LEAD_PROFILES])


def router_block(store: Any, hosts: Sequence[str]) -> str:
    """Evidence-driven 'recommended next actions / AVOID' block — deterministic
    routing from observed signals (id → sqli/idor, AI endpoint → llm_injection,
    MySQL → avoid MSSQL, GraphQL → sweep) that shrinks as things get tested.
    "" when there is nothing to recommend yet."""
    if store is None:
        return ""
    try:
        from dast.ai.evidence_router import RouterEvidence, route
        parts: List[str] = []
        for host in _host_names(hosts):
            plan = route(RouterEvidence.from_store(store, host))
            block = plan.to_prompt_block()
            if block:
                parts.append(block)
        return "\n\n".join(parts)
    except Exception as exc:  # noqa: BLE001 — routing is advisory
        logger.debug("router block unavailable", error=str(exc))
        return ""


def coverage_block(store: Any, hosts: Sequence[str]) -> str:
    """Coverage-ledger block for the focus hosts — what has already been
    recorded per host (reported / cleared) and which follow-ups are still open.
    Reminds the central invariant: a risk class with NO entry is UNEXAMINED,
    never clean. "" when the ledger has no rows for any focus host."""
    try:
        from dast.coverage.ledger import snapshot
        snap = snapshot()
    except Exception as exc:  # noqa: BLE001
        logger.debug("coverage block unavailable", error=str(exc))
        return ""
    focus = _host_names(hosts)
    rows = [(h, d) for h, d in snap.get("hosts", {}).items()
            if not focus or h.split(":")[0].lower() in focus]
    if not rows:
        return ""
    lines: List[str] = [
        "Coverage ledger — outcomes already recorded on this run. A risk class "
        "with no entry here is UNEXAMINED, not clean:"]
    for host, data in rows[:_MAX_LEAD_PROFILES]:
        outcomes = data.get("outcomes") or {}
        hist = ", ".join(f"{k}: {v}" for k, v in sorted(outcomes.items()))
        line = f"- {host}: {data.get('entries', 0)} outcome(s)"
        if hist:
            line += f" ({hist})"
        lines.append(line)
        follow_ups = data.get("needs_follow_up") or []
        if follow_ups:
            lines.append(
                "  open follow-ups (finish these): "
                + wrap_untrusted(", ".join(follow_ups[:_MAX_FOLLOW_UP_LINES]),
                                 "coverage_follow_ups"))
    return "\n".join(lines)


def guidance_blocks(store: Any, hosts: Sequence[str]) -> str:
    """All guidance blocks joined — the one call the interactive turn makes.
    "" when no block has anything to say (prompt stays byte-identical)."""
    parts = [b for b in (
        leads_block(store, hosts),
        router_block(store, hosts),
        coverage_block(store, hosts),
    ) if b]
    return "\n\n".join(parts)

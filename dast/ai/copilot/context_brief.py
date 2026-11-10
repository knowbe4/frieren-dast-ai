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
    """Compact block listing login profiles the copilot can use.

    Includes profiles with a saved browser session AND credential-only profiles
    (no captured session yet) — the orchestrator logs the latter in on demand, so
    the copilot must know they exist. Each line notes privilege, host, and whether
    a session is already captured. Returns "" when no usable profiles exist. Never
    raises."""
    try:
        from dast.profiles.store import list_profiles
        profiles = [p for p in list_profiles() if p.saved_session or p.credentials]
    except Exception as exc:
        logger.warning("context brief: could not load login profiles", error=str(exc))
        return ""
    if not profiles:
        return ""
    lines = []
    for p in profiles:
        level = p.privilege_level or "unset"
        host = p.host_pattern or "(no host)"
        captured = ("session captured" if p.saved_session
                    else "credentials only (logs in on use)")
        lines.append(f"  - {p.name} (slug={p.slug}, privilege={level}, host={host}, {captured})")
    return "Named login profiles available:\n" + "\n".join(lines)


def _scope_hosts_block(store: Any) -> str:
    """List the in-scope hosts from proxy settings so the copilot knows which
    targets to use without being told explicitly each session."""
    try:
        settings = getattr(store, "_settings", None)
        if settings is None:
            return ""
        get_hosts = getattr(settings, "get_scope_hosts", None)
        if get_hosts is None:
            return ""
        hosts = get_hosts()
        if not hosts:
            return ""
        return ("Target hosts in scope: " + ", ".join(hosts) + ". "
                "ALWAYS use these hosts for requests. NEVER use placeholder hostnames "
                "(example.com, localhost, unknown). If you need a URL and are unsure of "
                "the host, check get_history for real URLs the operator has visited.")
    except Exception as exc:
        logger.warning("context brief: could not read scope hosts", error=str(exc))
        return ""


def _app_knowledge_block(host: str) -> str:
    """Facts Frieren has learned about this app (auth model, where tokens live,
    endpoints, entitlements) from the local ~/.dast-ai/app_knowledge store. Derived from
    target responses, so the caller keeps the untrusted fencing. Returns "" if none."""
    try:
        from dast.app_knowledge.store import load_for_host
        note = (load_for_host(host) or "").strip()
    except Exception as exc:
        logger.warning("context brief: app-knowledge load failed", host=host, error=str(exc))
        return ""
    return f"## App knowledge — {host}\n{note}" if note else ""


def _transport_capability_block(host: str) -> str:
    """The transport (API vs browser session) Frieren has learned works for this host/sub-apps,
    from the local ~/.dast-ai/transport_capability store. A hint only — the copilot's auto
    API->browser fallback is the guarantee; this just lets it pick the right transport up front.
    Returns "" when nothing is learned for the host."""
    try:
        from dast.session.transport_capability import capability_for
        rec = capability_for(host)
    except Exception as exc:
        logger.warning("context brief: transport-capability load failed",
                       host=host, error=str(exc))
        return ""
    if not rec:
        return ""
    sub_app = rec.get("sub_app") or "(host)"
    reason = f" ({rec.get('reason')})" if rec.get("reason") else ""
    return (f"## Transport capability — {host}\n"
            f"- {sub_app}: prefer {rec.get('prefer')} (works: {rec.get('auth')}){reason}")


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

    blocks: List[str] = []

    scope_block = _scope_hosts_block(store)
    if scope_block:
        blocks.append(scope_block)

    ordered: List[str] = []
    for raw in hosts:
        host = (raw or "").strip().lower()
        if host and host not in ordered:
            ordered.append(host)
        if len(ordered) >= max_hosts:
            break

    host_blocks = [block for block in (_host_block(store, host) for host in ordered) if block]
    blocks.extend(host_blocks)

    # Locally-learned per-host app knowledge (auth model, token locations, entitlements).
    knowledge_blocks = [b for b in (_app_knowledge_block(host) for host in ordered) if b]
    blocks.extend(knowledge_blocks)

    # Locally-learned per-host transport preference (API vs browser session).
    transport_blocks = [b for b in (_transport_capability_block(host) for host in ordered) if b]
    blocks.extend(transport_blocks)

    sessions_block = _named_sessions_block()
    if sessions_block:
        blocks.append(sessions_block)

    if not blocks:
        return ""

    brief = "\n\n".join(blocks)
    if len(brief) > _MAX_BRIEF_CHARS:
        brief = brief[:_MAX_BRIEF_CHARS] + "\n... (context truncated)"
    return brief

"""
CopilotService — in-process owner of Exploration Copilot conversations.

The HTTP surface (``copilot_routes.py``) is a thin adapter over this service:
it owns the session store, the per-turn runner (with its approve/auth pause
plumbing), and — the reason it is a service and not a routes closure — an
in-process ``escalate_block`` entry point.

``escalate_block`` is how the scanner hands a WAF-disabled attack type to the
conversational agent instead of silently dropping it. The coordinator has no
handle to the dashboard, so it reaches the copilot through an injected callback
on ``SessionIntelligence.escalation_sink`` (wired in ``dashboard_server``); that
callback is this method. Keeping the coupling one-directional (dashboard depends
on ``dast.ai``, never the reverse) is why the coordinator only ever sees a plain
callable, not this class.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

from dast.proxy.api.agent_triage_routes import AgentToolContext
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.api.context import DashboardContext

logger = get_logger(__name__)

_MAX_SESSIONS = 50

# Human-in-the-loop pause budgets, matching the triage surface: approve bounds a
# quick decision; auth allows time to open a browser and log in.
_APPROVE_TIMEOUT_SECONDS = 120.0
_AUTH_TIMEOUT_SECONDS = 300.0

# Seeded operator message for an automated block escalation. Framed as an
# explicit scanner notice so the copilot knows the origin, but still delivered
# through the untrusted-operator channel (the block signature is response-derived
# content), so the engine's prompt-injection fencing still applies.
_ESCALATION_TEMPLATE = (
    "Automated escalation from the scanner. While scanning host {host}, the "
    "'{attack_type}' attack type was blocked by a WAF or security control "
    "repeatedly with no successful bypass, so the scanner disabled it for this "
    "host. Observed block signature: {signal}. Investigate whether a bypass is "
    "possible for '{attack_type}' on {host} using the available tools. If you "
    "confirm a working bypass, report it clearly; if you are blocked or need a "
    "human decision, say so explicitly."
)

# Seeded operator message for exploring an app-context vulnerability hypothesis.
# Understand-before-acting (CLAUDE.md rule 7): the copilot reads the real
# request/response first and only then decides whether the hypothesis holds.
_HYPOTHESIS_TEMPLATE = (
    "Investigate a vulnerability hypothesis raised by the app-context analysis. "
    "Host: {host}. Suspected issue: '{attack_type}' on endpoint {endpoint}"
    "{parameter_clause}. Rationale: {rationale}. Read the actual request and "
    "response for this endpoint first, decide whether the hypothesis holds, and "
    "if it does, attempt a safe, read-only proof. Report what you find with "
    "evidence, or explain why the hypothesis does not hold. If you are blocked "
    "or need a value only the operator has, say so explicitly."
)


class CopilotService:
    """Owns copilot session state, the turn runner, and block escalation."""

    def __init__(self, ctx: "DashboardContext") -> None:
        self._ctx = ctx
        self._sessions: Dict[str, dict] = {}
        # (host, attack_type) pairs already escalated this process lifetime — a
        # WAF-disabled type is handed to the copilot exactly once per host.
        self._escalated: Set[Tuple[str, str]] = set()
        # Hypothesis key -> session id, so re-exploring the same hypothesis
        # (e.g. a double-click) reuses the live session instead of duplicating it.
        self._hypothesis_sessions: Dict[str, str] = {}

    # ── Session store ──────────────────────────────────────────────────────────
    def has(self, sid: str) -> bool:
        return sid in self._sessions

    def get(self, sid: str) -> Optional[dict]:
        return self._sessions.get(sid)

    def _gc(self) -> None:
        if len(self._sessions) > _MAX_SESSIONS:
            oldest = sorted(self._sessions.keys(),
                            key=lambda k: self._sessions[k].get("created_at", 0))
            for k in oldest[:len(self._sessions) - _MAX_SESSIONS]:
                self._sessions.pop(k, None)

    def new_session(self) -> str:
        from dast.ai.copilot import CopilotSession
        sid = str(uuid.uuid4())[:12]
        self._sessions[sid] = {
            "engine": CopilotSession(sid),
            "status": "idle",
            "created_at": time.time(),
            "updated_at": time.time(),
            "trace": [],
            "pause": None,
            "last_reply": None,
            "origin": "operator",
            "escalation": None,
            "hypothesis": None,
            "_pause_event": asyncio.Event(),
            "_pause_result": None,
            "approved_hosts": set(),
            "_task": None,
        }
        self._gc()
        return sid

    def session_dict(self, sid: str) -> dict:
        session = self._sessions.get(sid)
        if not session:
            return {}
        engine = session["engine"]
        return {
            "session_id": sid,
            "status": session.get("status", "idle"),
            "created_at": session.get("created_at", 0),
            "updated_at": session.get("updated_at", 0),
            "origin": session.get("origin", "operator"),
            "escalation": session.get("escalation"),
            "hypothesis": session.get("hypothesis"),
            "messages": list(engine.messages),
            "trace": session.get("trace", []),
            "pause": session.get("pause"),
            "last_reply": session.get("last_reply"),
        }

    def list_summaries(self) -> List[dict]:
        return [
            {
                "session_id": sid,
                "status": self._sessions[sid].get("status", "idle"),
                "created_at": self._sessions[sid].get("created_at", 0),
                "updated_at": self._sessions[sid].get("updated_at", 0),
                "origin": self._sessions[sid].get("origin", "operator"),
                "message_count": len(self._sessions[sid]["engine"].messages),
            }
            for sid in sorted(self._sessions.keys(),
                              key=lambda k: -self._sessions[k].get("updated_at", 0))
        ]

    def start_turn(self, sid: str, text: str) -> None:
        """Schedule a turn on the running event loop."""
        session = self._sessions[sid]
        session["_task"] = asyncio.create_task(self._run_turn(sid, text))

    # ── Block escalation (in-process entry point) ────────────────────────────────
    def escalate_block(self, host: str, attack_type: str, host_intel: object) -> Optional[str]:
        """Hand a WAF-disabled attack type to the copilot as a new conversation.

        Deduped per (host, attack_type). Returns the new session id, or None if
        the pair was already escalated or a turn could not be scheduled. Called
        from the coordinator on the dashboard event loop via an injected sink, so
        ``asyncio.create_task`` has a running loop.
        """
        key = (host, attack_type)
        if key in self._escalated:
            return None

        signal = ""
        try:
            observations = getattr(host_intel, "waf_observations", []) or []
            matching = [sig for _, sig, at in observations if at == attack_type and sig]
            if matching:
                signal = matching[-1]
        except Exception as exc:
            logger.warning("copilot escalation signal extraction failed",
                           host=host, attack_type=attack_type, error=str(exc))

        sid = self.new_session()
        session = self._sessions[sid]
        session["origin"] = "block_escalation"
        session["escalation"] = {"host": host, "attack_type": attack_type, "signal": signal}
        message = _ESCALATION_TEMPLATE.format(
            host=host,
            attack_type=attack_type,
            signal=signal or "unknown block signature",
        )
        try:
            self.start_turn(sid, message)
        except RuntimeError as exc:
            # No running event loop — should not happen (the coordinator runs in
            # the dashboard loop), but never crash the scan over an escalation.
            # Leave the pair un-marked and drop the half-built session so a later
            # call (with a running loop) can retry the escalation.
            logger.warning("copilot escalation could not schedule turn",
                           host=host, attack_type=attack_type, error=str(exc))
            self._sessions.pop(sid, None)
            return None
        # Mark escalated only after the turn is scheduled, so a transient
        # scheduling failure does not permanently suppress this pair.
        self._escalated.add(key)
        logger.info("Copilot block escalation started",
                    session_id=sid, host=host, attack_type=attack_type)
        return sid

    def explore_hypothesis(self, host: str, attack_type: str, endpoint: str,
                           parameter: str, rationale: str) -> Optional[str]:
        """Open (or reuse) a copilot conversation to investigate an app-context
        vulnerability hypothesis.

        Idempotent per (host, endpoint, attack_type, parameter): a repeated
        request returns the existing live session so a double-click does not spawn
        duplicates. Returns the session id, or None if the turn could not be
        scheduled.
        """
        key = "|".join((host, endpoint, attack_type, parameter))
        existing = self._hypothesis_sessions.get(key)
        if existing and existing in self._sessions:
            return existing

        parameter_clause = (
            f", parameter '{parameter}'" if parameter and parameter != "*" else ""
        )
        message = _HYPOTHESIS_TEMPLATE.format(
            host=host,
            attack_type=attack_type,
            endpoint=endpoint,
            parameter_clause=parameter_clause,
            rationale=rationale or "not provided",
        )
        sid = self.new_session()
        session = self._sessions[sid]
        session["origin"] = "hypothesis"
        session["hypothesis"] = {
            "host": host, "attack_type": attack_type, "endpoint": endpoint,
            "parameter": parameter, "rationale": rationale,
        }
        try:
            self.start_turn(sid, message)
        except RuntimeError as exc:
            logger.warning("copilot hypothesis exploration could not schedule turn",
                           host=host, attack_type=attack_type, error=str(exc))
            self._sessions.pop(sid, None)
            return None
        self._hypothesis_sessions[key] = sid
        logger.info("Copilot hypothesis exploration started",
                    session_id=sid, host=host, attack_type=attack_type,
                    endpoint=endpoint)
        return sid

    # ── Turn runner ──────────────────────────────────────────────────────────────
    async def _run_turn(self, sid: str, text: str) -> None:
        ctx = self._ctx
        session = self._sessions[sid]

        async def on_event(payload: dict) -> None:
            event = {"session_id": sid, **payload}
            session["trace"].append(event)
            await ctx.broadcast_copilot(event)

        async def wait_for_human(kind: str, payload: dict) -> dict:
            timeout = {
                "approve": _APPROVE_TIMEOUT_SECONDS,
                "auth": _AUTH_TIMEOUT_SECONDS,
            }.get(kind, _APPROVE_TIMEOUT_SECONDS)
            defaults = {
                "approve": {"decision": "deny"},
                "auth": {"cookies": {}},
            }
            event: asyncio.Event = session["_pause_event"]
            event.clear()
            session["_pause_result"] = None
            session["status"] = f"paused_{kind}"
            session["pause"] = {"kind": kind, "payload": payload}
            await ctx.broadcast_copilot({"type": "pause", "session_id": sid,
                                         "kind": kind, "payload": payload})
            try:
                await asyncio.wait_for(event.wait(), timeout=timeout)
                result = session.get("_pause_result") or defaults.get(kind, {})
            except asyncio.TimeoutError:
                logger.warning("Copilot pause timed out", session_id=sid, kind=kind)
                result = defaults.get(kind, {})
            session["pause"] = None
            session["status"] = "running"
            await ctx.broadcast_copilot({"type": "resumed", "session_id": sid, "kind": kind})
            return result

        try:
            session["status"] = "running"
            session["updated_at"] = time.time()
            tool_ctx = AgentToolContext(
                proxy_port=ctx.proxy_port,
                dashboard_port=getattr(ctx, "dashboard_port", 8088),
                store=ctx.store,
                settings=ctx.settings,
                approved_hosts=session["approved_hosts"],
            )
            reply = await session["engine"].send(
                text, tool_ctx, on_event=on_event, wait_for_human=wait_for_human,
            )
            session["last_reply"] = {
                "message": reply.message,
                "blocked_reason": reply.blocked_reason,
            }
            session["status"] = "blocked" if reply.blocked_reason else "idle"
            session["updated_at"] = time.time()
        except asyncio.CancelledError:
            session["status"] = "idle"
        except Exception as exc:
            logger.error("Copilot turn runner error", session_id=sid, error=str(exc))
            session["status"] = "error"
            session["last_reply"] = {"message": f"Internal error: {str(exc)[:300]}",
                                     "blocked_reason": "error"}

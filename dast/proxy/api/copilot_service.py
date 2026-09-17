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

# ── Autonomous orchestrator mode ────────────────────────────────────────────────

# Budget defaults for an autonomous run. Every field is overridable at launch; the
# run stops on the FIRST bound reached (or when the copilot self-declares complete,
# or the operator stops it).
_AUTONOMOUS_DEFAULTS: Dict[str, object] = {
    "max_tool_calls": 150,          # total tool calls across all turns
    "max_wall_clock_seconds": 1800,  # 30 minutes of active (non-paused) run time
    "max_stuck_turns": 3,           # consecutive turns with no new findings/endpoints
    "allow_scope_escalation": False,  # False = auto-deny out-of-scope; True = ask the operator
}

# How many engine-level errors in a row abort the driver (guards a wedged model).
_MAX_DRIVER_ERRORS = 3

# blocked_reason values that mean "I cannot proceed without a human" — the driver
# turns these into an operator escalation (answer / pause / abort) then resumes.
_ESCALATE_REASONS = frozenset({
    "need_human", "need_value", "need_authorization", "need_authorisation",
    "out_of_scope", "auth_required", "waf_block",
})

_AUTONOMOUS_START = (
    "[AUTONOMOUS PENTEST] You are running fully autonomously against {hosts}. "
    "Objective: {objective}\n\n"
    "Work the objective end to end across many turns without waiting for me. Map the "
    "surface first (crawl, graphql_introspect, get_history), then actively test "
    "in-scope endpoints: use run_scan to unleash the full arsenal on an endpoint, and "
    "send_request / validate_chain for targeted checks. Record confirmed issues with "
    "record_finding. After each result, keep going to the next endpoint or technique.\n"
    "Signal control ONLY through blocked_reason on a reply: set it to 'complete' when "
    "the objective is fully covered, or 'need_human' with a specific question when you "
    "genuinely cannot proceed without me (a value only I have, or a decision). "
    "Otherwise just report progress in the message and continue working."
)

_AUTONOMOUS_CONTINUE = (
    "Continue with your plan autonomously. Progress so far: {progress}. "
    "Budget remaining: {budget}. Set blocked_reason='complete' once the objective is "
    "fully covered, or 'need_human' if you are truly blocked."
)

_AUTONOMOUS_GUIDANCE = (
    "Operator response to your request: {answer}\n\n"
    "Continue with your plan autonomously."
)


def _normalise_budget(budget: Optional[dict]) -> Dict[str, object]:
    """Merge a caller-supplied budget over the defaults and clamp to safe ranges."""
    cfg: Dict[str, object] = dict(_AUTONOMOUS_DEFAULTS)
    if isinstance(budget, dict):
        for key in _AUTONOMOUS_DEFAULTS:
            if budget.get(key) is not None:
                cfg[key] = budget[key]
    try:
        cfg["max_tool_calls"] = max(1, min(int(cfg["max_tool_calls"]), 2000))
    except (TypeError, ValueError):
        cfg["max_tool_calls"] = _AUTONOMOUS_DEFAULTS["max_tool_calls"]
    try:
        cfg["max_wall_clock_seconds"] = max(30, min(int(cfg["max_wall_clock_seconds"]), 24 * 3600))
    except (TypeError, ValueError):
        cfg["max_wall_clock_seconds"] = _AUTONOMOUS_DEFAULTS["max_wall_clock_seconds"]
    try:
        cfg["max_stuck_turns"] = max(1, min(int(cfg["max_stuck_turns"]), 50))
    except (TypeError, ValueError):
        cfg["max_stuck_turns"] = _AUTONOMOUS_DEFAULTS["max_stuck_turns"]
    cfg["allow_scope_escalation"] = bool(cfg["allow_scope_escalation"])
    return cfg


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

    def new_session(self, focus_hosts: Optional[List[str]] = None) -> str:
        from dast.ai.copilot import CopilotSession
        sid = str(uuid.uuid4())[:12]
        self._sessions[sid] = {
            "engine": CopilotSession(sid, focus_hosts=focus_hosts),
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
            # Set only for autonomous runs (see run_autonomous). None means this is
            # an ordinary human-in-the-loop conversation.
            "autonomous": None,
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
            "autonomous": self._autonomous_public(session),
        }

    @staticmethod
    def _autonomous_public(session: dict) -> Optional[dict]:
        """A secret-free snapshot of an autonomous run's state for the API/UI."""
        auto = session.get("autonomous")
        if not auto:
            return None
        cfg = auto.get("config", {})
        started_at = auto.get("started_at", 0)
        deadline = started_at + int(cfg.get("max_wall_clock_seconds", 0) or 0)
        return {
            "objective": auto.get("objective", ""),
            "status": auto.get("status", ""),
            "detail": auto.get("detail", ""),
            "hosts": list(auto.get("hosts", []) or []),
            "profile": auto.get("profile"),
            "config": dict(cfg),
            "tool_calls": auto.get("tool_calls", 0),
            "turns": auto.get("turns", 0),
            "started_at": started_at,
            "seconds_remaining": max(0, int(deadline - time.time())) if started_at else 0,
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

        sid = self.new_session(focus_hosts=[host])
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
        sid = self.new_session(focus_hosts=[host])
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

    # ── Shared turn plumbing (used by both interactive and autonomous runs) ───────
    def _make_on_event(self, sid: str, session: dict):
        """Build the per-turn trace-and-broadcast callback."""
        ctx = self._ctx

        async def on_event(payload: dict) -> None:
            event = {"session_id": sid, **payload}
            session["trace"].append(event)
            await ctx.broadcast_copilot(event)

        return on_event

    def _build_tool_ctx(self, session: dict) -> AgentToolContext:
        """Assemble the tool context for a turn. Orchestration tools (crawl,
        run_scan) reach the live queues through the extra fields; they are present
        only for the in-process copilot, so the tools degrade gracefully elsewhere."""
        ctx = self._ctx
        return AgentToolContext(
            proxy_port=ctx.proxy_port,
            dashboard_port=getattr(ctx, "dashboard_port", 8088),
            store=ctx.store,
            settings=ctx.settings,
            approved_hosts=session["approved_hosts"],
            scan_queue=getattr(ctx, "scan_queue", None),
            scan_queue_state=getattr(ctx, "scan_queue_state", None),
            crawl_queue=getattr(ctx, "crawl_queue", None),
        )

    async def _operator_wait(self, sid: str, session: dict, kind: str, payload: dict,
                             timeout: float, defaults: dict) -> dict:
        """Pause the run and block for an operator decision on the pause channel.

        Shared by the interactive turn's approve/auth gates and by the autonomous
        driver's escalation path (kind='guidance'), so all human-in-the-loop pauses
        use the same ``_pause_event``/``_pause_result`` plumbing and WS events.
        """
        ctx = self._ctx
        event: asyncio.Event = session["_pause_event"]
        event.clear()
        session["_pause_result"] = None
        session["status"] = f"paused_{kind}"
        session["pause"] = {"kind": kind, "payload": payload}
        await ctx.broadcast_copilot({"type": "pause", "session_id": sid,
                                     "kind": kind, "payload": payload})
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            result = session.get("_pause_result") or dict(defaults)
        except asyncio.TimeoutError:
            logger.warning("Copilot pause timed out", session_id=sid, kind=kind)
            result = dict(defaults)
        session["pause"] = None
        session["status"] = "running"
        await ctx.broadcast_copilot({"type": "resumed", "session_id": sid, "kind": kind})
        return result

    # ── Turn runner (interactive, human-in-the-loop) ─────────────────────────────
    async def _run_turn(self, sid: str, text: str) -> None:
        session = self._sessions[sid]
        on_event = self._make_on_event(sid, session)

        async def wait_for_human(kind: str, payload: dict) -> dict:
            timeout = {
                "approve": _APPROVE_TIMEOUT_SECONDS,
                "auth": _AUTH_TIMEOUT_SECONDS,
            }.get(kind, _APPROVE_TIMEOUT_SECONDS)
            defaults = {
                "approve": {"decision": "deny"},
                "auth": {"cookies": {}},
            }.get(kind, {})
            return await self._operator_wait(sid, session, kind, payload, timeout, defaults)

        try:
            session["status"] = "running"
            session["updated_at"] = time.time()
            tool_ctx = self._build_tool_ctx(session)
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

    # ── Autonomous orchestrator run ──────────────────────────────────────────────
    def run_autonomous(
        self,
        objective: str,
        focus_hosts: Optional[List[str]] = None,
        profile_slug: Optional[str] = None,
        budget: Optional[dict] = None,
        auto_ai_mode: bool = True,
    ) -> str:
        """Start a fully autonomous copilot run against ``focus_hosts``.

        Creates a session, records an autonomous config block on it, optionally
        preseeds auth from a login profile and turns on AI mode for ambient
        auto-scan of everything crawled, then spawns the cross-turn driver as the
        session task. Returns the session id. Raises ``ValueError`` on a missing
        objective and re-raises ``RuntimeError`` if no event loop is running.
        """
        objective = (objective or "").strip()
        if not objective:
            raise ValueError("objective is required")
        hosts = [h.strip().lower() for h in (focus_hosts or []) if h and h.strip()]

        sid = self.new_session(focus_hosts=hosts)
        session = self._sessions[sid]
        session["origin"] = "autonomous"
        cfg = _normalise_budget(budget)
        pause_gate = asyncio.Event()
        pause_gate.set()  # set = running; cleared = paused
        session["autonomous"] = {
            "objective": objective,
            "config": cfg,
            "hosts": hosts,
            "profile": profile_slug or None,
            "stop_event": asyncio.Event(),
            "pause_gate": pause_gate,
            "paused_at": None,
            "tool_calls": 0,
            "turns": 0,
            "errors": 0,
            "started_at": time.time(),
            "status": "starting",
            "detail": "",
        }

        # Ambient auto-scan: with AI mode on, every in-scope entry the copilot
        # crawls/proxies is auto-queued through the scan pipeline as well.
        if auto_ai_mode and self._ctx.store is not None:
            try:
                self._ctx.store.ai_mode = True
                logger.info("autonomous run enabled AI mode for ambient auto-scan",
                            session_id=sid)
            except Exception as exc:
                logger.warning("autonomous run could not enable AI mode",
                               session_id=sid, error=str(exc))

        # Preseed auth so the run carries a logged-in session from the first call
        # and the auth-wall gate stays quiet (no operator to answer it mid-run).
        if profile_slug:
            self._activate_profile(profile_slug, session)
        self._seed_engine_session(session, hosts)

        try:
            session["_task"] = asyncio.create_task(self._drive_autonomous(sid))
        except RuntimeError as exc:
            logger.warning("autonomous run could not schedule driver",
                           session_id=sid, error=str(exc))
            self._sessions.pop(sid, None)
            raise
        logger.info("autonomous copilot run started", session_id=sid,
                    hosts=hosts, profile=profile_slug or None, config=cfg)
        return sid

    # ── Autonomous run controls ──────────────────────────────────────────────────
    def stop_autonomous(self, sid: str) -> bool:
        """Kill switch: signal the driver to stop and cancel its task. Also releases
        a guidance pause so a blocked loop can observe the stop. Returns False if
        there is no autonomous run for this session."""
        session = self._sessions.get(sid)
        if not session or not session.get("autonomous"):
            return False
        auto = session["autonomous"]
        auto["stop_event"].set()
        auto["pause_gate"].set()  # unblock a paused loop so it sees the stop
        # Release a guidance escalation, if one is waiting.
        session["_pause_result"] = {"action": "abort"}
        session["_pause_event"].set()
        task = session.get("_task")
        if task is not None and not task.done():
            task.cancel()
        logger.info("autonomous run stop requested", session_id=sid)
        return True

    def pause_autonomous(self, sid: str) -> bool:
        """Hold the run at the next turn boundary (does not interrupt a turn in
        flight). Paused time does not count against the wall-clock budget."""
        session = self._sessions.get(sid)
        if not session or not session.get("autonomous"):
            return False
        auto = session["autonomous"]
        if auto["pause_gate"].is_set():
            auto["pause_gate"].clear()
            auto["paused_at"] = time.time()
            auto["status"] = "paused"
            logger.info("autonomous run paused", session_id=sid)
        return True

    def resume_autonomous(self, sid: str) -> bool:
        """Release a paused run so the driver continues from the next turn."""
        session = self._sessions.get(sid)
        if not session or not session.get("autonomous"):
            return False
        auto = session["autonomous"]
        if not auto["pause_gate"].is_set():
            auto["pause_gate"].set()
            auto["status"] = "running"
            logger.info("autonomous run resumed", session_id=sid)
        return True

    def answer_guidance(self, sid: str, answer: str, action: str) -> bool:
        """Answer a ``need_human`` escalation and tell the driver how to proceed
        (``continue`` | ``pause`` | ``abort``). Reuses the pause channel so the
        driver's ``_operator_wait`` returns with this result. Returns False if the
        session is not currently waiting on a guidance escalation."""
        session = self._sessions.get(sid)
        if not session or not session.get("autonomous"):
            return False
        pause = session.get("pause") or {}
        if pause.get("kind") != "guidance":
            return False
        normalized_action = action if action in ("continue", "pause", "abort") else "continue"
        session["_pause_result"] = {"answer": answer or "", "action": normalized_action}
        session["_pause_event"].set()
        logger.info("autonomous run guidance answered", session_id=sid, action=normalized_action)
        return True

    # ── Autonomous helpers ───────────────────────────────────────────────────────
    def _make_counting_on_event(self, sid: str, session: dict, auto: dict):
        """Wrap the trace/broadcast callback to also count executed tool calls
        (one per ``step``/``call_tool`` event) toward the run's tool-call budget."""
        base = self._make_on_event(sid, session)

        async def on_event(payload: dict) -> None:
            if payload.get("type") == "step" and payload.get("action") == "call_tool":
                auto["tool_calls"] += 1
            await base(payload)

        return on_event

    def _make_autonomous_wait(self, sid: str, session: dict):
        """Policy variant of ``wait_for_human`` for autonomous runs: resolve the
        routine gates without an operator, escalating only when configuration
        allows and the policy cannot resolve on its own.

        - approve: the engine only calls this for an out-of-scope host (in-scope
          hosts short-circuit before the gate). Auto-deny unless scope escalation
          is enabled, in which case ask the operator.
        - auth: serve the logged-in session from the jar/profile; if none and
          escalation is enabled, ask the operator; otherwise decline.
        """
        cfg = session["autonomous"]["config"]

        async def wait_for_human(kind: str, payload: dict) -> dict:
            if kind == "approve":
                if cfg["allow_scope_escalation"]:
                    return await self._operator_wait(
                        sid, session, "approve", payload,
                        _APPROVE_TIMEOUT_SECONDS, {"decision": "deny"},
                    )
                logger.info("autonomous run auto-denied out-of-scope host",
                            session_id=sid, host=(payload or {}).get("host", ""))
                return {"decision": "deny"}
            if kind == "auth":
                cookies = self._collect_session_cookies(payload)
                if cookies:
                    logger.info("autonomous run served session cookies from jar",
                                session_id=sid, count=len(cookies))
                    return {"cookies": cookies}
                if cfg["allow_scope_escalation"]:
                    return await self._operator_wait(
                        sid, session, "auth", payload,
                        _AUTH_TIMEOUT_SECONDS, {"cookies": {}},
                    )
                logger.info("autonomous run has no session for auth wall; declining",
                            session_id=sid, host=(payload or {}).get("host", ""))
                return {"cookies": {}}
            return {}

        return wait_for_human

    def _collect_session_cookies(self, payload: Optional[dict]) -> Dict[str, str]:
        """Return ``{name: value}`` cookies for the payload's host from the live jar.
        Never logs the values."""
        store = self._ctx.store
        host = str((payload or {}).get("host", "")).strip().lower()
        if store is None or not host:
            return {}
        try:
            cookie_dicts = store.get_cookies_for_host(host)
        except Exception as exc:
            logger.warning("autonomous run: cookie lookup failed", host=host, error=str(exc))
            return {}
        cookies: Dict[str, str] = {}
        for cookie in cookie_dicts or []:
            name = cookie.get("name")
            if name:
                value = cookie.get("value")
                cookies[str(name)] = str(value if value is not None else "")
        return cookies

    def _activate_profile(self, slug: str, session: dict) -> None:
        """Activate a login profile server-side the way ``/api/profiles/{slug}/
        activate`` does: register the named session and merge its cookies into the
        live jar so ``_apply_session_auth`` injects them on every request. Never
        crashes the run and never logs secret values."""
        store = self._ctx.store
        if store is None:
            return
        try:
            from dast.profiles.store import load_profile
            profile = load_profile(slug)
        except Exception as exc:
            logger.warning("autonomous run: profile load failed", slug=slug, error=str(exc))
            return
        if profile is None or not profile.saved_session:
            logger.warning("autonomous run: login profile has no saved session", slug=slug)
            return
        try:
            cookies = list(profile.saved_session.get("cookies", []))
            auth_headers = dict(profile.saved_session.get("_auth_headers", {}))
            store.save_named_session_from_playwright(
                name=profile.slug, role=profile.name,
                playwright_cookies=cookies, auth_headers=auth_headers,
            )
            imported = store.import_playwright_cookies(cookies)
            logger.info("autonomous run activated login profile", slug=slug, cookies=imported)
        except Exception as exc:
            logger.warning("autonomous run: profile activation failed", slug=slug, error=str(exc))

    def _seed_engine_session(self, session: dict, hosts: List[str]) -> None:
        """Seed the engine's session cookies for the primary focus host so the
        auth-wall gate stays quiet from the first call."""
        if not hosts:
            return
        cookies = self._collect_session_cookies({"host": hosts[0]})
        if not cookies:
            return
        try:
            session["engine"].seed_session_cookies(cookies)
            logger.info("autonomous run seeded engine session", count=len(cookies))
        except Exception as exc:
            logger.warning("autonomous run: engine session seed failed", error=str(exc))

    def _progress_snapshot(self) -> Tuple[int, int]:
        """A monotonic (findings, in-scope endpoints) tuple used by the stuck
        detector: no change across ``max_stuck_turns`` turns means no progress."""
        store = self._ctx.store
        if store is None:
            return (0, 0)
        try:
            entries = store.in_scope_entries()
        except Exception:
            return (0, 0)
        findings = sum(len(getattr(entry, "findings", None) or []) for entry in entries)
        return (findings, len(entries))

    async def _broadcast_autonomous(self, sid: str, event: str,
                                    extra: Optional[dict] = None) -> None:
        payload = {"type": "autonomous", "session_id": sid, "event": event}
        if extra:
            payload.update(extra)
        try:
            await self._ctx.broadcast_copilot(payload)
        except Exception as exc:
            logger.warning("autonomous broadcast failed", session_id=sid, error=str(exc))

    def _finish_autonomous(self, session: dict, status: str, detail: str) -> None:
        auto = session.get("autonomous")
        if auto is not None:
            auto["status"] = status
            auto["detail"] = detail
        session["status"] = "idle" if status == "complete" else status
        session["updated_at"] = time.time()

    async def _guidance_pause(self, sid: str, session: dict, reply, deadline: float) -> dict:
        """Turn a ``need_human`` escalation into an operator prompt on the pause
        channel and block for an answer (answer / pause / abort). Bounded by the
        wall-clock deadline so a forgotten escalation cannot hang forever."""
        remaining = max(30.0, deadline - time.time())
        await self._broadcast_autonomous(sid, "escalation", {
            "message": reply.message,
            "blocked_reason": reply.blocked_reason,
        })
        result = await self._operator_wait(
            sid, session, "guidance",
            {"message": reply.message, "blocked_reason": reply.blocked_reason},
            remaining, {"action": "abort", "answer": ""},
        )
        return result if isinstance(result, dict) else {"action": "abort", "answer": ""}

    async def _drive_autonomous(self, sid: str) -> None:
        """The cross-turn autonomy loop: self-continue turns commanding the arsenal
        until a stop condition trips. A plain reply is a checkpoint, not a stop."""
        session = self._sessions[sid]
        auto = session["autonomous"]
        cfg = auto["config"]
        stop_event: asyncio.Event = auto["stop_event"]
        pause_gate: asyncio.Event = auto["pause_gate"]
        deadline = auto["started_at"] + int(cfg["max_wall_clock_seconds"])

        on_event = self._make_counting_on_event(sid, session, auto)
        wait_for_human = self._make_autonomous_wait(sid, session)

        hosts_label = ", ".join(auto["hosts"]) or "the in-scope target(s)"
        prompt = _AUTONOMOUS_START.format(objective=auto["objective"], hosts=hosts_label)

        last_progress = self._progress_snapshot()
        stuck_turns = 0
        auto["status"] = "running"
        await self._broadcast_autonomous(sid, "started", {
            "objective": auto["objective"], "hosts": auto["hosts"], "config": cfg,
        })

        try:
            while True:
                # Honor a pause request at the turn boundary; extend the deadline by
                # the paused duration so pausing never eats the active-time budget.
                if not pause_gate.is_set():
                    await self._broadcast_autonomous(sid, "paused")
                    await pause_gate.wait()
                    if auto.get("paused_at"):
                        deadline += time.time() - auto["paused_at"]
                        auto["paused_at"] = None
                    await self._broadcast_autonomous(sid, "resumed")

                if stop_event.is_set():
                    self._finish_autonomous(session, "stopped", "stopped by operator")
                    await self._broadcast_autonomous(sid, "finished",
                                                     {"status": "stopped"})
                    return

                # ── Budget gates (checked before spending another turn) ──────────
                now = time.time()
                if now >= deadline:
                    self._finish_autonomous(session, "stopped", "wall-clock budget reached")
                    await self._broadcast_autonomous(sid, "finished",
                                                     {"status": "wall_clock"})
                    return
                if auto["tool_calls"] >= cfg["max_tool_calls"]:
                    self._finish_autonomous(session, "stopped", "tool-call budget reached")
                    await self._broadcast_autonomous(sid, "finished",
                                                     {"status": "tool_budget"})
                    return
                if stuck_turns >= cfg["max_stuck_turns"]:
                    self._finish_autonomous(session, "stopped",
                                            f"no progress for {stuck_turns} turns")
                    await self._broadcast_autonomous(sid, "finished", {"status": "stuck"})
                    return

                # ── Run one turn ─────────────────────────────────────────────────
                auto["turns"] += 1
                session["status"] = "running"
                session["updated_at"] = time.time()
                tool_ctx = self._build_tool_ctx(session)
                try:
                    reply = await session["engine"].send(
                        prompt, tool_ctx, on_event=on_event, wait_for_human=wait_for_human,
                    )
                    auto["errors"] = 0
                except asyncio.CancelledError:
                    self._finish_autonomous(session, "stopped", "cancelled")
                    return
                except Exception as exc:
                    auto["errors"] += 1
                    logger.error("autonomous turn error", session_id=sid,
                                 error=str(exc), errors=auto["errors"])
                    if auto["errors"] >= _MAX_DRIVER_ERRORS:
                        self._finish_autonomous(session, "error",
                                                f"aborted after repeated errors: {str(exc)[:200]}")
                        await self._broadcast_autonomous(sid, "finished", {"status": "error"})
                        return
                    prompt = _AUTONOMOUS_CONTINUE.format(
                        progress=self._progress_label(last_progress),
                        budget=self._budget_label(auto, cfg, deadline),
                    )
                    continue

                session["last_reply"] = {
                    "message": reply.message,
                    "blocked_reason": reply.blocked_reason,
                }
                blocked_reason = (reply.blocked_reason or "").strip().lower()

                # ── Progress / stuck accounting ──────────────────────────────────
                progress = self._progress_snapshot()
                if progress != last_progress:
                    stuck_turns = 0
                    last_progress = progress
                else:
                    stuck_turns += 1

                # ── Interpret the reply's control signal ─────────────────────────
                if blocked_reason == "complete":
                    self._finish_autonomous(session, "complete", "objective complete")
                    await self._broadcast_autonomous(sid, "finished", {
                        "status": "complete", "message": reply.message,
                    })
                    return

                if blocked_reason in _ESCALATE_REASONS:
                    guidance = await self._guidance_pause(sid, session, reply, deadline)
                    if stop_event.is_set() or guidance.get("action") == "abort":
                        self._finish_autonomous(session, "stopped", "aborted at escalation")
                        await self._broadcast_autonomous(sid, "finished",
                                                         {"status": "stopped"})
                        return
                    if guidance.get("action") == "pause":
                        pause_gate.clear()
                        auto["paused_at"] = time.time()
                        auto["status"] = "paused"
                    prompt = _AUTONOMOUS_GUIDANCE.format(
                        answer=str(guidance.get("answer", "")).strip() or "(no answer provided)"
                    )
                    continue

                # Plain reply (or error/need_direction/ceiling): a checkpoint — keep going.
                prompt = _AUTONOMOUS_CONTINUE.format(
                    progress=self._progress_label(last_progress),
                    budget=self._budget_label(auto, cfg, deadline),
                )
        except asyncio.CancelledError:
            self._finish_autonomous(session, "stopped", "cancelled")
        except Exception as exc:
            logger.error("autonomous driver crashed", session_id=sid, error=str(exc))
            self._finish_autonomous(session, "error", f"driver error: {str(exc)[:200]}")
            await self._broadcast_autonomous(sid, "finished", {"status": "error"})

    @staticmethod
    def _progress_label(progress: Tuple[int, int]) -> str:
        findings, endpoints = progress
        return f"{findings} findings across {endpoints} in-scope endpoints"

    @staticmethod
    def _budget_label(auto: dict, cfg: dict, deadline: float) -> str:
        remaining = max(0, int(deadline - time.time()))
        return (f"{auto['tool_calls']}/{cfg['max_tool_calls']} tool calls used, "
                f"{remaining}s of wall-clock left")

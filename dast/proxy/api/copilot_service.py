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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from dast.ai.prompt_safety import wrap_untrusted
from dast.tools.context import AgentToolContext
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
    "max_tool_calls": 300,          # total tool calls across all turns
    "max_wall_clock_seconds": 3600,  # 60 minutes of active (non-paused) run time
    "max_stuck_turns": 3,           # consecutive turns with no new findings/endpoints/coverage
    "allow_scope_escalation": False,  # False = auto-deny out-of-scope; True = ask the operator
}

# How many engine-level errors in a row abort the driver (guards a wedged model).
_MAX_DRIVER_ERRORS = 3

# How many times the coverage gate may bounce a premature 'complete' before letting the
# run end anyway (with an honest "coverage incomplete" report). Guards against a loop
# where the copilot cannot make coverage progress; the stuck detector is the other bound.
_MAX_COMPLETE_REJECTIONS = 8

# GraphQL schema buckets, matching the compact schema stored by graphql_introspection.
_GQL_BUCKETS = {"query": "queries", "mutation": "mutations"}

# blocked_reason values that mean "I cannot proceed without a human" — the driver
# turns these into an operator escalation (answer / pause / abort) then resumes.
_ESCALATE_REASONS = frozenset({
    "need_human", "need_value", "need_authorization", "need_authorisation",
    "out_of_scope", "auth_required", "waf_block",
})

_AUTONOMOUS_START = (
    "[AUTONOMOUS PENTEST] You are the operator now, running fully autonomously against "
    "{hosts}. You are NOT a chatbot doing raw HTTP — you DRIVE Frieren's own instruments so "
    "every action is registered inside the tool (schemas, history, findings) for the human to "
    "review later. Objective: {objective}\n\n"
    "{read_only}"
    "Work the objective end to end across many turns without waiting for me.\n"
    "USE THE INTERNAL TOOLS — never hand-roll with send_request what a dedicated tool does:\n"
    "- graphql_introspect on any GraphQL endpoint (this registers the schema in Frieren); do "
    "NOT introspect by hand with send_request.\n"
    "- run_scan on every interesting in-scope endpoint to unleash the full arsenal "
    "(planner + parallel VulnAgents + Red-Team Validator) — this is how confirmed findings get "
    "registered; a raw request that you eyeball registers nothing.\n"
    "- crawl / content_discovery / param_mining to expand the surface; get_history to reuse what "
    "you already captured; record_finding for anything you confirm yourself.\n"
    "- send_request / validate_chain ONLY for a targeted check no dedicated tool covers.\n"
    "BE A PENTESTER, NOT A READER. When you observe auth material (decode JWTs and reason about "
    "claims/roles/expiry), permission or ACL maps (e.g. /spa/session), or user-scoped endpoints "
    "(e.g. /lx/profile), form a concrete hypothesis and TEST it: IDOR/BOLA by swapping ids or "
    "account context, privilege escalation, mass assignment, reflected/stored XSS, parameter "
    "tampering. Non-destructive, detection-only, any time delay <= 5s. Reading an endpoint and "
    "moving on WITHOUT testing it is a failure.\n\n"
    "COVER THE WHOLE SURFACE — breadth first, then depth. Map every endpoint (crawl) and "
    "every GraphQL endpoint's schema (graphql_introspect), then TEST all of it: scan_surface "
    "scans every observed-but-unscanned REST endpoint in one call, and graphql_sweep exercises "
    "EVERY query and mutation of an introspected endpoint in one call. Do not eyeball a handful "
    "of operations and stop — sweep the entire schema and scan the entire REST surface, then go "
    "deep on the leads they surface.\n\n"
    "{leads}\n\n"
    "{router}"
    "{coverage}\n\n"
    "Signal control ONLY through blocked_reason on a reply: set it to 'complete' when the "
    "objective is fully covered AND you have actively TESTED the high-value leads (not merely "
    "mapped them) AND no coverage gaps remain (every REST endpoint scanned, every GraphQL "
    "operation swept); or 'need_human' with a specific question when you genuinely cannot proceed "
    "without me (a value only I have, or a decision) — and then also say what a vulnerable "
    "response would look like vs. a normal one, so I can help. Otherwise just report progress "
    "in the message and keep working."
)

_AUTONOMOUS_CONTINUE = (
    "Continue autonomously — keep driving Frieren's internal tools (graphql_introspect, "
    "graphql_sweep, run_scan, scan_surface, crawl, param_mining, record_finding), and actively "
    "TEST leads (IDOR/BOLA/XSS/privilege/param-tampering), don't just map them.\n"
    "{read_only}"
    "Progress so far: {progress}. Budget remaining: {budget}.\n\n"
    "{leads}\n\n"
    "{router}"
    "{coverage}\n\n"
    "Set blocked_reason='complete' ONLY once the objective is covered, the high-value leads "
    "have been actively tested, AND no coverage gaps remain; or 'need_human' if you are truly "
    "blocked (say what a vulnerable vs. normal response would look like)."
)

_AUTONOMOUS_COVERAGE_GATE = (
    "You set 'complete', but you have NOT tested the whole attack surface — that is premature. "
    "Do not stop yet.\n\n"
    "{coverage}\n\n"
    "Close these gaps now: run scan_surface until it reports remaining=0, and graphql_sweep on "
    "each introspected GraphQL endpoint until operations_remaining=0 (crawl / graphql_introspect "
    "first if the surface is not yet mapped). Then go deep on anything they flag. Budget "
    "remaining: {budget}. Only set 'complete' once every endpoint and operation has been tested."
)

_READ_ONLY_DIRECTIVE = (
    "[READ-ONLY MODE] This is a production target. Only safe methods (GET/HEAD/OPTIONS) leave "
    "the machine; any write a click or form would trigger is dropped at the network layer. "
    "The probe/attack tools (run_scan, scan_surface, graphql_sweep, idor_probe, param_mining, "
    "content_discovery, match_replace, validate_chain) are DISABLED and will return an error.\n"
    "Your job is to MAP and OBSERVE, not to attack: crawl to discover the surface, "
    "browser_navigate/browser_click to reach routes, graphql_introspect to register schemas, "
    "send_request (GET/HEAD/OPTIONS only) to read endpoints, get_history to review captured "
    "traffic, and record_finding for anything you can conclude from observation alone (e.g. a "
    "missing security header, a secret in a response). Do NOT keep retrying a disabled tool. "
    "Coverage here means 'surface mapped', not 'surface scanned' — set blocked_reason='complete' "
    "once you have mapped and observed the surface for the objective."
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

    def refresh_session(self, sid: str) -> Dict[str, Any]:
        """Pull the freshest cookies from the proxy jar for every host this session
        has touched and inject them into the engine. Call this after the operator
        logs in through the browser to give the copilot a live authenticated session.
        Returns {ok, hosts_updated, cookies_refreshed}."""
        session = self._sessions.get(sid)
        if session is None:
            return {"ok": False, "error": "session not found"}
        engine = session["engine"]
        store = self._ctx.store
        if store is None:
            return {"ok": False, "error": "proxy store not available"}
        known_hosts: set = set(engine.get_known_hosts()) | set(session.get("approved_hosts") or set())
        if not known_hosts:
            return {"ok": True, "hosts_updated": [], "cookies_refreshed": 0}
        merged_cookies: Dict[str, str] = {}
        hosts_updated: List[str] = []
        for host in sorted(known_hosts):
            try:
                jar_cookies = store.get_cookies_for_host(host) or []
            except Exception as exc:
                logger.warning("copilot refresh_session: jar lookup failed",
                               sid=sid, host=host, error=str(exc))
                continue
            batch = {c["name"]: c.get("value", "") for c in jar_cookies if c.get("name")}
            if batch:
                merged_cookies.update(batch)
                hosts_updated.append(host)
        engine.seed_session_cookies(merged_cookies)
        logger.info("copilot session refreshed from proxy jar",
                    sid=sid, hosts=hosts_updated, cookies=len(merged_cookies))
        return {"ok": True, "hosts_updated": hosts_updated, "cookies_refreshed": len(merged_cookies)}

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
        # One AgentBrowser per session, created lazily and reused across turns so
        # multi-step form state (and a fresh CSRF token) survives between tool calls.
        browser = session.get("_agent_browser")
        if browser is None:
            try:
                from dast.browser.agent_browser import AgentBrowser
                browser = AgentBrowser(
                    proxy_port=ctx.proxy_port, store=ctx.store,
                    read_only=bool((session.get("autonomous") or {}).get("read_only", False)),
                )
                session["_agent_browser"] = browser
            except Exception as exc:
                logger.warning("could not create AgentBrowser", error=str(exc))
                browser = None
        return AgentToolContext(
            proxy_port=ctx.proxy_port,
            dashboard_port=getattr(ctx, "dashboard_port", 8088),
            store=ctx.store,
            settings=ctx.settings,
            approved_hosts=session["approved_hosts"],
            scan_queue=getattr(ctx, "scan_queue", None),
            scan_queue_state=getattr(ctx, "scan_queue_state", None),
            crawl_queue=getattr(ctx, "crawl_queue", None),
            source_label="copilot",
            session_safe=bool((session.get("autonomous") or {}).get("session_safe", False)),
            read_only=bool((session.get("autonomous") or {}).get("read_only", False)),
            browser=browser,
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
        session_safe: bool = False,
        read_only: bool = False,
        mode: str = "bounded",
        submit_forms: bool = False,
    ) -> str:
        """Start a fully autonomous copilot run against ``focus_hosts``.

        Creates a session, records an autonomous config block on it, optionally
        preseeds auth from a login profile and turns on AI mode for ambient
        auto-scan of everything crawled, then spawns the cross-turn driver as the
        session task. Returns the session id. Raises ``ValueError`` on a missing
        objective and re-raises ``RuntimeError`` if no event loop is running.

        ``mode="complete"`` runs an exhaustive test: it will not self-terminate
        while UI routes or surface remain untested — only the operator, the
        wall-clock, or genuine exhaustion ends it. ``submit_forms`` lets the SPA
        explorer fill and submit forms (active runs only) to reach wizard steps.
        """
        objective = (objective or "").strip()
        if not objective:
            raise ValueError("objective is required")
        hosts = [h.strip().lower() for h in (focus_hosts or []) if h and h.strip()]
        mode = mode if mode in ("bounded", "complete") else "bounded"

        sid = self.new_session(focus_hosts=hosts)
        session = self._sessions[sid]
        session["origin"] = "autonomous"
        cfg = _normalise_budget(budget)
        # Complete mode: unless the caller set explicit bounds, run on a long leash
        # so breadth isn't cut short — the operator stops it. (Clamp ceilings from
        # _normalise_budget still apply.)
        if mode == "complete" and not budget:
            cfg["max_wall_clock_seconds"] = 86400
            cfg["max_tool_calls"] = 2000
            cfg["max_stuck_turns"] = 50
        pause_gate = asyncio.Event()
        pause_gate.set()  # set = running; cleared = paused
        session["autonomous"] = {
            "objective": objective,
            "config": cfg,
            "hosts": hosts,
            "profile": profile_slug or None,
            "session_safe": session_safe,
            "read_only": read_only,
            "mode": mode,
            "submit_forms": bool(submit_forms) and not read_only,
            "initial_explore_done": False,
            "stop_event": asyncio.Event(),
            "pause_gate": pause_gate,
            "paused_at": None,
            "tool_calls": 0,
            "turns": 0,
            "errors": 0,
            "complete_rejections": 0,
            "started_at": time.time(),
            "status": "starting",
            "detail": "",
        }

        # Ambient auto-scan: with AI mode on, every in-scope entry the copilot
        # crawls/proxies is auto-queued through the scan pipeline as well.
        # Session-safe mode suppresses this — the param-mining/agent probes it
        # fans out share the one logged-in cookie and trip concurrent-session
        # detection on strict targets (ASP.NET single-session), logging the run
        # (and the operator's browser) out mid-objective.
        if read_only:
            # Read-only: ambient auto-scan fires attack payloads at everything
            # crawled, so it must be OFF for the run even if the operator had
            # it on. Same save/restore path as the forced-on case below.
            auto_ai_mode = False
            if self._ctx.store is not None and self._ctx.store.ai_mode:
                session["autonomous"]["_ai_mode_prev"] = True
                session["autonomous"]["_ai_mode_forced"] = True
                self._ctx.store.ai_mode = False
                logger.info("read-only run: AI mode paused for the run", session_id=sid)
        if session_safe and auto_ai_mode:
            logger.info("session-safe mode: skipping ambient auto-scan (ai_mode)",
                        session_id=sid)
            auto_ai_mode = False
        if auto_ai_mode and self._ctx.store is not None:
            try:
                # Remember the operator's prior AI-mode setting so it is restored
                # when the run ends — an autonomous run must not permanently flip
                # ambient auto-scan on for the whole store.
                session["autonomous"]["_ai_mode_prev"] = bool(self._ctx.store.ai_mode)
                session["autonomous"]["_ai_mode_forced"] = True
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

    def _progress_snapshot(self) -> Tuple[int, int, int, int]:
        """A monotonic (findings, in-scope endpoints, coverage units, ui units) tuple
        used by the stuck detector: no change across ``max_stuck_turns`` turns means no
        progress. Coverage units count scanned endpoints + swept GraphQL operations so
        breadth work (scan_surface / graphql_sweep) registers as progress; ui units count
        discovered + visited UI routes so SPA exploration (discovering or visiting a
        route) also counts and never trips the stuck detector."""
        store = self._ctx.store
        if store is None:
            return (0, 0, 0, 0)
        try:
            entries = store.in_scope_entries()
        except Exception:
            return (0, 0, 0, 0)
        findings = sum(len(getattr(entry, "findings", None) or []) for entry in entries)
        scanned = sum(1 for entry in entries if getattr(entry, "scan_result", None))
        swept_ops = sum(
            len(ops or ())
            for ops in (getattr(store, "graphql_tested_ops", None) or {}).values()
        )
        graph = getattr(store, "ui_route_graph", None)
        ui_stats = graph.stats() if graph is not None else {"visited": 0, "frontier": 0}
        ui_units = ui_stats["visited"] + ui_stats["frontier"]
        return (findings, len(entries), scanned + swept_ops, ui_units)

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
            # Restore the operator's prior AI-mode setting if this run forced it on.
            # Guard against double-restore so re-entry is a no-op.
            if auto.pop("_ai_mode_forced", False) and self._ctx.store is not None:
                try:
                    self._ctx.store.ai_mode = auto.pop("_ai_mode_prev", False)
                except Exception as exc:
                    logger.warning("autonomous run could not restore AI mode",
                                   error=str(exc))
        session["status"] = "idle" if status == "complete" else status
        session["updated_at"] = time.time()

        # Clean up resources the copilot acquired during the run.
        self._cleanup_session(session)

    def _cleanup_session(self, session: dict) -> None:
        """Release per-session resources: close the agent browser and remove any
        match/replace rules the copilot added (tagged with [copilot_session])."""
        # Close the agent browser so it doesn't leak Playwright processes.
        browser = session.pop("_agent_browser", None)
        if browser is not None:
            import asyncio
            try:
                asyncio.ensure_future(browser.close())
            except Exception as exc:
                logger.debug("AgentBrowser cleanup error", error=str(exc))
        # Remove copilot-scoped match/replace rules so the operator's browsing
        # is not affected after the copilot finishes.
        settings = getattr(self._ctx, "settings", None)
        if settings is not None:
            try:
                from dast.tools.match_replace_tools import _COPILOT_TAG
                all_rules = settings.get_match_replace() or []
                removed = 0
                for i in reversed(range(len(all_rules))):
                    if all_rules[i].get("comment", "").startswith(f"[{_COPILOT_TAG}]"):
                        settings.remove_match_replace(i)
                        removed += 1
                if removed:
                    logger.info("Cleaned up copilot match/replace rules", removed=removed)
            except Exception as exc:
                logger.warning("match/replace cleanup failed", error=str(exc))

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

    def _leads_label(self, hosts: List[str]) -> str:
        """Compact, prioritised app-context leads for the focus hosts, injected into the
        autonomous turn prompt so the copilot chases concrete hypotheses ITSELF instead of
        escalating to a human. Reuses AppProfile.to_coordinator_hint() (already
        prompt-injection sanitised). Empty-safe: returns a nudge when nothing is profiled yet."""
        nudge = ("Leads: none from app-context analysis yet — map the surface "
                 "(crawl, graphql_introspect, get_history) to surface concrete hypotheses.")
        store = self._ctx.store
        if store is None:
            return nudge
        try:
            profiles = store.discovery_engine.all_app_profiles()
        except Exception as exc:  # noqa: BLE001 — leads are best-effort, never crash the run
            logger.debug("autonomous leads unavailable", error=str(exc))
            return nudge
        focus_names = {h.split(":")[0] for h in (hosts or [])}
        blocks: List[str] = []
        for host, profile in profiles.items():
            if focus_names and host.split(":")[0] not in focus_names:
                continue
            hint = profile.to_coordinator_hint()
            if hint:
                blocks.append(f"[{host}]\n{hint}")
        if not blocks:
            return nudge
        return "App-context leads — chase and TEST these first:\n" + "\n\n".join(blocks[:3])

    def _router_block(self, hosts: List[str]) -> str:
        """Evidence-driven 'recommended next actions / AVOID' block for the turn prompt.
        Deterministic routing from observed signals (id -> sqli/idor, AI endpoint ->
        llm_injection, MySQL -> avoid MSSQL, GraphQL -> sweep) that shrinks as things get
        tested. Best-effort; empty string when there is nothing to recommend yet."""
        store = self._ctx.store
        if store is None:
            return ""
        try:
            from dast.ai.evidence_router import RouterEvidence, route
            parts: List[str] = []
            for host in (hosts or []):
                plan = route(RouterEvidence.from_store(store, host.split(":")[0]))
                block = plan.to_prompt_block()
                if block:
                    parts.append(block)
            return ("\n\n".join(parts) + "\n\n") if parts else ""
        except Exception as exc:  # noqa: BLE001 — routing is advisory, never crash the run
            logger.debug("router block unavailable", error=str(exc))
            return ""

    async def _auto_route(self, session: dict, ctx: Any, hosts: set) -> None:
        """Auto-run the unambiguous, auto_safe evidence recommendations (e.g. AI
        endpoint -> run_scan[llm_injection], high-confidence id flow -> run_scan[sqli]/
        idor_probe), honoring read_only (active tools dropped) and skipping anything
        already auto-run this session. Mirrors _auto_test_graphql; the LLM still handles
        the judgment-call recommendations surfaced in the prompt block."""
        from dast.ai.evidence_router import RouterEvidence, route
        from dast.tools import run_tool

        auto = session["autonomous"]
        read_only = bool(auto.get("read_only"))
        stop_event: asyncio.Event = auto["stop_event"]
        routed: set = auto.setdefault("routed", set())
        store = self._ctx.store
        if store is None:
            return
        for host in hosts:
            if stop_event.is_set():
                return
            try:
                plan = route(RouterEvidence.from_store(store, str(host).split(":")[0]))
            except Exception as exc:  # noqa: BLE001
                logger.debug("auto-route: planning failed", host=host, error=str(exc))
                continue
            for rec in plan.auto_actions(read_only=read_only):
                if stop_event.is_set():
                    return
                key = (rec.target_url, rec.kind, rec.attack_type)
                if not rec.target_url or key in routed:
                    continue
                routed.add(key)
                args: Dict[str, Any] = {"url": rec.target_url}
                if rec.kind == "run_scan" and rec.attack_type:
                    args["attack_types"] = [rec.attack_type]
                try:
                    logger.info("auto-route: running", kind=rec.kind, attack=rec.attack_type,
                                url=rec.target_url, source=rec.source)
                    await run_tool(ctx, rec.kind, args)
                except Exception as exc:  # noqa: BLE001 — never crash the run on one tool
                    logger.warning("auto-route tool failed", kind=rec.kind, error=str(exc))

    async def _deterministic_recon_scan_sweep(self, sid: str, session: dict) -> None:
        """Drive breadth deterministically in complete mode so it is never left to
        LLM discretion: per focus host, EXPLORE the SPA to drain the UI frontier,
        then (active runs only) CONTENT-DISCOVER, SCAN every observed endpoint to
        exhaustion, and INTROSPECT+SWEEP (or FUZZ captured ops when introspection is
        disabled) every GraphQL endpoint. The LLM turns that follow focus on depth.
        Best-effort and stop-aware — any tool failure is logged, never fatal."""
        from dast.tools import run_tool

        auto = session["autonomous"]
        hosts = auto.get("hosts") or []
        if not hosts:
            return
        read_only = bool(auto.get("read_only"))
        submit_forms = bool(auto.get("submit_forms"))
        stop_event: asyncio.Event = auto["stop_event"]
        ctx = self._build_tool_ctx(session)

        async def _call(tool: str, args: dict) -> dict:
            try:
                result = await run_tool(ctx, tool, args)
                return result if isinstance(result, dict) else {}
            except Exception as exc:  # noqa: BLE001 — never crash the run on one tool
                logger.warning("complete-mode sweep tool failed", session_id=sid,
                               tool=tool, error=str(exc))
                return {}

        async def _loop_until_zero(tool: str, args: dict, key: str, passes: int = 12) -> None:
            prev = -1
            for _ in range(passes):
                if stop_event.is_set():
                    return
                result = await _call(tool, args)
                remaining = int(result.get(key, 0) or 0)
                if remaining == 0 or remaining == prev:
                    return
                prev = remaining

        for host in hosts:
            if stop_event.is_set():
                return
            seed = f"https://{host}/"

            # 1) Exhaustive SPA exploration — drain the UI-route frontier.
            prev_frontier = -1
            last_visited = 0
            for _pass in range(10):
                if stop_event.is_set():
                    return
                result = await _call("explore", {"url": seed, "submit_forms": submit_forms})
                remaining = int(result.get("frontier_remaining", 0) or 0)
                last_visited = int(result.get("routes_visited", 0) or 0)
                await self._broadcast_autonomous(sid, "explore_progress", {
                    "host": host, "routes_visited": last_visited, "frontier_remaining": remaining,
                })
                if remaining == 0 or remaining == prev_frontier:
                    break
                prev_frontier = remaining

            # Coordinator decision (NOT automatic): normal DOM/accessibility
            # navigation found no routes on an app that is clearly authenticated
            # and rendering (its own traffic reached the store). The nav is likely
            # a web-component/canvas UI with no enumerable structure — try VISION
            # navigation once (cheap multimodal model, bounded in the explorer).
            if last_visited <= 1 and len(self._store.in_scope_entries()) > 3:
                logger.info("complete-mode: normal nav found no routes — trying vision", host=host)
                await self._broadcast_autonomous(sid, "vision_fallback", {"host": host})
                await _call("explore", {"url": seed, "submit_forms": submit_forms, "vision": True})

            if read_only:
                continue  # active tools below are blocked in read-only

            # 2) Scan every observed-but-unscanned endpoint to exhaustion.
            #    Surface comes from REAL navigation (the explore above) + the
            #    authenticated app's own traffic — NOT wordlist forced-browsing.
            #    content_discovery remains an explicit tool the operator/LLM can
            #    invoke, but the complete sweep no longer brute-forces paths from
            #    files (noisy, false-positive-prone on SPAs).
            await _loop_until_zero("scan_surface", {}, "remaining")
            # 4) GraphQL: introspect+sweep, or fuzz captured ops when introspection is off.
            await self._auto_test_graphql(session, ctx, hosts={host})
            # 5) Auto-route the unambiguous evidence recommendations (id -> sqli/idor,
            #    AI endpoint -> llm_injection, etc.) — breadth not left to the LLM.
            await self._auto_route(session, ctx, hosts={host})

    async def _auto_test_graphql(self, session: dict, ctx: Any, hosts: set) -> None:
        """Automatically test every GraphQL endpoint seen in traffic for the given
        hosts: introspect, then sweep its schema — or, when introspection is
        disabled, fuzz the operations captured from traffic. Idempotent (already
        tested ops are skipped) so it is safe to call every turn. No-op in
        read-only (the GraphQL query/fuzz traffic is active and network-blocked).
        This is what makes 'see a GraphQL endpoint -> test it' happen without the
        operator or the LLM having to ask for it."""
        from dast.plugins.graphql_analyzer import _is_graphql
        from dast.tools import run_tool

        auto = session["autonomous"]
        if auto.get("read_only"):
            return
        stop_event: asyncio.Event = auto["stop_event"]
        store = self._ctx.store
        if store is None:
            return

        gql_urls = set()
        try:
            for entry in store.in_scope_entries():
                if _is_graphql(entry) and (getattr(entry, "host", "") or "").split(":")[0] in hosts:
                    gql_urls.add(entry.url)
        except Exception as exc:  # noqa: BLE001
            logger.debug("auto-graphql: enumeration failed", error=str(exc))
            return

        async def _call(tool: str, args: dict) -> dict:
            try:
                result = await run_tool(ctx, tool, args)
                return result if isinstance(result, dict) else {}
            except Exception as exc:  # noqa: BLE001
                logger.warning("auto-graphql tool failed", tool=tool, error=str(exc))
                return {}

        for gql_url in gql_urls:
            if stop_event.is_set():
                return
            intro = await _call("graphql_introspect", {"url": gql_url})
            op_tool = "graphql_sweep" if intro.get("ok") else "graphql_fuzz"
            logger.info("auto-graphql: testing endpoint", url=gql_url, via=op_tool)
            prev = -1
            for _ in range(12):
                if stop_event.is_set():
                    return
                result = await _call(op_tool, {"url": gql_url})
                remaining = int(result.get("operations_remaining", 0) or 0)
                if remaining == 0 or remaining == prev:
                    break
                prev = remaining

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
        mode = auto.get("mode", "bounded")

        # Complete mode: force an exhaustive explore of each focus host up front so
        # the UI-route frontier is seeded and has_surface is True — this closes the
        # path where an early self-declared 'complete' is honored because nothing
        # was mapped yet. Best-effort; never blocks the run on a crawl failure.
        if mode == "complete" and not auto.get("initial_explore_done"):
            await self._deterministic_recon_scan_sweep(sid, session)
            auto["initial_explore_done"] = True

        hosts_label = ", ".join(auto["hosts"]) or "the in-scope target(s)"
        read_only_note = _READ_ONLY_DIRECTIVE + "\n\n" if auto.get("read_only") else ""
        prompt = _AUTONOMOUS_START.format(
            objective=auto["objective"], hosts=hosts_label,
            leads=self._leads_label(auto["hosts"]),
            router=self._router_block(auto["hosts"]),
            coverage=self._coverage_block(self._surface_coverage(auto["hosts"])),
            read_only=read_only_note,
        )

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
                # Complete mode never stops on 'stuck' — only the operator, the
                # wall-clock, or genuine exhaustion ends it. Bounded mode is unchanged.
                if mode != "complete" and stuck_turns >= cfg["max_stuck_turns"]:
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
                        leads=self._leads_label(auto["hosts"]),
                        router=self._router_block(auto["hosts"]),
                        coverage=self._coverage_block(self._surface_coverage(auto["hosts"])),
                        read_only=read_only_note,
                    )
                    continue

                session["last_reply"] = {
                    "message": reply.message,
                    "blocked_reason": reply.blocked_reason,
                }
                blocked_reason = (reply.blocked_reason or "").strip().lower()

                # ── Auto-test any GraphQL endpoint seen so far ───────────────────
                # The moment the copilot's traffic surfaces a GraphQL endpoint, test
                # it (introspect -> sweep, or fuzz captured ops) without waiting for
                # the model to decide to. Idempotent; no-op in read-only. Runs in
                # bounded AND complete mode so "see GraphQL -> test GraphQL" is
                # guaranteed, not discretionary.
                if auto.get("hosts"):
                    turn_ctx = self._build_tool_ctx(session)
                    await self._auto_test_graphql(session, turn_ctx, set(auto["hosts"]))
                    # Evidence-driven auto-routing of the unambiguous leads (bounded
                    # and complete). The prompt block surfaces the rest for the LLM.
                    await self._auto_route(session, turn_ctx, set(auto["hosts"]))

                # ── Progress / stuck accounting ──────────────────────────────────
                progress = self._progress_snapshot()
                if progress != last_progress:
                    stuck_turns = 0
                    last_progress = progress
                else:
                    stuck_turns += 1

                # ── Interpret the reply's control signal ─────────────────────────
                if blocked_reason == "complete":
                    coverage = self._surface_coverage(auto["hosts"])
                    budget_left = (time.time() < deadline
                                   and auto["tool_calls"] < cfg["max_tool_calls"])
                    # A 'complete' is only premature when a surface has actually been
                    # mapped and part of it is still untested. With nothing discovered
                    # yet there is no coverage to force (the crawl-first prompt already
                    # pushes discovery), and a fully-tested surface is genuinely done.
                    # In read-only mode scan_surface/graphql_sweep are disabled, so a
                    # scan-based coverage gap can never be closed — don't bounce 'complete'.
                    # In complete mode, ANY gap (unscanned REST, unswept GraphQL, or an
                    # unexplored UI route in the frontier) blocks 'complete' — so the run
                    # keeps exploring/scanning until the whole surface is covered. In
                    # bounded mode, a gap only counts when a surface was mapped (nothing
                    # mapped = nothing to force). Read-only can't close scan gaps, so it
                    # never bounces for them (the explorer still drains the UI frontier).
                    if mode == "complete":
                        surface_incomplete = not coverage["complete"] and not auto.get("read_only")
                    else:
                        surface_incomplete = (coverage["has_surface"] and not coverage["complete"]
                                              and not auto.get("read_only"))
                    # Coverage gate: refuse a premature 'complete' while known surface is
                    # not fully tested and there is budget headroom. In complete mode the
                    # rejection cap does not apply — the operator decides when to stop.
                    rejection_headroom = (mode == "complete"
                                          or auto["complete_rejections"] < _MAX_COMPLETE_REJECTIONS)
                    if surface_incomplete and budget_left and rejection_headroom:
                        auto["complete_rejections"] += 1
                        logger.info(
                            "autonomous run: coverage gate rejected premature complete",
                            session_id=sid, rejection=auto["complete_rejections"],
                            rest_untested=len(coverage["rest_untested"]),
                            gql_untested=len(coverage["gql_untested"]),
                        )
                        await self._broadcast_autonomous(sid, "coverage_gate", {
                            "rest_untested": len(coverage["rest_untested"]),
                            "gql_untested": len(coverage["gql_untested"]),
                            "ui_frontier": len(coverage["ui_frontier"]),
                            "rejection": auto["complete_rejections"],
                        })
                        # Complete mode closes gaps deterministically rather than
                        # relying on the LLM to do breadth: drain the frontier, scan
                        # every endpoint, fuzz/sweep GraphQL. Then re-prompt for depth.
                        if mode == "complete":
                            await self._deterministic_recon_scan_sweep(sid, session)
                        prompt = _AUTONOMOUS_COVERAGE_GATE.format(
                            coverage=self._coverage_block(self._surface_coverage(auto["hosts"])),
                            budget=self._budget_label(auto, cfg, deadline),
                        )
                        continue

                    if not surface_incomplete:
                        # Fully-covered surface, or nothing mapped to cover — honor it.
                        message = ("objective complete; full surface covered"
                                   if coverage["has_surface"]
                                   else "objective complete")
                        self._finish_autonomous(session, "complete", message)
                        await self._broadcast_autonomous(sid, "finished", {
                            "status": "complete", "message": reply.message,
                        })
                        return

                    # Budget/rejection headroom is gone but the surface is not fully
                    # covered — end honestly, naming what was left untested (no silent cap).
                    detail = (
                        f"objective complete but coverage incomplete: "
                        f"{len(coverage['rest_untested'])} REST endpoint(s) and "
                        f"{len(coverage['gql_untested'])} GraphQL operation(s) untested "
                        f"({self._coverage_label(coverage)})"
                    )
                    logger.warning("autonomous run: completed with incomplete coverage",
                                   session_id=sid,
                                   rest_untested=len(coverage["rest_untested"]),
                                   gql_untested=len(coverage["gql_untested"]))
                    self._finish_autonomous(session, "complete", detail)
                    await self._broadcast_autonomous(sid, "finished", {
                        "status": "complete", "message": reply.message,
                        "coverage_incomplete": True,
                        "rest_untested": len(coverage["rest_untested"]),
                        "gql_untested": len(coverage["gql_untested"]),
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
                    leads=self._leads_label(auto["hosts"]),
                    router=self._router_block(auto["hosts"]),
                    coverage=self._coverage_block(self._surface_coverage(auto["hosts"])),
                    read_only=read_only_note,
                )
        except asyncio.CancelledError:
            self._finish_autonomous(session, "stopped", "cancelled")
        except Exception as exc:
            logger.error("autonomous driver crashed", session_id=sid, error=str(exc))
            self._finish_autonomous(session, "error", f"driver error: {str(exc)[:200]}")
            await self._broadcast_autonomous(sid, "finished", {"status": "error"})

    @staticmethod
    def _progress_label(progress: Tuple[int, int, int]) -> str:
        findings, endpoints = progress[0], progress[1]
        return f"{findings} findings across {endpoints} in-scope endpoints"

    @staticmethod
    def _budget_label(auto: dict, cfg: dict, deadline: float) -> str:
        remaining = max(0, int(deadline - time.time()))
        return (f"{auto['tool_calls']}/{cfg['max_tool_calls']} tool calls used, "
                f"{remaining}s of wall-clock left")

    def _surface_coverage(self, hosts: List[str]) -> Dict[str, object]:
        """Enumerate the discovered in-scope attack surface for the focus hosts and how
        much of it has been tested. REST endpoints are distinct (host, method,
        id-normalised path) over real observed traffic, tested once a representative has
        a scan_result. GraphQL operations are every introspected query/mutation, tested
        once graphql_sweep records them on ``store.graphql_tested_ops``.

        ``complete`` is True only when a surface exists AND nothing on it is untested —
        so 'nothing mapped yet' does not read as 'fully covered'. Best-effort: any error
        degrades to an empty (incomplete) coverage rather than crashing the run."""
        from dast.plugins.graphql_analyzer import _is_graphql
        from dast.proxy.session_store import normalise_endpoint_path
        from dast.proxy.ui_route_graph import normalise_route_key

        cov: Dict[str, object] = {
            "rest_total": 0, "rest_tested": 0, "rest_untested": [],
            "gql_total": 0, "gql_tested": 0, "gql_untested": [],
            "gql_captured_total": 0, "gql_captured_tested": 0, "gql_captured_untested": [],
            "ui_total": 0, "ui_visited": 0, "ui_frontier": [],
            "has_surface": False, "complete": False,
        }
        store = self._ctx.store
        if store is None:
            return cov
        focus = {h.split(":")[0] for h in (hosts or []) if h}

        # ── REST surface ────────────────────────────────────────────────────────
        try:
            entries = store.in_scope_entries()
        except Exception as exc:  # noqa: BLE001 — coverage is best-effort
            logger.debug("coverage: rest enumeration failed", error=str(exc))
            entries = []
        rest_status: Dict[Tuple[str, str, str], bool] = {}
        for entry in entries:
            method = (getattr(entry, "method", "") or "").upper()
            path = getattr(entry, "path", "") or ""
            if not method or not path:
                continue  # not a real observed request — skip
            if method in ("CONNECT", "OPTIONS", "HEAD"):
                continue
            if getattr(entry, "source", "") in ("agent", "scanner", "scan", "out-of-scope"):
                continue
            # GraphQL endpoints are covered by the GraphQL dimensions (sweep/fuzz),
            # not by scan_surface — don't double-count them as untested REST.
            if _is_graphql(entry):
                continue
            host = (getattr(entry, "host", "") or "").split(":")[0]
            if focus and host not in focus:
                continue
            key = (host, method, normalise_endpoint_path(path))
            tested = bool(getattr(entry, "scan_result", None))
            rest_status[key] = rest_status.get(key, False) or tested
        cov["rest_total"] = len(rest_status)
        cov["rest_tested"] = sum(1 for tested in rest_status.values() if tested)
        cov["rest_untested"] = sorted(
            f"{method} {path}" for (_h, method, path), tested in rest_status.items() if not tested
        )

        # ── GraphQL surface ─────────────────────────────────────────────────────
        schemas = getattr(store, "graphql_schemas", None) or {}
        tested_ops = getattr(store, "graphql_tested_ops", None) or {}
        for endpoint, schema in schemas.items():
            if not isinstance(schema, dict) or not schema.get("introspected"):
                continue
            host = (urlparse(endpoint).hostname or "").split(":")[0]
            if focus and host not in focus:
                continue
            done = tested_ops.get(endpoint) or set()
            for kind, bucket_name in _GQL_BUCKETS.items():
                for field_name in (schema.get(bucket_name) or {}):
                    cov["gql_total"] += 1
                    if f"{kind}:{field_name}" in done:
                        cov["gql_tested"] += 1
                    else:
                        cov["gql_untested"].append(f"{kind} {field_name}")

        # ── Captured-GraphQL surface (schema-free; prod introspection disabled) ──
        # Distinct GraphQL operations observed in traffic, tested once graphql_fuzz
        # records "fuzz:<op>". This is the coverage dimension for endpoints where
        # introspection is off (so gql_total above stays 0).
        try:
            from dast.plugins.graphql_analyzer import _is_graphql
            from dast.tools.graphql_fuzz_tools import _op_key
            import json as _json
            captured: Dict[str, set] = {}
            for entry in entries:
                if not _is_graphql(entry):
                    continue
                host = (getattr(entry, "host", "") or "").split(":")[0]
                if focus and host not in focus:
                    continue
                raw = getattr(entry, "request_body", None)
                if not raw:
                    continue
                parsed = _json.loads(raw[:200000].decode("utf-8", errors="replace"))
                for item in (parsed if isinstance(parsed, list) else [parsed]):
                    if not isinstance(item, dict) or not isinstance(item.get("query"), str):
                        continue
                    if not (item.get("variables") or {}):
                        continue
                    captured.setdefault(entry.url, set()).add(_op_key(item))
            for endpoint, keys in captured.items():
                done = tested_ops.get(endpoint) or set()
                for key in keys:
                    cov["gql_captured_total"] += 1
                    if f"fuzz:{key}" in done:
                        cov["gql_captured_tested"] += 1
                    else:
                        cov["gql_captured_untested"].append(key)
        except Exception as exc:  # noqa: BLE001 — coverage is best-effort
            logger.debug("coverage: captured-graphql enumeration failed", error=str(exc))

        # ── UI-route surface (SPA exploration frontier) ─────────────────────────
        graph = getattr(store, "ui_route_graph", None)
        if graph is not None:
            try:
                for route in graph.visited() + graph.frontier():
                    host = normalise_route_key(route.url).split("/")[0].split(":")[0]
                    if focus and host not in focus:
                        continue
                    cov["ui_total"] += 1
                    if route.state == "visited":
                        cov["ui_visited"] += 1
                    else:
                        cov["ui_frontier"].append(route.url)
            except Exception as exc:  # noqa: BLE001 — coverage is best-effort
                logger.debug("coverage: ui enumeration failed", error=str(exc))

        cov["has_surface"] = (cov["rest_total"] > 0 or cov["gql_total"] > 0
                              or cov["gql_captured_total"] > 0 or cov["ui_total"] > 0)
        cov["complete"] = bool(
            cov["has_surface"] and not cov["rest_untested"] and not cov["gql_untested"]
            and not cov["gql_captured_untested"] and not cov["ui_frontier"]
        )
        return cov

    @staticmethod
    def _coverage_label(cov: Dict[str, object]) -> str:
        return (f"{cov['rest_tested']}/{cov['rest_total']} REST endpoints, "
                f"{cov['gql_tested']}/{cov['gql_total']} GraphQL operations tested")

    def _coverage_block(self, cov: Dict[str, object]) -> str:
        """Prompt block describing the remaining untested surface and which breadth tool
        closes each gap. Injected into every autonomous turn so the copilot keeps pushing
        toward full coverage."""
        if not cov["has_surface"]:
            return ("Coverage: no attack surface mapped yet — crawl the app and run "
                    "graphql_introspect on every GraphQL endpoint to enumerate what must be tested.")
        if cov["complete"]:
            return ("Coverage: full — every observed REST endpoint and introspected GraphQL "
                    "operation has been tested.")
        lines = ["Coverage gaps remain — you have NOT tested the whole surface "
                 f"({self._coverage_label(cov)}):"]
        # Endpoint paths and GraphQL field names are derived from observed target
        # traffic / introspection, so they are attacker-influenceable content — a
        # crafted route or field name could carry prompt-injection text. Fence the
        # examples so they cannot be read as instructions (the copilot system prompt
        # already carries UNTRUSTED_CONTENT_DIRECTIVE).
        rest_untested = cov["rest_untested"]
        if rest_untested:
            lines.append(
                f"- {len(rest_untested)} REST endpoint(s) unscanned. Run scan_surface (scans every "
                f"untested endpoint) and crawl to widen the surface. Examples: "
                + wrap_untrusted(", ".join(rest_untested[:8]), "untested_rest_endpoints")
            )
        gql_untested = cov["gql_untested"]
        if gql_untested:
            lines.append(
                f"- {len(gql_untested)} GraphQL operation(s) untested. Run graphql_sweep on the "
                f"endpoint (covers every query/mutation) until operations_remaining is 0. Examples: "
                + wrap_untrusted(", ".join(gql_untested[:8]), "untested_gql_operations")
            )
        gql_captured_untested = cov.get("gql_captured_untested") or []
        if gql_captured_untested:
            lines.append(
                f"- {len(gql_captured_untested)} captured GraphQL operation(s) not yet fuzzed "
                f"(introspection disabled). Run graphql_fuzz on the endpoint until "
                f"operations_remaining is 0. Examples: "
                + wrap_untrusted(", ".join(gql_captured_untested[:8]), "unfuzzed_gql_operations")
            )
        ui_frontier = cov.get("ui_frontier") or []
        if ui_frontier:
            lines.append(
                f"- {len(ui_frontier)} UI route(s) discovered but not yet explored. Run `explore` "
                f"on the app until frontier_remaining is 0 to reach every section. Examples: "
                + wrap_untrusted(", ".join(ui_frontier[:8]), "unexplored_ui_routes")
            )
        return "\n".join(lines)

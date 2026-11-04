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

# Uniform-failure breaker: if a turn adds at least _UNIFORM_FAIL_MIN_NEW in-scope
# requests and NONE got a 2xx, that is a failing turn; _MAX_UNIFORM_FAIL_TURNS such
# turns in a row stop the run (403/null floods read as progress otherwise).
_UNIFORM_FAIL_MIN_NEW = 5
_MAX_UNIFORM_FAIL_TURNS = 2

# Proactive session keepalive: between turns the browser navigates to a known
# authenticated URL so the SSO session cookie is refreshed server-side before it
# expires. 20 minutes is well within typical 1h SSO windows.
_SESSION_KEEPALIVE_INTERVAL = 1200.0

# How many times the coverage gate may bounce a premature 'complete' before letting the
# run end anyway (with an honest "coverage incomplete" report). Guards against a loop
# where the copilot cannot make coverage progress; the stuck detector is the other bound.
_MAX_COMPLETE_REJECTIONS = 8
# How many times the engine may report a stuck_loop (an agent repeating the same
# normalized call) before the coordinator KILLS the run instead of re-prompting it.
_MAX_STUCK_LOOPS = 2

# GraphQL schema buckets, matching the compact schema stored by graphql_introspection.
_GQL_BUCKETS = {"query": "queries", "mutation": "mutations"}

# Per-dimension coverage: map Frieren's agent attack_type vocabulary onto the pentest
# test dimensions an operator reasons about, so coverage can report "injection tested,
# access-control not" per endpoint instead of a single tested/untested bit.
_ATTACK_TYPE_DIMENSION = {
    # injection family
    "xss": "injection", "sqli": "injection", "cmdi": "injection", "ssti": "injection",
    "nosql": "injection", "xxe": "injection", "lfi": "injection", "file_read": "injection",
    "ssrf": "injection", "prototype_pollution": "injection", "host_header": "injection",
    "open_redirect": "injection", "cache_poisoning": "injection", "blazor": "injection",
    "graphql": "injection", "oob_headers": "injection",
    # access control / authz / token / info-disclosure
    "idor": "access_control", "auth": "access_control", "auth_bypass": "access_control",
    "mfa_bypass": "access_control", "jwt": "access_control", "sensitive_data": "access_control",
    # cross-tenant (multi-user replay) — only applicable with >=2 named sessions
    "cross_session_idor": "cross_tenant",
    # business logic (incl. mass assignment + race conditions)
    "business_logic": "business_logic", "race_condition": "business_logic",
    # prompt / LLM injection
    "llm_injection": "llm_injection",
    # csrf
    "csrf": "csrf",
}
# Order shown to the operator / model.
_COVERAGE_DIMENSIONS = ("injection", "access_control", "cross_tenant",
                        "business_logic", "llm_injection", "csrf")

def _order_hosts(hosts) -> List[str]:
    """Sorted host list with identity-provider hosts pushed to the end.

    The autonomous sweep iterates this order, so the IdP (whose probing kills the
    shared SSO session) is only reached after the rest of the surface is covered."""
    from dast.proxy.session_store import is_identity_host
    return sorted(hosts, key=lambda host: (is_identity_host(host), host))

# blocked_reason values that mean "I cannot proceed without a human" — the driver
# turns these into an operator escalation (answer / pause / abort) then resumes.
_ESCALATE_REASONS = frozenset({
    "need_human", "need_value", "need_authorization", "need_authorisation",
    "out_of_scope", "auth_required", "waf_block",
})

# "Soft" escalations: the copilot is unsure or asking permission for a next step it
# could just take. In an autonomous run these are not real blockers — the driver
# auto-nudges it to proceed instead of pausing the operator. The "hard" reasons
# (auth_required/out_of_scope/need_authorization/waf_block) genuinely need operator
# action and still pause immediately.
_SOFT_ESCALATE_REASONS = frozenset({"need_human", "need_value"})
# Soft escalations auto-nudged before a real human pause, per no-progress streak.
_MAX_AUTO_GUIDANCE_NUDGES = 3

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
    "- browser_navigate / browser_snapshot / browser_fill / browser_click to INTERACT with the "
    "app like a real user: load pages, read form structures, fill fields, click buttons. This is "
    "how you understand what each endpoint does and what parameters mean before you test them.\n"
    "- browser_fetch to make authenticated API calls (GraphQL, REST) from inside the browser. "
    "It uses the browser's own cookies (session, CSRF) automatically — more reliable than "
    "send_request for SPAs. Use after logging in via browser tools.\n"
    "- send_request / validate_chain ONLY for a targeted check no dedicated tool covers.\n"
    "- code_list / code_lookup_path / code_search / code_file — IF the target's source is loaded "
    "(call code_list; non-empty means it is), read the handler for an endpoint (code_lookup_path on "
    "its URL path) to learn its real parameters, auth checks, and sinks BEFORE testing it, instead "
    "of guessing. Do not assume source is loaded; skip these if code_list is empty.\n"
    "BE A PENTESTER, NOT A SCANNER. Your edge over the automated agents is UNDERSTANDING the app:\n"
    "0. AUTHENTICATE like a human: if you have credentials, use browser_navigate to the login "
    "page, browser_snapshot to see the form, browser_fill to enter email/password, browser_click "
    "to submit. This gives you session cookies AND CSRF tokens (set on page load). Then use "
    "send_request for API testing — the cookies from the browser are in the proxy jar. Never "
    "skip this step and go straight to send_request with raw cookies — apps need CSRF tokens "
    "that are only set when a real browser loads the page.\n"
    "1. EXPLORE interactively: browser_navigate to key pages, browser_snapshot to read what the "
    "UI shows (forms, fields, user data, role indicators). Read get_history to see the API calls "
    "each page makes. Decode JWTs and reason about claims/roles/expiry.\n"
    "2. REASON about parameters: for every state-changing endpoint, examine each parameter by "
    "name. Is it an identity field (user_id, email, account_id, org_id)? A role/privilege "
    "field (role, is_admin, permission)? A resource reference (file_path, url, redirect)? "
    "Each category implies a specific test.\n"
    "3. TEST with precision: IDOR/BOLA by swapping identity values, mass assignment by adding "
    "role/privilege fields the client does not send, privilege escalation by replaying a "
    "low-privilege session's request against a high-privilege endpoint (use idor_probe when the "
    "pattern is stored-object BOLA). Always compare against a baseline — a finding needs a "
    "differential, not a guess.\n"
    "Any time delay <= 5s. Reading an endpoint and moving on WITHOUT testing it is a failure.\n"
    "Write requests (POST/PUT/PATCH/DELETE) are expected and authorized for testing — you "
    "cannot test access controls without them. 'Destructive' means mass deletion, DoS, or "
    "irreversible corruption — not normal CRUD for testing. Always clean up after write tests.\n\n"
    "RECORDING FINDINGS — when a test confirms a vuln, call record_finding IMMEDIATELY:\n"
    "- 201/200 creating a system/global resource as regular tenant = privilege escalation (record it)\n"
    "- 200 PATCHing/GETting with a foreign tenant ID = IDOR (record it)\n"
    "- 200/204 from endpoint with no auth = missing authentication (record it)\n"
    "- Response has different account_id = cross-tenant disclosure (record it)\n"
    "Do NOT say 'this is an authorized test, not a finding' — the TEST RESULT IS the finding.\n"
    "Include title, severity, description, and steps (request/response evidence).\n"
    "After recording, clean up: DELETE created objects, revert PATCHed fields to original.\n"
    "For PATCH: GET original state FIRST, test, record finding, then revert.\n\n"
    "PENTEST MINDSET — be resilient, not passive:\n"
    "- If a request fails (401, 302 to login, timeout), retry with a different approach "
    "before asking the operator. Try: re-login with browser_login, use cookies from "
    "get_history, try a different path.\n"
    "- If session expired, use browser_login to re-authenticate immediately — do not ask "
    "the operator unless MFA is needed and the browser is headless.\n"
    "- If a URL returns 404 or you are unsure of the hostname, check get_history for the "
    "correct host and path pattern, then retry. NEVER invent placeholder hostnames.\n"
    "- Only block and ask the operator for: captcha that needs human eyes, MFA OTP entry "
    "in a headless browser, credentials you do not have.\n"
    "- Never describe the same error twice without trying a fix between descriptions.\n\n"
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
    "graphql_sweep, run_scan, scan_surface, crawl, param_mining, record_finding, "
    "browser_navigate, browser_snapshot, send_request, and code_lookup_path/code_search when "
    "source is loaded), and actively TEST leads "
    "(IDOR/BOLA/XSS/privilege/mass-assignment/param-tampering) with parameter-level reasoning, "
    "don't just map them.\n"
    "{read_only}"
    "Progress so far: {progress}. Budget remaining: {budget}.\n\n"
    "{leads}\n\n"
    "{router}"
    "{coverage}\n\n"
    "If a request fails (401/timeout/302-to-login), retry with a different approach "
    "(re-login, different cookies, correct URL from get_history) before blocking. Only "
    "block for genuinely unresolvable issues (captcha, missing credentials, MFA in headless).\n"
    "Set blocked_reason='complete' ONLY once the objective is covered, the high-value leads "
    "have been actively tested, AND no coverage gaps remain; or 'need_human' if you are truly "
    "blocked (say what a vulnerable vs. normal response would look like)."
)

_AUTONOMOUS_STUCK_LOOP = (
    "LOOP BROKEN BY THE COORDINATOR. You repeated the same request over and over with no "
    "new result:\n{detail}\n\n"
    "Root cause: do NOT paste Cookie or X-CSRF-Token headers into send_request — the tool "
    "manages the session for the active identity (activate_login_profile / the named session). "
    "Pasting a header literal pins a stale session and changes nothing.\n"
    "Do something DIFFERENT now: a different endpoint, a different parameter, or a different "
    "tool (scan_surface, run_scan, run_multiuser_idor, idor_probe). If you have genuinely "
    "exhausted this endpoint, move to the next one or conclude. Budget: {budget}.\n\n"
    "{coverage}"
)

_AUTONOMOUS_SELF_PROCEED = (
    "You set blocked_reason='{reason}', but this is NOT a genuine blocker — you do not need my "
    "permission to run safe, in-scope next steps you have already planned. Proceed autonomously "
    "right now: execute your plan with the internal tools (run_scan, scan_surface, idor_probe, "
    "param_mining, validate_chain, record_finding, browser_navigate, browser_snapshot, "
    "send_request). Reserve a blocked_reason for a TRUE blocker "
    "only I can resolve: a credential/value I hold, or an out-of-scope authorization decision — "
    "never to confirm a step you can already take. Progress: {progress}. Budget: {budget}.\n\n"
    "{leads}\n\n"
    "{router}"
    "{coverage}"
)

_AUTONOMOUS_COVERAGE_GATE = (
    "You set 'complete', but you have NOT tested the whole attack surface — that is premature. "
    "Do not stop yet.\n\n"
    "{coverage}\n\n"
    "Close these gaps now: run scan_surface until it reports remaining=0, and graphql_sweep on "
    "each introspected GraphQL endpoint until operations_remaining=0 (crawl / graphql_introspect "
    "first if the surface is not yet mapped). Then go deep on anything they flag.\n\n"
    "After closing automated scan gaps, go DEEP on the high-value leads: examine state-changing "
    "endpoints for business-logic bugs (identity parameter manipulation, mass assignment, "
    "privilege boundaries) using browser_navigate + browser_snapshot to understand the UI, then "
    "send_request with parameter-level reasoning. The automated agents cover injection vulns; "
    "your job in this phase is the auth/logic bugs they miss. Budget "
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
        # Shared AgentBrowser across all copilot sessions — login state, cookies,
        # and page context persist between messages. One browser window, never
        # recreated unless closed or crashed.
        self._shared_browser: Any = None

    async def close_browser(self) -> None:
        """Close the shared AgentBrowser (e.g. on proxy shutdown)."""
        if self._shared_browser is not None:
            try:
                await self._shared_browser.close()
            except Exception as exc:
                logger.debug("shared AgentBrowser close error", error=str(exc))
            self._shared_browser = None

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

    def _init_engine(self, sid: str, focus_hosts: Optional[List[str]] = None):
        from dast.ai.copilot import CopilotSession
        engine = CopilotSession(sid, focus_hosts=focus_hosts)
        engine._store = self._ctx.store
        return engine

    def new_session(self, focus_hosts: Optional[List[str]] = None) -> str:
        sid = str(uuid.uuid4())[:12]
        self._sessions[sid] = {
            "engine": self._init_engine(sid, focus_hosts),
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

    async def _session_keepalive(self, sid: str, session: dict) -> bool:
        """Navigate the browser to a known host to keep the SSO session alive.

        The browser request goes through the proxy, so the proxy jar captures any
        refreshed Set-Cookie headers. Then ``refresh_session`` propagates the fresh
        cookies into the copilot engine. Returns True if cookies were refreshed."""
        auto = session.get("autonomous")
        if not auto:
            return False
        hosts = auto.get("hosts") or []
        if not hosts:
            return False
        browser = session.get("_agent_browser")
        if browser is None:
            return False

        target_url = f"https://{hosts[0]}/"
        try:
            result = await browser.navigate(target_url, timeout_ms=15000)
            status = result.get("status")
            final_url = result.get("url", "")
            logger.info("session keepalive: browser visit complete",
                        sid=sid, target=target_url, status=status, final_url=final_url)
        except Exception as exc:
            logger.warning("session keepalive: browser navigation failed",
                           sid=sid, target=target_url, error=str(exc))
            return False

        refreshed = self.refresh_session(sid)
        cookies = refreshed.get("cookies_refreshed", 0)
        if cookies:
            logger.info("session keepalive: cookies propagated to engine",
                        sid=sid, cookies=cookies)
            await self._broadcast_autonomous(sid, "session_keepalive", {
                "cookies_refreshed": cookies,
            })
        return cookies > 0

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
        # Shared AgentBrowser across ALL copilot sessions — login state, cookies,
        # and page context persist between messages. Created lazily on first use;
        # recreated if closed or crashed.
        browser = self._shared_browser
        if browser is None or getattr(browser, "_browser", None) is None:
            try:
                from dast.browser.agent_browser import AgentBrowser
                browser = AgentBrowser(
                    proxy_port=ctx.proxy_port, store=ctx.store,
                    read_only=bool((session.get("autonomous") or {}).get("read_only", False)),
                )
                self._shared_browser = browser
            except Exception as exc:
                logger.warning("could not create AgentBrowser", error=str(exc))
                browser = None
        session["_agent_browser"] = browser
        tool_ctx = AgentToolContext(
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
        # Attach the engine session so tools (e.g. browser_login) can record the last
        # successful login on it. Without this the engine's auto-relogin on 401/expiry
        # (session.py) stays dormant because `_last_login` is never populated.
        tool_ctx._session = session.get("engine")
        # Validation-only runs hide breadth/recon tools from the model (enforced in
        # the engine's tool-menu build) so it tests only the finding's endpoint.
        tool_ctx.validation_only = bool(
            (session.get("autonomous") or {}).get("validation_only", False))
        return tool_ctx

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
        validation_only: bool = False,
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
        # Validation-only: test ONLY the finding's endpoint — no breadth. Force bounded
        # so the complete-mode exhaustive sweep never runs; the per-turn auto-graphql /
        # auto-route breadth is also skipped in _drive_autonomous.
        if validation_only:
            mode = "bounded"

        # With a login profile, authentication is handled server-side: _activate_profile
        # seeds the session cookies and arms credential auto-relogin. The model is NOT
        # given the password, so the base "authenticate like a human" step would make it
        # invent a placeholder credential and hammer the login. Tell it to skip that.
        if profile_slug:
            objective = (
                objective
                + "\n\nAUTHENTICATION (handled for you — overrides any 'authenticate like a human' "
                f"step): you were logged in at run start via the active profile '{profile_slug}'. A "
                "session (cookies + CSRF) is loaded and auto-relogins from the profile on 401/expiry, "
                "so just make your requests. You do NOT have the password: never type or invent one, "
                "and do not call login tools with made-up credentials. If you still land on a login "
                "page or stay unauthenticated, the profile login failed — report it as a blocker "
                "(record_finding or reply to the operator); do not guess credentials."
            )

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
            "validation_only": bool(validation_only),
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

        # Defer identity-provider hosts for the main run: the ambient auto-scan and
        # scan_surface skip them so probing the IdP cannot log the run out mid-scan.
        # The driver lifts this for a final phase that tests the IdP last.
        if self._ctx.store is not None:
            self._ctx.store.defer_identity_hosts = True

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
        # Clear stale pause state so the UI does not show guidance controls
        # on a stopped session.
        session["pause"] = None
        auto["status"] = "stopped"
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
        if profile is None:
            logger.warning("autonomous run: login profile not found", slug=slug)
            return
        # Cookie import only applies to a profile that captured a live session.
        # A fresh credential-only profile has none — that is NOT a reason to skip
        # the credential seeding below (which is what arms auto-login).
        if profile.saved_session:
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
        else:
            logger.info("autonomous run: profile has no saved session; relying on "
                        "credential auto-login", slug=slug)
        # Seed the engine's relogin credentials from the profile so the existing
        # 401/expiry auto-relogin (session.py) can re-authenticate WITHOUT pausing the
        # run. Needs a credential + auth_url on the profile; cookie-only profiles skip this.
        try:
            creds = getattr(profile, "credentials", None) or []
            auth_url = (getattr(profile, "auth_url", "") or "").strip()
            engine = session.get("engine")
            if engine is not None and auth_url and creds and creds[0].username and creds[0].secret:
                engine._last_login = {
                    "url": auth_url, "email": creds[0].username, "password": creds[0].secret,
                }
                logger.info("autonomous run seeded relogin credentials from profile", slug=slug)
            elif engine is not None:
                logger.info("autonomous run: profile has no credentials for auto-relogin", slug=slug)
        except Exception as exc:
            logger.warning("autonomous run: relogin-credential seed failed", slug=slug, error=str(exc))

    async def _ensure_profile_login(self, sid: str, session: dict) -> None:
        """Proactively log in a credential-only profile at run start so the run begins
        authenticated. The model never receives the password; this uses the credentials
        seeded onto the engine (``engine._last_login``) by ``_activate_profile`` and the
        same ``adaptive_login`` cascade as the inline 401 auto-relogin. Best-effort: never
        raises, never deadlocks the run, never logs secret values."""
        auto = session.get("autonomous") or {}
        if auto.get("_proactive_login_done"):
            return
        engine = session.get("engine")
        creds = getattr(engine, "_last_login", None) if engine is not None else None
        if not creds or not creds.get("url") or not creds.get("email") or not creds.get("password"):
            return  # no credentials to use — the model will report any auth wall itself
        auto["_proactive_login_done"] = True
        try:
            tool_ctx = self._build_tool_ctx(session)
            browser = getattr(tool_ctx, "browser", None)
            if browser is None:
                logger.warning("autonomous run: no browser for proactive login", session_id=sid)
                return
            from dast.browser.login_cascade import adaptive_login
            result = await adaptive_login(
                browser, creds["url"], creds["email"], creds["password"],
                in_scope=tool_ctx.is_in_scope, store=self._ctx.store, session=engine,
            )
            if getattr(result, "ok", False):
                try:
                    cookies = await browser.export_cookies()
                except Exception:
                    cookies = {}
                if cookies and hasattr(engine, "_session_cookies"):
                    engine._session_cookies.update(cookies)
                self._seed_engine_session(session, auto.get("hosts") or [])
                auto["detail"] = (f"authenticated via profile '{auto.get('profile')}' "
                                  f"({getattr(result, 'engine', '?')})")
                logger.info("autonomous run: proactive profile login ok", session_id=sid,
                            engine=getattr(result, "engine", "?"), cookies=len(cookies))
                await self._broadcast_autonomous(sid, "authenticated", {
                    "profile": auto.get("profile"), "engine": getattr(result, "engine", None),
                })
            else:
                auto["detail"] = f"profile login failed: {getattr(result, 'error', 'unknown')}"
                logger.warning("autonomous run: proactive profile login failed",
                               session_id=sid, error=getattr(result, "error", None))
                await self._broadcast_autonomous(sid, "auth_failed", {
                    "profile": auto.get("profile"), "error": getattr(result, "error", None),
                })
        except Exception as exc:
            auto["detail"] = f"profile login error: {str(exc)[:150]}"
            logger.warning("autonomous run: proactive profile login error",
                           session_id=sid, error=str(exc)[:200])

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

    def _response_counts(self) -> Tuple[int, int]:
        """(# in-scope entries, # with a 2xx status) — feeds the uniform-failure breaker.
        A 403/null still creates an entry, so comparing the 2xx count across turns is
        what distinguishes real responses from a rejection flood."""
        store = self._ctx.store
        if store is None:
            return (0, 0)
        try:
            entries = store.in_scope_entries()
        except Exception:
            return (0, 0)
        ok = sum(1 for entry in entries
                 if isinstance(getattr(entry, "status", None), int)
                 and 200 <= entry.status < 300)
        return (len(entries), ok)

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
            # Lift the identity-host deferral so it never leaks into manual use.
            if self._ctx.store is not None:
                self._ctx.store.defer_identity_hosts = False
        session["status"] = "idle" if status == "complete" else status
        session["pause"] = None
        session["updated_at"] = time.time()

        # Clean up resources the copilot acquired during the run.
        self._cleanup_session(session)

    def _cleanup_session(self, session: dict) -> None:
        """Release per-session resources: close the agent browser and remove any
        match/replace rules the copilot added (tagged with [copilot_session])."""
        # Detach the shared browser from this session but do NOT close it —
        # it persists across sessions so login state survives.
        session.pop("_agent_browser", None)
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

    def _effective_hosts(self, focus_hosts: List[str]) -> List[str]:
        """Expand the operator's focus hosts to every in-scope host actually observed
        in captured traffic.

        The focus host the operator typed is only a seed. Modern apps serve their real
        API from sibling subdomains (BFF/API/reporting hosts) that never appear in the
        operator's one-line target, so grounding and targeting keyed on the literal
        focus host leave that surface invisible — the copilot then guesses URLs on the
        focus host and escalates to a human when the guess fails. Deriving the working
        host set from traffic instead means leads/router/coverage and auto-targeting
        cover every in-scope host for every vuln class, with no per-host enumeration by
        the operator. Scope is already enforced by the proxy: ``in_scope_entries``
        excludes anything tagged out-of-scope, so this never reaches beyond scope.

        Ordering: identity-provider hosts (SSO/login/OAuth) are sorted LAST. Probing
        them floods the login/token endpoints and invalidates the very SSO session
        every other host depends on, so they must be tested only after the rest of
        the surface is covered — a dead session at the end costs nothing, a dead
        session at the start wastes the whole run."""
        hosts = {h.split(":")[0].lower() for h in (focus_hosts or []) if h and h.split(":")[0]}
        store = self._ctx.store
        if store is None:
            return _order_hosts(hosts)
        try:
            for entry in store.in_scope_entries():
                host = (getattr(entry, "host", "") or "").split(":")[0].lower()
                if host:
                    hosts.add(host)
        except Exception as exc:  # noqa: BLE001 — best-effort expansion, never crash the run
            logger.debug("effective host expansion failed", error=str(exc))
        return _order_hosts(hosts)

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

    def _without_deferred_identity(self, hosts: set) -> set:
        """Drop identity-provider hosts while the run defers them, so auto-targeting
        never probes the IdP until the final phase lifts the deferral."""
        from dast.proxy.session_store import is_identity_host
        store = self._ctx.store
        if store is None or not getattr(store, "defer_identity_hosts", False):
            return set(hosts)
        return {h for h in hosts if not is_identity_host(h)}

    async def _final_identity_phase(self, sid: str, session: dict) -> None:
        """Test identity-provider hosts LAST, once the rest of the surface is covered.

        Lifts the deferral and runs the active arsenal against the IdP hosts: scan
        every now-unblocked endpoint, then GraphQL and evidence-routed probes. Any
        session death this causes is harmless — every other host is already done.
        Runs once per run; no-op in read-only (active tools disabled)."""
        from dast.proxy.session_store import is_identity_host
        from dast.tools import run_tool

        auto = session["autonomous"]
        if auto.get("identity_phase_done"):
            return
        auto["identity_phase_done"] = True
        store = self._ctx.store
        if store is not None:
            store.defer_identity_hosts = False  # lift the deferral for the IdP pass
        identity_hosts = {
            h for h in self._effective_hosts(auto.get("hosts") or []) if is_identity_host(h)
        }
        if not identity_hosts or auto.get("read_only") or store is None:
            return
        logger.info("autonomous run: final identity-provider phase (tested last)",
                    session_id=sid, hosts=sorted(identity_hosts))
        await self._broadcast_autonomous(sid, "identity_phase", {"hosts": sorted(identity_hosts)})
        ctx = self._build_tool_ctx(session)
        stop_event: asyncio.Event = auto["stop_event"]
        # scan_surface now sees the IdP endpoints (deferral lifted); the rest of the
        # surface is already scanned, so this effectively covers just the IdP.
        prev = -1
        for _ in range(12):
            if stop_event.is_set():
                return
            try:
                result = await run_tool(ctx, "scan_surface", {})
            except Exception as exc:  # noqa: BLE001 — never crash the run on one tool
                logger.warning("identity phase: scan_surface failed", session_id=sid, error=str(exc))
                break
            remaining = int((result or {}).get("remaining", 0) or 0)
            if remaining == 0 or remaining == prev:
                break
            prev = remaining
        await self._auto_test_graphql(session, ctx, set(identity_hosts))
        await self._auto_route(session, ctx, set(identity_hosts))

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
        hosts = self._without_deferred_identity(hosts)
        if not hosts:
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
        LLM discretion: per in-scope host (focus hosts expanded with every in-scope
        host seen in traffic), EXPLORE the SPA to drain the UI frontier,
        then (active runs only) CONTENT-DISCOVER, SCAN every observed endpoint to
        exhaustion, and INTROSPECT+SWEEP (or FUZZ captured ops when introspection is
        disabled) every GraphQL endpoint. The LLM turns that follow focus on depth.
        Best-effort and stop-aware — any tool failure is logged, never fatal."""
        from dast.tools import run_tool

        auto = session["autonomous"]
        hosts = self._effective_hosts(auto.get("hosts") or [])
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
            try:
                observed = len(self._ctx.store.in_scope_entries()) if self._ctx.store else 0
            except Exception:  # noqa: BLE001
                observed = 0
            if last_visited <= 1 and observed > 3:
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
        hosts = self._without_deferred_identity(hosts)
        if not hosts:
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
        if mode == "complete" and not auto.get("validation_only") \
                and not auto.get("initial_explore_done"):
            await self._deterministic_recon_scan_sweep(sid, session)
            auto["initial_explore_done"] = True
            auto["breadth_done"] = True
            await self._session_keepalive(sid, session)

        # A credential-only login profile carries no captured session, so nothing is
        # authenticated yet and the model is never handed the password. Log in for real
        # now (server-side, same cascade as the inline 401 auto-relogin) so the run
        # starts authenticated. Best-effort — never deadlocks the run.
        await self._ensure_profile_login(sid, session)

        hosts_label = ", ".join(auto["hosts"]) or "the in-scope target(s)"
        read_only_note = _READ_ONLY_DIRECTIVE + "\n\n" if auto.get("read_only") else ""
        breadth_note = (
            "[BREADTH PHASE COMPLETE] The automated scan arsenal has already covered every "
            "discovered REST endpoint and GraphQL operation. Your job now is DEPTH: examine "
            "the high-value leads for business-logic, auth, and access-control issues that "
            "automated payload injection misses. Use browser tools to interact with the app, "
            "send_request to test parameter manipulation hypotheses, and idor_probe for stored-"
            "object BOLA. Focus on state-changing endpoints with identity-bearing parameters.\n\n"
        ) if auto.get("breadth_done") else ""
        start_hosts = self._effective_hosts(auto["hosts"])
        prompt = breadth_note + _AUTONOMOUS_START.format(
            objective=auto["objective"], hosts=hosts_label,
            leads=self._leads_label(start_hosts),
            router=self._router_block(start_hosts),
            coverage=self._coverage_block(self._surface_coverage(start_hosts)),
            read_only=read_only_note,
        )

        last_progress = self._progress_snapshot()
        stuck_turns = 0
        last_counts = self._response_counts()
        consec_fail_turns = 0
        last_keepalive = time.time()
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

                # ── Session keepalive ────────────────────────────────────────────
                now_ka = time.time()
                if now_ka - last_keepalive >= _SESSION_KEEPALIVE_INTERVAL:
                    await self._session_keepalive(sid, session)
                    last_keepalive = time.time()

                # ── Run one turn ─────────────────────────────────────────────────
                auto["turns"] += 1
                session["status"] = "running"
                session["updated_at"] = time.time()
                # Recomputed each turn: traffic grows as the run crawls, so sibling
                # in-scope hosts surface over time and must enter grounding/targeting.
                effective_hosts = self._effective_hosts(auto["hosts"])
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
                        leads=self._leads_label(effective_hosts),
                        router=self._router_block(effective_hosts),
                        coverage=self._coverage_block(self._surface_coverage(effective_hosts)),
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
                # guaranteed, not discretionary. Skipped in validation-only mode,
                # which must test ONLY the finding's endpoint, not sweep breadth.
                if effective_hosts and not auto.get("validation_only"):
                    turn_ctx = self._build_tool_ctx(session)
                    await self._auto_test_graphql(session, turn_ctx, set(effective_hosts))
                    # Evidence-driven auto-routing of the unambiguous leads (bounded
                    # and complete). The prompt block surfaces the rest for the LLM.
                    await self._auto_route(session, turn_ctx, set(effective_hosts))

                # ── Progress / stuck accounting ──────────────────────────────────
                progress = self._progress_snapshot()
                if progress != last_progress:
                    stuck_turns = 0
                    # Real work happened — refresh the soft-escalation nudge budget so a
                    # later genuine question isn't starved by earlier permission-asks.
                    auto["auto_guidance_nudges"] = 0
                    last_progress = progress
                else:
                    stuck_turns += 1

                # ── Uniform-failure breaker ──────────────────────────────────────
                # 403/null responses still create in-scope entries, so they read as
                # "progress" and never trip the stuck detector. Track turns whose new
                # traffic had NO 2xx at all and stop if that persists — otherwise the
                # run floods a target that is uniformly rejecting it.
                counts = self._response_counts()
                new_entries = counts[0] - last_counts[0]
                new_ok = counts[1] - last_counts[1]
                last_counts = counts
                if new_entries >= _UNIFORM_FAIL_MIN_NEW and new_ok <= 0:
                    consec_fail_turns += 1
                else:
                    consec_fail_turns = 0
                if consec_fail_turns >= _MAX_UNIFORM_FAIL_TURNS:
                    self._finish_autonomous(
                        session, "stopped",
                        f"no successful (2xx) responses for {consec_fail_turns} turns — "
                        f"stopping instead of flooding the target")
                    await self._broadcast_autonomous(sid, "finished", {"status": "stopped"})
                    return

                # ── Interpret the reply's control signal ─────────────────────────
                # Watchdog: the engine killed a turn whose agent looped on the same
                # normalized call. The coordinator breaks it — re-prompt once with a hard
                # corrective, and KILL the run if it keeps happening (the agent cannot
                # self-correct; the supervisor must stop it rather than burn the budget).
                if blocked_reason == "stuck_loop":
                    auto["stuck_loops"] = auto.get("stuck_loops", 0) + 1
                    await self._broadcast_autonomous(sid, "stuck_loop",
                                                     {"count": auto["stuck_loops"]})
                    logger.warning("autonomous run: agent stuck in a loop",
                                   session_id=sid, count=auto["stuck_loops"])
                    if auto["stuck_loops"] >= _MAX_STUCK_LOOPS:
                        self._finish_autonomous(
                            session, "stuck",
                            "agent repeatedly looped on the same call and could not self-correct")
                        await self._broadcast_autonomous(sid, "finished", {"status": "stuck"})
                        return
                    # Clear the engine's dedup + repeat counters so the corrected strategy
                    # is not itself suppressed, then re-prompt with a hard constraint.
                    try:
                        session["engine"]._seen_calls.clear()
                        session["engine"]._repeat_sigs.clear()
                    except Exception as exc:
                        logger.debug("stuck_loop: could not clear engine dedup", error=str(exc))
                    prompt = _AUTONOMOUS_STUCK_LOOP.format(
                        detail=(reply.message or "")[:400],
                        budget=self._budget_label(auto, cfg, deadline),
                        coverage=self._coverage_block(self._surface_coverage(effective_hosts)),
                    )
                    continue

                if blocked_reason == "complete":
                    # A validation-only run cares about ONE finding, not surface
                    # coverage — accept the verdict immediately instead of bouncing
                    # 'complete' through the coverage gate (which would push breadth).
                    if auto.get("validation_only"):
                        self._finish_autonomous(session, "complete",
                                                 reply.message or "validation concluded")
                        await self._broadcast_autonomous(sid, "finished",
                                                         {"status": "complete"})
                        return
                    coverage = self._surface_coverage(effective_hosts)
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
                            # Per-dimension gaps on scanned endpoints, so the dashboard can
                            # render the coverage checklist (endpoint x dimension).
                            "dimensions": {
                                dim: len(info.get("untested") or [])
                                for dim, info in (coverage.get("dimensions") or {}).items()
                            },
                            "cross_tenant_gap": coverage.get("cross_tenant_gap", False),
                            "rejection": auto["complete_rejections"],
                        })
                        # Complete mode closes gaps deterministically rather than
                        # relying on the LLM to do breadth: drain the frontier, scan
                        # every endpoint, fuzz/sweep GraphQL. Then re-prompt for depth.
                        if mode == "complete":
                            await self._deterministic_recon_scan_sweep(sid, session)
                        prompt = _AUTONOMOUS_COVERAGE_GATE.format(
                            coverage=self._coverage_block(self._surface_coverage(effective_hosts)),
                            budget=self._budget_label(auto, cfg, deadline),
                        )
                        continue

                    if not surface_incomplete:
                        # The non-IdP surface is covered. Before completing, test the
                        # identity-provider hosts LAST — deferred all run so probing
                        # them could not log the run out mid-scan. This runs once; the
                        # next turn re-evaluates coverage with the IdP included.
                        from dast.proxy.session_store import is_identity_host
                        store = self._ctx.store
                        identity_pending = (
                            not auto.get("identity_phase_done")
                            and store is not None
                            and getattr(store, "defer_identity_hosts", False)
                            and any(is_identity_host(h) for h in effective_hosts)
                        )
                        if identity_pending:
                            await self._final_identity_phase(sid, session)
                            prompt = _AUTONOMOUS_CONTINUE.format(
                                progress=self._progress_label(last_progress),
                                budget=self._budget_label(auto, cfg, deadline),
                                leads=self._leads_label(effective_hosts),
                                router=self._router_block(effective_hosts),
                                coverage=self._coverage_block(self._surface_coverage(effective_hosts)),
                                read_only=read_only_note,
                            )
                            continue
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
                    # Soft escalation (the copilot is unsure or asking permission for a
                    # step it could just take): auto-nudge it to proceed instead of
                    # pausing the operator. Bounded per no-progress streak so a genuinely
                    # stuck loop still surfaces to the human after a few nudges.
                    nudges = auto.get("auto_guidance_nudges", 0)
                    if (blocked_reason in _SOFT_ESCALATE_REASONS
                            and nudges < _MAX_AUTO_GUIDANCE_NUDGES):
                        auto["auto_guidance_nudges"] = nudges + 1
                        logger.info("autonomous run: auto-nudging past soft escalation",
                                    session_id=sid, blocked_reason=blocked_reason,
                                    nudge=nudges + 1)
                        await self._broadcast_autonomous(sid, "auto_nudge", {
                            "blocked_reason": blocked_reason, "nudge": nudges + 1,
                        })
                        prompt = _AUTONOMOUS_SELF_PROCEED.format(
                            reason=blocked_reason,
                            progress=self._progress_label(last_progress),
                            budget=self._budget_label(auto, cfg, deadline),
                            leads=self._leads_label(effective_hosts),
                            router=self._router_block(effective_hosts),
                            coverage=self._coverage_block(self._surface_coverage(effective_hosts)),
                        )
                        continue
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
                    leads=self._leads_label(effective_hosts),
                    router=self._router_block(effective_hosts),
                    coverage=self._coverage_block(self._surface_coverage(effective_hosts)),
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
        # While identity hosts are deferred they are intentionally untested, so they
        # must not count against coverage — otherwise 'complete' could never be reached
        # and the final IdP phase (which lifts the deferral) would never run.
        if getattr(store, "defer_identity_hosts", False):
            from dast.proxy.session_store import is_identity_host
            non_identity = {h for h in focus if not is_identity_host(h)}
            if non_identity:
                focus = non_identity

        # ── REST surface ────────────────────────────────────────────────────────
        try:
            entries = store.in_scope_entries()
        except Exception as exc:  # noqa: BLE001 — coverage is best-effort
            logger.debug("coverage: rest enumeration failed", error=str(exc))
            entries = []
        rest_status: Dict[Tuple[str, str, str], bool] = {}
        rest_dims: Dict[Tuple[str, str, str], set] = {}  # key -> dimensions evaluated
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
            # Which test dimensions were evaluated on this endpoint — from the attack
            # types the scan ran plus any finding's attack type.
            dims = rest_dims.setdefault(key, set())
            for at in (getattr(entry, "scanned_attack_types", None) or []):
                dim = _ATTACK_TYPE_DIMENSION.get(at)
                if dim:
                    dims.add(dim)
            for finding in (getattr(entry, "findings", None) or []):
                dim = _ATTACK_TYPE_DIMENSION.get((finding or {}).get("attack_type", ""))
                if dim:
                    dims.add(dim)
        cov["rest_total"] = len(rest_status)
        cov["rest_tested"] = sum(1 for tested in rest_status.values() if tested)
        cov["rest_untested"] = sorted(
            f"{method} {path}" for (_h, method, path), tested in rest_status.items() if not tested
        )

        # ── Per-dimension coverage matrix over the scanned REST endpoints ─────────
        # cross_tenant is only applicable (expected) when >=2 named sessions exist to
        # replay across; otherwise it is N/A and must not count as a gap.
        try:
            named_count = len(store.get_named_sessions() or [])
        except Exception:
            named_count = 0
        cross_tenant_applicable = named_count >= 2
        dim_summary: Dict[str, Dict[str, object]] = {}
        for dim in _COVERAGE_DIMENSIONS:
            if dim == "cross_tenant" and not cross_tenant_applicable:
                continue
            evaluated = [k for k, dims in rest_dims.items() if dim in dims]
            # Only endpoints that were scanned at all are candidates for a dimension gap
            # (an unscanned endpoint is already reported under rest_untested).
            scanned_keys = [k for k, t in rest_status.items() if t]
            missing = [k for k in scanned_keys if dim not in rest_dims.get(k, set())]
            dim_summary[dim] = {
                "tested": len(evaluated),
                "scanned_endpoints": len(scanned_keys),
                "untested": sorted(f"{m} {p}" for (_h, m, p) in missing),
            }
        cov["dimensions"] = dim_summary
        cov["cross_tenant_applicable"] = cross_tenant_applicable
        # The one hard per-dimension gate: with >=2 identities saved, cross-tenant MUST be
        # exercised on the scanned endpoints — not testing it is the exact gap that made the
        # run miss every cross-account check.
        cov["cross_tenant_gap"] = bool(
            cross_tenant_applicable
            and dim_summary.get("cross_tenant", {}).get("untested")
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
            and not cov["cross_tenant_gap"]
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
        # Per-dimension gaps on the ALREADY-scanned endpoints — so the copilot does not
        # stop after a shallow injection-only pass and call the surface "covered".
        dims = cov.get("dimensions") or {}
        _DIM_HINT = {
            "injection": "injection probes (scan_surface / run_scan reach these)",
            "access_control": "authz / IDOR — reason about id/owner params and run idor_probe or run_scan",
            "cross_tenant": "cross-account replay — run run_multiuser_idor across the saved named sessions",
            "business_logic": "business-logic / mass-assignment — add fields the client does not send",
            "llm_injection": "prompt / LLM injection on any field that reaches an AI classifier",
            "csrf": "CSRF protection checks on state-changing endpoints",
        }
        for dim in _COVERAGE_DIMENSIONS:
            info = dims.get(dim)
            if not info:
                continue
            missing = info.get("untested") or []
            if not missing:
                continue
            hard = " (REQUIRED: you have >=2 identities saved)" if dim == "cross_tenant" else ""
            lines.append(
                f"- {len(missing)} scanned endpoint(s) NOT yet tested for {dim}{hard} — "
                f"{_DIM_HINT.get(dim, dim)}. Examples: "
                + wrap_untrusted(", ".join(missing[:6]), f"untested_{dim}")
            )
        return "\n".join(lines)

"""
AppContextWorker — background LLM synthesis of application-level context.

Runs independently of the scan pipeline. As traffic flows through the proxy,
the worker periodically samples recent entries + the existing DiscoveryContext
and asks the LLM to build a structured AppProfile: application type, auth model,
resource types, privilege levels, and concrete vulnerability hypotheses.

The AppProfile is stored on DiscoveryEngine and consumed by:
  - Coordinator._plan()  → hypothesis hints steer agent selection
  - Agents               → resource types + privilege levels sharpen payloads
  - Dashboard AI tab     → visible context summary

Memory budget:
  - Hypotheses capped at _MAX_HYPOTHESES (20) — oldest dropped on overflow
  - Entry sample: _SAMPLE_SIZE (20) entries per LLM call
  - Re-analysis triggered every _DELTA_ENTRIES new entries, starting at _FIRST_THRESHOLD

All values from external sources pass through _sanitize() before reaching the LLM.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore
    from dast.discovery.engine import DiscoveryEngine

logger = get_logger(__name__)

_FIRST_THRESHOLD = 15    # trigger first analysis after N entries
_DELTA_ENTRIES = 30      # re-analyse every N new entries after first
_SAMPLE_SIZE = 20        # entries sent to LLM per call
_MAX_HYPOTHESES = 20     # cap on stored hypotheses (oldest dropped)

_INJECTION_RE = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)"
    r"|system\s*:\s*you\s+are"
    r"|<\s*/?system\s*>"
    r"|\[INST\]|\[/INST\]"
    r"|forget\s+(everything|all)\s+(above|previous)"
    r"|you\s+are\s+now\s+(a\s+)?(different|new)\s+(ai|assistant))",
    re.IGNORECASE,
)


def _sanitize(value: str, max_len: int = 200) -> str:
    return _INJECTION_RE.sub("[redacted]", str(value)[:max_len])


# ── App profile data model ─────────────────────────────────────────────────

@dataclass
class VulnHypothesis:
    """A concrete, actionable vulnerability hypothesis for a specific endpoint."""
    attack_type: str           # xss | sqli | idor | ssrf | auth_bypass | business_logic | ...
    endpoint: str              # e.g. "POST /api/orders"
    parameter: str             # e.g. "customerId"
    rationale: str             # why this is suspicious, max 1 sentence
    priority: str              # high | medium | low
    ts: float = field(default_factory=time.time)


@dataclass
class AppProfile:
    """
    Synthesised understanding of the application under test.
    Built incrementally — fields may be None until enough traffic is observed.
    """
    host: str
    app_type: Optional[str] = None          # e.g. "SaaS B2B platform", "e-commerce API"
    auth_model: Optional[str] = None        # e.g. "JWT Bearer", "session cookie + CSRF"
    resource_types: List[str] = field(default_factory=list)   # e.g. ["users","orders","products"]
    privilege_levels: List[str] = field(default_factory=list) # e.g. ["admin","manager","user"]
    interesting_flows: List[str] = field(default_factory=list)# e.g. ["checkout flow","impersonation header"]
    vuln_hypotheses: List[VulnHypothesis] = field(default_factory=list)
    last_analysed_at: Optional[float] = None
    entry_count_at_analysis: int = 0
    analysis_count: int = 0

    def top_hypotheses(self, n: int = 5) -> List[VulnHypothesis]:
        ranked = sorted(
            self.vuln_hypotheses,
            key=lambda h: {"high": 0, "medium": 1, "low": 2}.get(h.priority, 3),
        )
        return ranked[:n]

    def to_coordinator_hint(self) -> str:
        """Compact text injected into the LLM planner prompt."""
        if not self.vuln_hypotheses:
            return ""
        lines = []
        if self.app_type:
            lines.append(f"App type: {_sanitize(self.app_type)}")
        if self.auth_model:
            lines.append(f"Auth: {_sanitize(self.auth_model)}")
        if self.resource_types:
            lines.append("Resources: " + ", ".join(_sanitize(r) for r in self.resource_types[:8]))
        if self.privilege_levels:
            lines.append("Privilege levels: " + ", ".join(_sanitize(p) for p in self.privilege_levels[:6]))
        top = self.top_hypotheses(5)
        if top:
            lines.append("Vulnerability hypotheses (prioritise these agents):")
            for h in top:
                lines.append(
                    f"  [{h.priority.upper()}] {_sanitize(h.attack_type)} — "
                    f"{_sanitize(h.endpoint)} param={_sanitize(h.parameter)} — "
                    f"{_sanitize(h.rationale)}"
                )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "app_type": self.app_type,
            "auth_model": self.auth_model,
            "resource_types": self.resource_types,
            "privilege_levels": self.privilege_levels,
            "interesting_flows": self.interesting_flows,
            "vuln_hypotheses": [
                {
                    "attack_type": h.attack_type,
                    "endpoint": h.endpoint,
                    "parameter": h.parameter,
                    "rationale": h.rationale,
                    "priority": h.priority,
                    "ts": h.ts,
                }
                for h in self.vuln_hypotheses
            ],
            "last_analysed_at": self.last_analysed_at,
            "entry_count_at_analysis": self.entry_count_at_analysis,
            "analysis_count": self.analysis_count,
        }


# ── LLM system prompt ──────────────────────────────────────────────────────

_SYSTEM = """\
You are an expert web application security analyst and penetration tester.
You are observing HTTP traffic through a proxy and building a structured pentest
intelligence record for the application under test.

Given a sample of HTTP request/response pairs and any known tech stack information,
produce a structured analysis. Focus on:
1. What kind of application this is and how its auth model works
2. What resource types and privilege levels exist
3. Concrete, actionable vulnerability hypotheses — specific endpoints and parameters
   that are most likely to be vulnerable based on the observed patterns
4. Pentest notes — one-sentence observations that a skilled pentester would write in
   their notes: unusual patterns, missing protections, suspicious fields, trust boundaries,
   anything that informs which attack surface to prioritise

Attack types to consider: xss, sqli, idor, ssrf, auth_bypass, business_logic,
mass_assignment, open_redirect, ssti, lfi, graphql_injection, llm_injection,
prototype_pollution, host_header_injection

Respond ONLY with JSON matching this schema exactly:
{
  "app_type": "<one short phrase, e.g. SaaS B2B API>",
  "auth_model": "<one short phrase, e.g. JWT Bearer + refresh token>",
  "resource_types": ["<noun>", ...],
  "privilege_levels": ["<role>", ...],
  "interesting_flows": ["<short description of a notable user flow>", ...],
  "pentest_notes": [
    "<one sentence — a concrete observation useful for planning tests, e.g.:
      'Price field is sent by client and echoed in order confirmation — mass assignment candidate',
      'No CSRF token seen on any state-changing POST',
      'User IDs in path appear sequential and numeric',
      'Internal service name visible in X-Served-By header',
      'GraphQL introspection is enabled'>"
  ],
  "vuln_hypotheses": [
    {
      "attack_type": "<attack type>",
      "endpoint": "<METHOD /path>",
      "parameter": "<param name or *>",
      "rationale": "<one sentence>",
      "priority": "high|medium|low"
    },
    ...
  ]
}

Rules:
- pentest_notes: max 10 items, each a distinct observation. Skip obvious/generic notes.
  Only include when there is concrete evidence in the observed traffic.
- vuln_hypotheses must be specific and actionable — avoid generic claims
- Only include hypotheses where you observed concrete evidence
- Do not include more than 10 hypotheses
- Sanitise all values — never echo untrusted content verbatim

Must NOT generate hypotheses for:
- OIDC/OAuth/SSO callback or relay endpoints (/callback, /oauth, /saml, /sso, /auth/token)
- Endpoints whose parameters contain JWTs, opaque session tokens, or PKCE codes
- Static asset paths (.js, .css, .png, .woff, /static/, /assets/, /_next/)
- Health-check or metrics endpoints (/health, /ping, /metrics, /ready)
- Any endpoint that returned a redirect to a login page (server is already enforcing auth)
"""


# ── AppContextWorker ───────────────────────────────────────────────────────

class AppContextWorker:
    """
    Background coroutine that synthesises AppProfile objects per host.
    Triggered by entry count thresholds; does not send any extra HTTP requests.
    """

    def __init__(
        self,
        store: "SessionStore",
        engine: "DiscoveryEngine",
        scan_queue=None,
        scan_queue_state=None,
    ) -> None:
        self._store = store
        self._engine = engine
        self._profiles: Dict[str, AppProfile] = {}
        self._seen_count: Dict[str, int] = {}   # host → entry count at last analysis
        self._running = False
        self._scan_queue = scan_queue
        self._scan_queue_state = scan_queue_state
        # Tracks which (host, endpoint, attack_type) hypotheses were already queued
        self._queued_hypotheses: set = set()

    def get_profile(self, host: str) -> Optional[AppProfile]:
        return self._profiles.get(host)

    def all_profiles(self) -> Dict[str, AppProfile]:
        return dict(self._profiles)

    async def run(self) -> None:
        """Main loop — checks thresholds every 10 s and triggers analysis."""
        self._running = True
        logger.info("AppContextWorker started")
        while self._running:
            try:
                await self._check_all_hosts()
            except Exception as e:
                logger.debug("AppContextWorker loop error", error=str(e))
            await asyncio.sleep(10)

    def stop(self) -> None:
        self._running = False

    async def _check_all_hosts(self) -> None:
        # AI synthesis is an AI feature — it must stay OFF unless the user has
        # explicitly enabled AI mode. In manual mode (the default) no AI config
        # runs at all: the worker stays alive but performs no LLM analysis, and
        # resumes automatically once AI mode is turned on.
        if not getattr(self._store, "ai_mode", False):
            return

        all_entries = list(self._store.all_entries())
        # Group by host — skip out-of-scope and synthetic import entries
        # so the app context only reflects real observed traffic.
        host_entries: Dict[str, List["ProxyEntry"]] = {}
        settings = getattr(self._store, "_settings", None) or getattr(self, "_settings", None)
        for entry in all_entries:
            if not entry.host or entry.method == "CONNECT":
                continue
            if entry.source in ("out-of-scope", "imported", "agent", "scan"):
                continue
            if settings and not settings.is_in_scope(entry.url):
                continue
            host_entries.setdefault(entry.host, []).append(entry)

        for host, entries in host_entries.items():
            total = len(entries)
            last = self._seen_count.get(host, 0)
            profile = self._profiles.get(host)

            if profile is None and total >= _FIRST_THRESHOLD:
                await self._analyse(host, entries)
            elif profile is not None and (total - last) >= _DELTA_ENTRIES:
                await self._analyse(host, entries)

    async def _analyse(self, host: str, entries: List["ProxyEntry"]) -> None:
        logger.info("AppContextWorker: analysing", host=host, entries=len(entries))
        self._seen_count[host] = len(entries)

        # Build entry sample — prefer varied endpoints
        sample = _diverse_sample(entries, _SAMPLE_SIZE)

        # Build traffic summary
        traffic_lines = []
        for e in sample:
            req_preview = ""
            if e.request_body:
                req_preview = e.request_body[:120].decode("utf-8", errors="replace")
                req_preview = _sanitize(req_preview, 120)
            resp_preview = ""
            if e.response_body:
                resp_preview = e.response_body[:120].decode("utf-8", errors="replace")
                resp_preview = _sanitize(resp_preview, 120)
            auth_hdr = e.request_headers.get("authorization", "")
            cookie_hdr = e.request_headers.get("cookie", "")
            traffic_lines.append(
                f"{e.method} {_sanitize(e.path, 100)} → {e.response_status}"
                + (f" | body={req_preview}" if req_preview else "")
                + (f" | resp={resp_preview}" if resp_preview else "")
                + (f" | auth={_sanitize(auth_hdr[:60])}" if auth_hdr else "")
                + (f" | cookie_names={_cookie_names(cookie_hdr)}" if cookie_hdr else "")
            )

        # Add existing tech stack context
        ctx = self._engine.context_for_host(host)
        tech_summary = ctx.to_agent_summary() if ctx else ""

        # Add existing hypotheses for delta analysis
        existing_profile = self._profiles.get(host)
        existing_hint = ""
        if existing_profile and existing_profile.vuln_hypotheses:
            existing_hint = "\nExisting hypotheses (avoid duplicates, add new ones):\n" + "\n".join(
                f"  {h.attack_type} {h.endpoint}" for h in existing_profile.vuln_hypotheses
            )

        user = (
            f"Host: {host}\n"
            f"Total requests observed: {len(entries)}\n"
            + (f"Tech stack:\n{tech_summary}\n" if tech_summary else "")
            + f"\nTraffic sample ({len(sample)} requests):\n"
            + "\n".join(traffic_lines)
            + existing_hint
        )

        try:
            from dast.ai import bedrock_client
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: bedrock_client.invoke_json(system=_SYSTEM, user=user, max_tokens=3000),
            )
            self._apply_result(host, result, len(entries))
            logger.info(
                "AppContextWorker: analysis complete",
                host=host,
                hypotheses=len(self._profiles[host].vuln_hypotheses),
            )
        except Exception as e:
            logger.warning("AppContextWorker: LLM call failed", host=host, error=str(e))

    def _apply_result(self, host: str, result: dict, entry_count: int) -> None:
        existing = self._profiles.get(host) or AppProfile(host=host)

        existing.app_type = result.get("app_type") or existing.app_type
        existing.auth_model = result.get("auth_model") or existing.auth_model

        for rt in result.get("resource_types", []):
            rt = str(rt)[:60]
            if rt not in existing.resource_types:
                existing.resource_types.append(rt)
        existing.resource_types = existing.resource_types[:20]

        for pl in result.get("privilege_levels", []):
            pl = str(pl)[:60]
            if pl not in existing.privilege_levels:
                existing.privilege_levels.append(pl)
        existing.privilege_levels = existing.privilege_levels[:10]

        for flow in result.get("interesting_flows", []):
            flow = str(flow)[:120]
            if flow not in existing.interesting_flows:
                existing.interesting_flows.append(flow)
        existing.interesting_flows = existing.interesting_flows[:10]

        for h in result.get("vuln_hypotheses", [])[:10]:
            hyp = VulnHypothesis(
                attack_type=str(h.get("attack_type", ""))[:40],
                endpoint=str(h.get("endpoint", ""))[:100],
                parameter=str(h.get("parameter", ""))[:60],
                rationale=str(h.get("rationale", ""))[:200],
                priority=str(h.get("priority", "medium"))[:10],
            )
            # Deduplicate by (attack_type, endpoint, parameter)
            key = (hyp.attack_type, hyp.endpoint, hyp.parameter)
            if not any((x.attack_type, x.endpoint, x.parameter) == key for x in existing.vuln_hypotheses):
                existing.vuln_hypotheses.append(hyp)

        # Cap and keep highest priority hypotheses
        if len(existing.vuln_hypotheses) > _MAX_HYPOTHESES:
            ranked = sorted(
                existing.vuln_hypotheses,
                key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.priority, 3),
            )
            existing.vuln_hypotheses = ranked[:_MAX_HYPOTHESES]

        existing.last_analysed_at = time.time()
        existing.entry_count_at_analysis = entry_count
        existing.analysis_count += 1
        self._profiles[host] = existing

        # Write synthesis results back into SessionIntelligence so the coordinator
        # planner sees app context + pentest notes before the first scan fires.
        session_intelligence = getattr(self._store, "session_intelligence", None)
        if session_intelligence is not None:
            try:
                app_summary = " | ".join(filter(None, [
                    existing.app_type,
                    existing.auth_model,
                    (", ".join(existing.resource_types[:4]) if existing.resource_types else ""),
                ]))
                pentest_notes = [
                    _sanitize(str(n), 300)
                    for n in result.get("pentest_notes", [])
                    if n and str(n).strip()
                ]
                session_intelligence.record_app_context(
                    host=host,
                    app_summary=app_summary,
                    pentest_notes=pentest_notes,
                )
            except Exception as exc:
                logger.warning("AppContextWorker: session intelligence write-back failed", host=host, error=str(exc))

        # Act on new high/medium priority hypotheses immediately
        asyncio.ensure_future(self._act_on_hypotheses(host, existing))


    async def _act_on_hypotheses(self, host: str, profile: AppProfile) -> None:
        """
        For each new high/medium hypothesis, find a matching proxy entry and
        queue it for active scan with the hypothesis as an import hint.
        Hypotheses with no matching entry are stored as suggestions in the store.
        """
        from dast.proxy.plugin_manager import log_event
        import re as _re

        if not self._scan_queue:
            return

        for hyp in profile.vuln_hypotheses:
            if hyp.priority == "low":
                continue

            key = (host, hyp.endpoint, hyp.attack_type)
            if key in self._queued_hypotheses:
                continue

            # Parse "METHOD /path" from endpoint string
            ep_match = _re.match(r'(\w+)\s+(/\S*)', hyp.endpoint)
            if not ep_match:
                continue
            method, path = ep_match.group(1).upper(), ep_match.group(2)

            # Find the best matching proxy entry for this host + method + path
            best_entry = self._find_best_entry(host, method, path)

            if best_entry is None:
                # No matching entry yet — park as a pending hypothesis so it fires
                # automatically when a real proxy entry with a matching path arrives.
                pending = getattr(self._store, "pending_import_findings", None)
                if pending is not None:
                    pending_key = (host, path, hyp.attack_type)
                    if pending_key not in self._queued_hypotheses:
                        self._queued_hypotheses.add(pending_key)
                        pending.append({
                            "path": path,
                            "method": method,
                            "hints": [{
                                "parameter": hyp.parameter if hyp.parameter != "*" else "",
                                "payload": hyp.rationale,
                                "attack_type": hyp.attack_type,
                            }],
                            "stub": None,  # no stub — this is a hypothesis, not an imported finding
                        })
                        log_event(
                            "app-context", "info",
                            f"Hypothesis parked (no proxy entry yet): {hyp.priority.upper()} {hyp.attack_type} on {hyp.endpoint} — will test when URL appears",
                            url=f"https://{host}{path}", source="agent",
                        )

                # Also store as an active suggestion for the UI
                suggestions = getattr(self._store, "active_suggestions", None)
                if suggestions is not None:
                    suggestion_key = (host, hyp.endpoint, hyp.attack_type)
                    if suggestion_key not in {
                        (s["host"], s["endpoint"], s["attack_type"])
                        for s in suggestions
                    }:
                        auto_scan = getattr(self._store, "auto_scan_suggestions", False)
                        suggestions.append({
                            "host": host,
                            "endpoint": hyp.endpoint,
                            "method": method,
                            "path": path,
                            "attack_type": hyp.attack_type,
                            "parameter": hyp.parameter,
                            "hypothesis": hyp.rationale,
                            "severity": hyp.priority,
                            "source": "app-context",
                            "rationale": hyp.rationale,
                            "priority": hyp.priority,
                            "status": "queued" if auto_scan else "pending",
                            "body_preview": "",
                            "ts": time.time(),
                        })
                        log_event(
                            "app-context", "info",
                            f"Hypothesis suggested: {hyp.priority.upper()} {hyp.attack_type} on {hyp.endpoint} — {hyp.rationale}",
                            url=f"https://{host}{path}", source="agent",
                        )
                continue

            # Found a matching entry — inject hypothesis as import hint
            hint = {
                "parameter": hyp.parameter if hyp.parameter != "*" else "",
                "payload": "",   # no specific payload — let agents generate
                "attack_type": hyp.attack_type,
            }
            existing_hints = list(best_entry.import_hints or [])
            if hint not in existing_hints:
                best_entry.import_hints = existing_hints + [hint]

            auto_scan = getattr(self._store, "auto_scan_suggestions", False)
            body_preview = ""
            if best_entry and best_entry.request_body:
                body_preview = best_entry.request_body[:120].decode("utf-8", errors="replace")

            if not auto_scan:
                # Auto-scan is off — store as suggestion with "Test Now" button instead
                suggestions = getattr(self._store, "active_suggestions", None)
                if suggestions is not None:
                    suggestion_key = (host, hyp.endpoint, hyp.attack_type)
                    if suggestion_key not in {
                        (s["host"], s["endpoint"], s["attack_type"])
                        for s in suggestions
                    }:
                        suggestions.append({
                            "host": host,
                            "endpoint": hyp.endpoint,
                            "method": method,
                            "path": path,
                            "attack_type": hyp.attack_type,
                            "parameter": hyp.parameter,
                            "hypothesis": hyp.rationale,
                            "severity": hyp.priority,
                            "source": "app-context",
                            "rationale": hyp.rationale,
                            "priority": hyp.priority,
                            "status": "pending",
                            "body_preview": body_preview,
                            "ts": time.time(),
                        })
                log_event(
                    "app-context", "info",
                    f"Hypothesis suggested (auto-scan off): {hyp.priority.upper()} {hyp.attack_type} on {hyp.endpoint} — {hyp.rationale}",
                    url=best_entry.url, source="agent",
                )
                continue

            # Auto-scan is on — queue for immediate scan.
            # Mark skip_dedup=True so the scan worker bypasses dedup for re-scans
            # triggered by new hypothesis context on already-seen URLs.
            # Do NOT set ai_queued — that flag means "user explicitly requested this
            # scan" and bypasses the ai_mode gate; hypothesis scans must respect it.
            self._queued_hypotheses.add(key)
            best_entry.skip_dedup = True
            if not best_entry.queued_for_scan:
                best_entry.queued_for_scan = True
                if self._scan_queue_state:
                    self._scan_queue_state.enqueue(
                        best_entry.id, best_entry.method,
                        best_entry.url, best_entry.host,
                    )
                await self._scan_queue.put(best_entry.id)
                log_event(
                    "app-context", "info",
                    f"Hypothesis queued for scan: {hyp.priority.upper()} {hyp.attack_type} on {hyp.endpoint} — {hyp.rationale}",
                    url=best_entry.url, source="agent",
                )
            else:
                log_event(
                    "app-context", "info",
                    f"Hypothesis noted (entry already scanned): {hyp.attack_type} on {hyp.endpoint}",
                    url=best_entry.url, source="agent",
                )

    def _find_best_entry(self, host: str, method: str, path: str):
        """
        Return the most recent proxy entry matching host + method + path.
        Tries exact match first, then prefix match (for parameterised paths like /users/:id).
        """
        import re as _re

        # Normalise path pattern: /users/:id or /users/{id} → prefix /users/
        path_prefix = _re.split(r'[:{]', path)[0].rstrip("/")

        best = None
        best_ts = 0.0
        with self._store._lock:
            for eid in reversed(self._store._order):
                e = self._store._entries.get(eid)
                if not e or e.host != host or e.method != method:
                    continue
                if e.source in ("agent", "imported"):
                    continue
                ep = e.path.split("?")[0]
                if ep == path or (path_prefix and ep.startswith(path_prefix + "/")):
                    if e.ts > best_ts:
                        best = e
                        best_ts = e.ts
        return best


# ── helpers ────────────────────────────────────────────────────────────────

def _diverse_sample(entries: List["ProxyEntry"], n: int) -> List["ProxyEntry"]:
    """Return up to n entries, preferring unique paths and non-GET methods."""
    seen_paths: set = set()
    result = []
    # First pass: unique paths
    for e in reversed(entries):  # most recent first
        if e.path not in seen_paths:
            seen_paths.add(e.path)
            result.append(e)
        if len(result) >= n:
            break
    # Fill remainder with most-recent if still under n
    if len(result) < n:
        remaining = [e for e in reversed(entries) if e not in result]
        result.extend(remaining[: n - len(result)])
    return result[:n]


def _cookie_names(cookie_hdr: str) -> str:
    """Extract just the cookie names (not values) for the LLM summary."""
    names = [part.split("=")[0].strip() for part in cookie_hdr.split(";") if "=" in part]
    return ",".join(names[:8])

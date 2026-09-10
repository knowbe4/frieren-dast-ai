"""
In-memory store for all intercepted requests/responses.

Thread-safe. Notifies registered listeners when new entries arrive
so the dashboard WebSocket can push updates without polling.
"""

import asyncio
import concurrent.futures
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import TYPE_CHECKING, Callable, Dict, List, Optional
from urllib.parse import urlparse

from dast.proxy.service_graph import ServiceGraph
from dast.discovery.engine import DiscoveryEngine
# Re-exported for backward compatibility: raw HTTP evidence formatting now lives
# in dast.proxy.http_format. Existing callers still import these names from here.
from dast.proxy.http_format import _format_raw_request, _format_raw_response
from dast.proxy.signalr import (
    SIGNALR_SEPARATOR,
    annotate_blazor_args,
    body_preview,
    decode_body,
    decode_msgpack_signalr,
    decode_signalr_body,
    is_signalr_binary,
    is_signalr_body,
    is_signalr_path,
)
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.plugin_manager import PluginManager
    from dast.proxy.proxy_settings import ProxySettings

logger = get_logger(__name__)

# Re-exported for backward compatibility: SignalR / Blazor body decoding now lives
# in dast.proxy.signalr. These private aliases keep the historical names importable.
_SIGNALR_SEP = SIGNALR_SEPARATOR
_annotate_blazor_args = annotate_blazor_args
_decode_msgpack_signalr = decode_msgpack_signalr
_decode_signalr_body = decode_signalr_body
_is_signalr_binary = is_signalr_binary
_is_signalr_body = is_signalr_body
_is_signalr_path = is_signalr_path
_decode_body = decode_body
_body_preview = body_preview


_ENDPOINT_ID_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24,})$"
)


def normalise_endpoint_path(path: str) -> str:
    """Collapse an entry path to an endpoint template so ``/users/1`` and ``/users/2``
    count as one endpoint for coverage purposes. Drops the query string and replaces
    numeric / UUID / long-hex path segments with ``:id``. Shared by the scan_surface
    tool and the autonomous coverage gate so both agree on what a distinct endpoint is."""
    base = (path or "").split("?", 1)[0]
    segments = base.split("/")
    return "/".join(":id" if _ENDPOINT_ID_SEGMENT_RE.match(seg) else seg for seg in segments)


@dataclass
class NamedSession:
    """Auth context for a specific user — used by CrossSessionIdorAgent."""
    name: str           # e.g. "user_a", "admin"
    role: str           # e.g. "member", "admin"
    cookies: Dict[str, dict]    # Playwright-compatible cookie dicts keyed by name
    auth_headers: Dict[str, str]  # e.g. {"Authorization": "Bearer ..."}
    created_at: float = field(default_factory=time.time)


@dataclass
class ProxyEntry:
    id: str
    method: str
    url: str
    host: str
    path: str
    request_headers: Dict[str, str]
    request_body: Optional[bytes]
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[bytes] = None
    content_type: str = ""
    duration_ms: float = 0.0
    ts: float = field(default_factory=time.time)
    source: str = "proxy"   # "proxy" | "crawler" | "browse" | "scanner"
    browse_session_id: Optional[str] = None
    crawler_session_id: Optional[str] = None
    # scan state
    queued_for_scan: bool = False
    scan_result: Optional[str] = None  # "vulnerable" | "safe" | "error"
    findings: List[dict] = field(default_factory=list)
    # hints from imported reports: [{parameter, payload, attack_type}]
    import_hints: List[dict] = field(default_factory=list)
    # payload injected by an agent probe (for display in HTTP history)
    probe_payload: Optional[str] = None
    # manual "Send to AI" note and queued flag (set via /api/manual/send-to-ai)
    manual_note: Optional[str] = None
    ai_queued: bool = False
    skip_dedup: bool = False

    def to_dict(self, include_bodies: bool = False) -> dict:
        d = {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status": self.response_status,
            "content_type": self.content_type,
            "duration_ms": round(self.duration_ms, 1),
            "ts": self.ts,
            "source": self.source,
            "browse_session_id": self.browse_session_id,
            "crawler_session_id": self.crawler_session_id,
            "queued_for_scan": self.queued_for_scan,
            "scan_result": self.scan_result,
            "findings": self.findings,
            "body_preview": body_preview(self.request_body, self.path),
            "probe_payload": self.probe_payload,
            "ai_queued": self.ai_queued,
            "manual_note": self.manual_note,
            "import_hints": self.import_hints or [],
        }
        if include_bodies:
            d["request_headers"] = self.request_headers
            d["request_body"] = decode_body(self.request_body, self.path)
            d["response_headers"] = self.response_headers
            d["response_body"] = decode_body(self.response_body, self.path)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ProxyEntry":
        """Restore a ProxyEntry from a to_dict(include_bodies=True) snapshot."""
        req_body = d.get("request_body")
        resp_body = d.get("response_body")
        return cls(
            id=d["id"],
            method=d["method"],
            url=d["url"],
            host=d.get("host", ""),
            path=d.get("path", ""),
            request_headers=d.get("request_headers") or {},
            request_body=req_body.encode("utf-8", errors="replace") if isinstance(req_body, str) else None,
            response_status=d.get("status"),
            response_headers=d.get("response_headers") or {},
            response_body=resp_body.encode("utf-8", errors="replace") if isinstance(resp_body, str) else None,
            content_type=d.get("content_type", ""),
            duration_ms=d.get("duration_ms", 0.0),
            ts=d.get("ts", time.time()),
            source=d.get("source", "proxy"),
            browse_session_id=d.get("browse_session_id"),
            crawler_session_id=d.get("crawler_session_id"),
            queued_for_scan=d.get("queued_for_scan", False),
            scan_result=d.get("scan_result"),
            findings=d.get("findings") or [],
            import_hints=d.get("import_hints") or [],
            ai_queued=d.get("ai_queued", False),
            manual_note=d.get("manual_note"),
            probe_payload=d.get("probe_payload"),
        )


_NOISE_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "segment.com",
    "mixpanel.com", "amplitude.com", "hotjar.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com",
}

_NOISE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".css", ".map",
}


class SessionStore:
    """
    Stores all intercepted proxy entries.
    Listeners (async callables) are notified on every new/updated entry.
    """

    def __init__(self) -> None:
        self._entries: Dict[str, ProxyEntry] = {}
        self._order: List[str] = []
        # Guards _entries, _order, _cookies and every mutation of ProxyEntry.findings.
        # Finding appends must go through _append_finding_locked (see add_finding).
        self._lock = threading.Lock()
        self._listeners: List[Callable] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._counter = 0
        # cookie jar: host → {name: {value, path, domain, secure, httponly}}
        self._cookies: Dict[str, Dict[str, dict]] = {}
        # active browse session tag — set while user browses manually
        self.active_browse_session_id: Optional[str] = None
        # active crawler session tag — set while SpaCrawler is running
        self.active_crawler_session_id: Optional[str] = None
        # service graph, discovery engine and session intelligence
        self._init_passive_analysers()
        # Active suggestions from AppContextWorker — hypotheses with no matching
        # proxy entry yet. Shown in dashboard AI Suggestions tab with "Test Now" option.
        self.active_suggestions: List[dict] = []
        # When True, new suggestions are automatically queued for scan
        self.auto_scan_suggestions: bool = False
        # Taint marker correlation — unique benign markers injected at each entry
        # point, then correlated against every observed response so cross-endpoint
        # data flows (stored XSS, second-order injection) surface even when the
        # input and output points are different requests.
        from dast.scanners.taint import TaintStore
        self.taint_store = TaintStore()
        # GraphQL schemas discovered via introspection — keyed by endpoint URL.
        # Populated by the graphql_introspection plugin; read by the findings importer
        # to build correct query/mutation bodies when importing reports.
        # Value: {"types": [...], "mutations": {...}, "queries": {...}, "ts": float}
        self.graphql_schemas: Dict[str, dict] = {}
        # GraphQL operations already exercised by the graphql_sweep tool — keyed by
        # endpoint URL, value is a set of "kind:field" op keys (e.g. "query:me").
        # Read by the autonomous copilot's coverage gate to know which introspected
        # operations still need testing before a run may declare complete.
        self.graphql_tested_ops: Dict[str, set] = {}
        # background executor for passive analysis (fingerprinting, plugins, discovery)
        # keeps the proxy hot path free — responses are returned before analysis runs
        self._bg_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="dast-bg")
        # named auth sessions for cross-session IDOR testing — keyed by name
        self.named_sessions: Dict[str, NamedSession] = {}
        # AI mode: when True, every completed in-scope entry is auto-queued for scan
        self.ai_mode: bool = False
        # Pending findings: imported findings whose host wasn't in proxy yet.
        # Each item: {"path": str, "method": str, "nf": NormalisedFinding-like dict,
        #             "hints": list, "stub": dict}
        # When a real proxy entry arrives whose path matches, it gets queued for scan.
        self.pending_import_findings: List[dict] = []
        # Passive scanner one_per_host state — keyed by rule_id → set of hosts.
        # Lives on SessionStore so plugin re-instantiation doesn't reset deduplication.
        self.passive_fired_hosts: Dict[str, set] = {}

    def _init_passive_analysers(self) -> None:
        """Instantiate the per-store passive analysers fed from complete_entry()."""
        # Imported lazily: session_intelligence pulls in the AI layer.
        from dast.ai.session_intelligence import SessionIntelligence

        # service graph — auto-detects multi-host application boundaries
        self.service_graph = ServiceGraph()
        # discovery engine — enriches CheckTarget with tech stack, JS endpoints, call chains
        self.discovery_engine = DiscoveryEngine()
        # Session-wide scan intelligence — accumulated across all endpoints/hosts.
        # The Coordinator reads and writes this on every scan.
        self.session_intelligence = SessionIntelligence()

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self.discovery_engine.set_event_loop(loop)

    def set_scan_queue(self, queue: asyncio.Queue) -> None:
        """Called by the runner so plugins can enqueue entries for active scan."""
        self._scan_queue: asyncio.Queue = queue

    def _drain_pending_findings(self, entry: "ProxyEntry") -> None:
        """
        Called when a real proxy entry completes. Checks if any pending imported
        findings match this entry's path and, if so, injects their hints and queues
        the entry for active scan.

        Matching is loose: a pending finding matches if its path prefix appears in
        the entry path (handles /users vs /users/123, and template params).
        """
        if not self.pending_import_findings:
            return
        if entry.source in ("out-of-scope", "agent", "imported"):
            return

        entry_path = (entry.path or "").split("?")[0].lower()
        matched = []
        remaining = []

        with self._lock:
            for pf in self.pending_import_findings:
                pf_path = (pf.get("path") or "/").split("?")[0].lower()
                pf_method = (pf.get("method") or "GET").upper()
                # Match if: same method AND (exact path, or pf_path is prefix of entry path,
                # or the last non-template segment of pf_path appears in entry_path)
                pf_static = pf_path.split("{")[0].rstrip("/")
                path_match = (
                    entry_path == pf_path
                    or (pf_static and entry_path.startswith(pf_static))
                    or (pf_static and pf_static in entry_path)
                )
                method_match = (pf_method == entry.method or pf_method == "GET")
                if path_match and method_match:
                    matched.append(pf)
                else:
                    remaining.append(pf)

            if not matched:
                return

            self.pending_import_findings = remaining

            # Inject hints from all matched pending findings into this entry
            existing_hints = list(entry.import_hints or [])
            for pf in matched:
                for hint in (pf.get("hints") or []):
                    if hint not in existing_hints:
                        existing_hints.append(hint)
                # Add stub finding so the UI shows it before the scan completes.
                # Stubs carry no raw evidence — the scan fills that in later.
                stub = pf.get("stub")
                if stub and stub.get("title"):
                    self._append_finding_locked(entry, stub, attach_evidence=False)

            entry.import_hints = existing_hints

            should_queue = not entry.queued_for_scan and not entry.scan_result
            if should_queue:
                entry.queued_for_scan = True

        if should_queue:
            self.enqueue_for_scan(entry.id)
            logger.info(
                "Pending import findings matched — queued for scan",
                entry_id=entry.id,
                url=entry.url,
                matched=len(matched),
            )
        self._notify(entry)

    def enqueue_for_scan(self, entry_id: str) -> None:
        """Thread-safe: queue an entry for active scan. No-op if loop/queue not set."""
        queue = getattr(self, "_scan_queue", None)
        loop = getattr(self, "_loop", None)
        if queue and loop:
            asyncio.run_coroutine_threadsafe(queue.put(entry_id), loop)

    def add_listener(self, fn: Callable) -> None:
        self._listeners.append(fn)

    def _notify(self, entry: ProxyEntry) -> None:
        if not self._loop or not self._listeners:
            return
        for fn in list(self._listeners):
            asyncio.run_coroutine_threadsafe(fn(entry), self._loop)

    def new_entry(
        self,
        method: str,
        url: str,
        request_headers: Dict[str, str],
        request_body: Optional[bytes],
        source: str = "proxy",
    ) -> Optional[str]:
        """
        Register a new request. Returns the entry ID, or None if filtered out.
        """
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"

        if self._is_noise(host, path):
            return None

        with self._lock:
            self._counter += 1
            entry_id = f"{int(time.time() * 1000)}-{self._counter}"
            browse_sid = self.active_browse_session_id
            crawler_sid = self.active_crawler_session_id
            # Scanner/passive requests and explicitly-tagged sources keep their tag.
            # Explicit sources from proxy_server (agent, crawler, out-of-scope) are authoritative.
            # browse_sid only applies when no explicit source was given (source="proxy").
            if source in ("agent", "passive", "out-of-scope", "crawler"):
                resolved_source = source
            elif browse_sid:
                resolved_source = "browse"
            elif crawler_sid:
                resolved_source = "crawler"
            else:
                resolved_source = source
            probe_payload = request_headers.pop("x-dast-payload", None)
            entry = ProxyEntry(
                id=entry_id,
                method=method,
                url=url,
                host=host,
                path=path,
                request_headers=request_headers,
                request_body=request_body,
                source=resolved_source,
                browse_session_id=browse_sid,
                crawler_session_id=crawler_sid,
                probe_payload=probe_payload,
            )
            self._entries[entry_id] = entry
            self._order.append(entry_id)

        self._notify(entry)
        return entry_id

    def set_plugin_manager(self, plugin_manager: "PluginManager") -> None:
        self._plugin_manager = plugin_manager

    def complete_entry(
        self,
        entry_id: str,
        status: int,
        response_headers: Dict[str, str],
        response_body: bytes,
        duration_ms: float,
    ) -> None:
        with self._lock:
            entry = self._entries.get(entry_id)
            if not entry:
                return
            entry.response_status = status
            entry.response_headers = response_headers
            entry.response_body = response_body
            entry.content_type = response_headers.get("content-type", "")
            entry.duration_ms = duration_ms
            self._ingest_cookies(entry.host, response_headers)
            host_cookies = dict(self._cookies.get(entry.host, {}))

        # Notify dashboard immediately — response is already stored
        self._notify(entry)

        # Run all passive analysis in the background so the proxy thread is never blocked.
        # Captures everything needed by value; entry fields are set before we hand off.
        service_graph = self.service_graph
        discovery_engine = self.discovery_engine
        session_intelligence = self.session_intelligence
        loop = self._loop
        plugin_manager = getattr(self, "_plugin_manager", None)
        store_ref = self

        def _bg_analyse() -> None:
            try:
                service_graph.observe(
                    host=entry.host,
                    request_headers=entry.request_headers,
                    response_headers=response_headers,
                    cookies=host_cookies,
                )
            except Exception as exc:
                logger.warning("Background service graph analysis failed", host=entry.host, error=str(exc))
            try:
                discovery_engine.observe_entry(entry)
            except Exception as exc:
                logger.warning("Background discovery analysis failed", host=entry.host, error=str(exc))
            # Feed every completed in-scope entry into session intelligence.
            # Extracts deterministic signals (auth headers, WAF, rate limits,
            # endpoint inventory) so the coordinator has context before the
            # first scan fires, not just after scan write-backs.
            # Out-of-scope and agent probe entries are skipped — intel must only
            # reflect the target application, not third-party hosts or scanner noise.
            _settings_ref = getattr(store_ref, "_settings", None)
            _intel_in_scope = (
                entry.source not in ("imported", "out-of-scope", "agent", "scanner")
                and entry.host
                and (_settings_ref is None or _settings_ref.is_in_scope(entry.url))
            )
            if session_intelligence is not None and _intel_in_scope:
                try:
                    body_prefix = (entry.response_body or b"")[:512].decode("utf-8", errors="replace")
                    session_intelligence.observe_entry(
                        host=entry.host,
                        method=entry.method,
                        path=entry.path.split("?")[0],
                        request_headers=entry.request_headers,
                        response_status=entry.response_status or 0,
                        response_headers=response_headers,
                        response_body_prefix=body_prefix,
                        content_type=response_headers.get("content-type", ""),
                        source=entry.source,
                    )
                except Exception as exc:
                    logger.warning("Session intelligence passive ingestion failed", host=entry.host, error=str(exc))
            if plugin_manager and loop:
                asyncio.run_coroutine_threadsafe(plugin_manager.dispatch(entry, store_ref), loop)

        self._bg_executor.submit(_bg_analyse)

        # Check if any pending imported findings now have a matching real entry
        self._drain_pending_findings(entry)

    def _ingest_cookies(self, host: str, response_headers: Dict[str, str]) -> None:
        """Parse set-cookie headers and update the per-host cookie jar."""
        # response_headers may have a single collapsed set-cookie (proxy dict)
        # or multiple via a list — handle both
        raw = response_headers.get("set-cookie", "")
        if not raw:
            return
        values = raw if isinstance(raw, list) else [raw]
        jar = self._cookies.setdefault(host, {})
        for cookie_str in values:
            sc = SimpleCookie()
            try:
                sc.load(cookie_str)
            except Exception as exc:
                logger.debug("Failed to parse set-cookie header", host=host, error=str(exc))
                continue
            for name, morsel in sc.items():
                jar[name] = {
                    "name": name,
                    "value": morsel.value,
                    "domain": morsel["domain"] or host,
                    "path": morsel["path"] or "/",
                    "secure": bool(morsel["secure"]),
                    "httpOnly": "httponly" in cookie_str.lower(),
                }

    def get_cookie_hosts(self) -> List[str]:
        """Return all hosts that currently have at least one cookie in the jar."""
        with self._lock:
            return [h for h, jar in self._cookies.items() if jar]

    def get_all_cookies(self) -> List[dict]:
        """Return all Playwright-compatible cookie dicts across every host."""
        with self._lock:
            result: dict = {}
            for jar in self._cookies.values():
                for name, cookie in jar.items():
                    # Key by (name, domain) so duplicate names on different domains are kept
                    result[(name, cookie.get("domain", ""))] = cookie
            return list(result.values())

    def get_crawl_cookies(self) -> List[dict]:
        """Return every session cookie the crawler could authenticate with.

        Merges the shared proxy jar (populated by the legacy unnamed Browse flow)
        with all NAMED-session cookies (captured in isolation by the named /
        headless-credentials Browse flows, and therefore invisible to
        ``get_all_cookies``). Without this merge a user who logged in via a named
        session would have their cookies stranded in ``named_sessions`` and the
        crawler would run unauthenticated and get bounced to the login page.

        Named-session cookies take precedence on a ``(name, domain)`` collision
        since they represent a deliberately-saved authenticated session.
        """
        with self._lock:
            result: dict = {}
            for jar in self._cookies.values():
                for name, cookie in jar.items():
                    result[(name, cookie.get("domain", ""))] = cookie
            # Named sessions layered on top — an explicit login wins over whatever
            # the passive jar happened to capture.
            for session in self.named_sessions.values():
                for name, cookie in session.cookies.items():
                    result[(name, cookie.get("domain", ""))] = cookie
            return list(result.values())

    def get_cookies_for_host(self, host: str) -> List[dict]:
        """Return Playwright-compatible cookie dicts for the given host."""
        with self._lock:
            # Collect cookies from the exact host and any parent domain match
            result = {}
            for h, jar in self._cookies.items():
                if h == host or host.endswith("." + h) or h.endswith("." + host):
                    result.update(jar)
            # Also exact host
            result.update(self._cookies.get(host, {}))
            return list(result.values())

    def save_named_session(self, name: str, role: str) -> "NamedSession":
        """Snapshot current proxy cookies + auth headers as a named session."""
        from dast.proxy.auth_headers import extract_auth_headers

        cookies = {}
        with self._lock:
            for jar in self._cookies.values():
                cookies.update(jar)
            recent_entries = [
                self._entries[eid] for eid in reversed(self._order[-50:])
                if eid in self._entries
            ]
            auth_headers = extract_auth_headers(recent_entries, host=None, exclude_sources=())
        session = NamedSession(name=name, role=role, cookies=cookies, auth_headers=auth_headers)
        self.named_sessions[name] = session
        return session

    def save_named_session_from_playwright(
        self,
        name: str,
        role: str,
        playwright_cookies: List[dict],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> "NamedSession":
        """Save a named session from cookies captured directly from a Playwright context.

        Bypasses the shared proxy cookie jar so multiple users can be saved without
        one logout overwriting another session's cookies.
        Playwright cookie dicts use camelCase keys (name, value, domain, path, secure, httpOnly).
        """
        cookies: Dict[str, dict] = {}
        for c in playwright_cookies:
            cookie_name = c.get("name", "")
            if not cookie_name:
                continue
            cookies[cookie_name] = {
                "name": cookie_name,
                "value": c.get("value", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "secure": bool(c.get("secure", False)),
                "httpOnly": bool(c.get("httpOnly", False)),
            }
        session = NamedSession(
            name=name,
            role=role,
            cookies=cookies,
            auth_headers=auth_headers or {},
        )
        self.named_sessions[name] = session
        return session

    def import_playwright_cookies(self, playwright_cookies: List[dict]) -> int:
        """Merge Playwright-shaped cookie dicts into the live per-host jar.

        Used when activating a saved/imported login session so subsequent proxied
        and scanned requests carry it. Cookies are keyed by their own ``domain``
        (leading dot stripped) so host matching in get_cookies_for_host works.
        Returns the number of cookies imported.
        """
        count = 0
        with self._lock:
            for c in playwright_cookies:
                name = c.get("name", "")
                if not name:
                    continue
                domain = (c.get("domain") or "").lstrip(".").lower()
                if not domain:
                    continue
                jar = self._cookies.setdefault(domain, {})
                jar[name] = {
                    "name": name,
                    "value": c.get("value", ""),
                    "domain": domain,
                    "path": c.get("path", "/"),
                    "secure": bool(c.get("secure", False)),
                    "httpOnly": bool(c.get("httpOnly", False)),
                }
                count += 1
        return count

    def delete_named_session(self, name: str) -> bool:
        return self.named_sessions.pop(name, None) is not None

    def get_named_sessions(self) -> List["NamedSession"]:
        return list(self.named_sessions.values())

    def mark_queued(self, entry_ids: List[str]) -> List[str]:
        queued = []
        with self._lock:
            for eid in entry_ids:
                e = self._entries.get(eid)
                if e and not e.queued_for_scan:
                    e.queued_for_scan = True
                    queued.append(eid)
        for eid in queued:
            with self._lock:
                e = self._entries.get(eid)
            if e:
                self._notify(e)
        return queued

    @staticmethod
    def _finding_dedup_key(finding: dict) -> tuple:
        """Identity of a finding for deduplication: title + attack_type + parameter."""
        return (finding.get("title", ""), finding.get("attack_type", ""), finding.get("parameter", ""))

    def _append_finding_locked(self, entry: ProxyEntry, finding: dict, attach_evidence: bool) -> bool:
        """Single mutation path for ``entry.findings``. Caller MUST hold ``self._lock``.

        Skips the finding when one with the same dedup key is already recorded.
        With ``attach_evidence`` the parent entry's raw request/response is copied
        onto the finding when it did not supply its own. Returns True if appended.
        """
        key = self._finding_dedup_key(finding)
        for idx, existing in enumerate(entry.findings):
            if self._finding_dedup_key(existing) != key:
                continue
            # A confirmed finding upgrades a previously held-for-review duplicate
            # (recorded while the AI validator was offline). This lets a re-scan
            # promote "Needs review" to a real confirmation instead of being
            # silently deduped away. All other duplicates are skipped as before.
            if finding.get("confirmed") and not existing.get("confirmed"):
                if attach_evidence:
                    self._attach_evidence_locked(entry, finding)
                entry.findings[idx] = finding
                return True
            return False
        if attach_evidence:
            self._attach_evidence_locked(entry, finding)
        entry.findings.append(finding)
        return True

    def _attach_evidence_locked(self, entry: ProxyEntry, finding: dict) -> None:
        """Auto-populate raw HTTP evidence from the parent entry when the finding
        (agent or plugin) did not supply it. Ensures every finding carries at
        least the intercepted baseline pair for the report. Caller holds the lock."""
        if not finding.get("raw_request") and entry.method and entry.url:
            try:
                finding["raw_request"] = _format_raw_request(entry)[:6000]
            except Exception as exc:
                logger.debug("Failed to attach raw request evidence to finding",
                             entry_id=entry.id, error=str(exc))
        if not finding.get("raw_response") and entry.response_status:
            try:
                finding["raw_response"] = _format_raw_response(entry)[:6000]
            except Exception as exc:
                logger.debug("Failed to attach raw response evidence to finding",
                             entry_id=entry.id, error=str(exc))

    def snapshot_findings(self, entry: ProxyEntry) -> List[dict]:
        """Return a consistent copy of ``entry.findings`` taken under the store lock."""
        with self._lock:
            return list(entry.findings)

    def add_finding(self, entry_id: str, finding: dict, scan_result: str) -> None:
        with self._lock:
            e = self._entries.get(entry_id)
            if not e:
                logger.warning("add_finding: entry not found", entry_id=entry_id, scan_result=scan_result)
                return
            if finding.get("title"):
                # Deduplicate: skip if same title + attack_type + parameter already recorded
                if not self._append_finding_locked(e, finding, attach_evidence=True):
                    return
            # Never downgrade a confirmed vulnerable entry to safe/error via an empty sentinel
            if scan_result == "vulnerable" or e.scan_result != "vulnerable":
                e.scan_result = scan_result
        if e:
            self._notify(e)

    def record_manual_finding(
        self, finding: dict, url: str, method: str = "GET"
    ) -> Optional[str]:
        """Attach a finding produced outside the scan pipeline (Exploration Copilot
        or an MCP client) to the proxy history so it shows in the Findings tab.

        Links the finding to the most recent in-store entry for the same url+method
        so it carries the real request/response it was confirmed on. When no such
        entry exists (the caller never proxied that url through Frieren) a
        lightweight synthetic entry is created so the finding still lands with its
        request context. Returns the entry id it was attached to, or None if url is
        missing.
        """
        url = (url or "").strip()
        if not url:
            return None
        method = (method or "GET").strip().upper() or "GET"
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        entry_id: Optional[str] = None
        with self._lock:
            # Newest matching entry first (the request the caller just probed).
            for eid in reversed(self._order):
                e = self._entries.get(eid)
                if e and e.url == url and e.method == method:
                    entry_id = eid
                    break
            if entry_id is None:
                entry_id = f"copilot-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
                self._entries[entry_id] = ProxyEntry(
                    id=entry_id, method=method, url=url, host=host, path=path,
                    request_headers={}, request_body=None, source="copilot",
                )
                self._order.append(entry_id)
        # add_finding re-acquires the lock and notifies listeners — call it outside
        # the lock block above (the lock is not reentrant).
        self.add_finding(entry_id, finding, "vulnerable")
        return entry_id

    def remove_finding(self, entry_id: str, finding_index: int) -> bool:
        """Remove a single finding by index. Returns True if removed."""
        with self._lock:
            e = self._entries.get(entry_id)
            if not e:
                return False
            if finding_index < 0 or finding_index >= len(e.findings):
                return False
            e.findings.pop(finding_index)
            if not e.findings and e.scan_result == "vulnerable":
                e.scan_result = "safe"
        if e:
            self._notify(e)
        return True

    def get_entry(self, entry_id: str) -> Optional[ProxyEntry]:
        with self._lock:
            return self._entries.get(entry_id)

    def entries_for_browse_session(self, session_id: str) -> List[ProxyEntry]:
        with self._lock:
            return [
                self._entries[eid] for eid in self._order
                if eid in self._entries and self._entries[eid].browse_session_id == session_id
            ]

    def all_entries(self) -> List[ProxyEntry]:
        with self._lock:
            return [self._entries[eid] for eid in self._order if eid in self._entries]

    def in_scope_entries(self) -> List[ProxyEntry]:
        """All entries except out-of-scope — use for findings, overview, scan targeting."""
        with self._lock:
            return [
                self._entries[eid] for eid in self._order
                if eid in self._entries and self._entries[eid].source != "out-of-scope"
            ]

    def queued_entries(self) -> List[ProxyEntry]:
        with self._lock:
            return [
                self._entries[eid] for eid in self._order
                if eid in self._entries and self._entries[eid].queued_for_scan
            ]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._order.clear()
        # Give previously-unreachable hosts a fresh chance after a clear —
        # the network may have changed (VPN up, DNS propagated).
        try:
            from dast.scanners.active_checks import reset_host_reachability
            reset_host_reachability()
        except Exception as exc:
            logger.debug("Failed to reset host reachability after store clear", error=str(exc))

    def load_from_session_data(
        self,
        entries_data: list,
        cookies_data: dict,
        settings: Optional["ProxySettings"] = None,
    ) -> int:
        """Replace store contents with entries from a saved session. Returns entry count."""
        with self._lock:
            self._entries.clear()
            self._order.clear()
            self._cookies = {}
            for d in entries_data:
                try:
                    entry = ProxyEntry.from_dict(d)
                    if entry.queued_for_scan and not entry.scan_result:
                        entry.queued_for_scan = False
                    # Re-apply scope rules so entries saved before out-of-scope
                    # tracking existed get the correct source tag on load.
                    if settings is not None and entry.source not in ("agent", "imported", "out-of-scope"):
                        if not settings.is_in_scope(entry.url):
                            entry.source = "out-of-scope"
                    self._entries[entry.id] = entry
                    self._order.append(entry.id)
                except Exception as exc:
                    logger.warning("load_from_session_data: failed to load entry", error=str(exc))
                    continue
            if isinstance(cookies_data, dict):
                self._cookies = cookies_data
        logger.info("Session data loaded", entry_count=len(self._order))
        return len(self._order)

    def load_session_intelligence(self, si_data: dict) -> None:
        """Restore session intelligence from persisted data."""
        for host, hdata in si_data.items():
            intel = self.session_intelligence.get(host)
            with self.session_intelligence._lock:
                # confirmed_vulns
                for key_str, types in hdata.get("confirmed_vulns", {}).items():
                    p, _, param = key_str.partition("|")
                    intel.confirmed_vulns[(p, param)] = types
                # sets
                intel.effective_attack_types = set(hdata.get("effective_attack_types", []))
                intel.ineffective_attack_types = set(hdata.get("ineffective_attack_types", []))
                # structural_errors
                for key_str, errs in hdata.get("structural_errors", {}).items():
                    if "|" in key_str:
                        p, _, op = key_str.partition("|")
                        intel.structural_errors[(p, op)] = errs
                    else:
                        intel.structural_errors[(key_str, "")] = errs
                intel.waf_observations = [tuple(x) for x in hdata.get("waf_observations", [])]
                intel.auth_headers_seen = set(hdata.get("auth_headers_seen", []))
                intel.rate_limit_observed = bool(hdata.get("rate_limit_observed", False))
                intel.graphql_endpoints = set(hdata.get("graphql_endpoints", []))

    def _is_noise(self, host: str, path: str) -> bool:
        if any(host == d or host.endswith(f".{d}") for d in _NOISE_DOMAINS):
            return True
        if any(path.lower().endswith(ext) for ext in _NOISE_EXTENSIONS):
            return True
        return False

"""
In-memory store for all intercepted requests/responses.

Thread-safe. Notifies registered listeners when new entries arrive
so the dashboard WebSocket can push updates without polling.
"""

import asyncio
import concurrent.futures
import threading
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from dast.proxy.service_graph import ServiceGraph
from dast.discovery.engine import DiscoveryEngine
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def _format_raw_request(entry: "ProxyEntry") -> str:
    """Format a ProxyEntry's request as raw HTTP text (reusable by any caller)."""
    parsed = urlparse(entry.url)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    lines = [f"{entry.method} {path} HTTP/1.1", f"Host: {entry.host}"]
    for k, v in (entry.request_headers or {}).items():
        if k.lower() != "host":
            lines.append(f"{k}: {v}")
    lines.append("")
    if entry.request_body:
        lines.append(entry.request_body.decode("utf-8", errors="replace"))
    return "\r\n".join(lines)


def _format_raw_response(entry: "ProxyEntry") -> str:
    """Format a ProxyEntry's response as raw HTTP text (reusable by any caller)."""
    status = entry.response_status or 0
    lines = [f"HTTP/1.1 {status}"]
    for k, v in (entry.response_headers or {}).items():
        if k.lower() == "set-cookie" and isinstance(v, list):
            for cookie in v:
                lines.append(f"set-cookie: {cookie}")
        else:
            lines.append(f"{k}: {v}")
    lines.append("")
    if entry.response_body:
        lines.append(entry.response_body.decode("utf-8", errors="replace")[:4000])
    return "\r\n".join(lines)

_SIGNALR_SEP = "\x1e"


def _annotate_blazor_args(target: str, args) -> str:
    """
    Return a human-readable annotation for known Blazor circuit management calls.
    Raw args are often opaque tokens — we label them so the reader knows what they are.
    """
    import json as _json

    def _fmt(v) -> str:
        return _json.dumps(v, ensure_ascii=False, default=str)

    # ConnectCircuit args[0] is an ASP.NET Core Data Protection token (CfDJ8... prefix).
    # It is AES-256-CBC + HMAC-SHA256 encrypted with the server's key ring —
    # cannot be decrypted without the server private key. It authenticates the circuit.
    if target == "ConnectCircuit":
        if isinstance(args, (list, tuple)) and args:
            token = str(args[0])
            is_dp = token.startswith("CfDJ8")
            label = "ASP.NET DataProtection token (encrypted, not decodable)" if is_dp else "circuit token"
            rest = _fmt(list(args[1:])) if len(args) > 1 else ""
            return f'"{token[:24]}…" [{label}]{(", " + rest) if rest else ""}'
        return _fmt(args)

    # UpdateRootComponents: args contain component descriptors
    if target == "UpdateRootComponents":
        if isinstance(args, (list, tuple)) and args:
            try:
                ops = _json.loads(args[0]) if isinstance(args[0], str) else args[0]
                if isinstance(ops, list):
                    summary = [f"{op.get('type','?')}:{op.get('marker','?')}" for op in ops[:3]]
                    return f"[{', '.join(summary)}{'…' if len(ops)>3 else ''}] ({len(ops)} ops)"
            except Exception:
                pass

    # OnNavigate: URL the user navigated to
    if target == "OnNavigate":
        if isinstance(args, (list, tuple)) and args:
            url = args[0]
            return f'"{url}"'

    # JsInitialized, AttachWebRendererInterop etc — just show arg count
    _KNOWN_INFRA = {
        "JsInitialized", "AttachWebRendererInterop", "SetHasLocationChangingHandlers",
        "OnAfterRenderComplete", "AcknowledgeRenderer",
    }
    if target in _KNOWN_INFRA:
        if isinstance(args, (list, tuple)):
            return f"({len(args)} args)"
        return _fmt(args)

    return _fmt(args)


def _decode_msgpack_signalr(raw: bytes) -> str:
    """
    Decode SignalR binary (MessagePack / blazorpack) protocol frames using msgpack lib.

    Each frame: <varint-length><msgpack-payload>
    SignalR msgpack array layout by type:
      1 = Invocation:  [1, headers, invId|null, target, args, streamIds?]
      3 = Completion:  [3, headers, invId, resultKind, payload?]
      6 = Ping:        [6]
      7 = Close:       [7, error?]
    """
    import json as _json
    try:
        import msgpack as _mp
    except ImportError:
        return ""

    def _read_varint(data: bytes, pos: int):
        result, shift = 0, 0
        while pos < len(data):
            b = data[pos]; pos += 1
            result |= (b & 0x7f) << shift
            if not (b & 0x80):
                return result, pos
            shift += 7
        return result, pos

    def _unpack(payload: bytes):
        return _mp.unpackb(payload, raw=False, strict_map_key=False)

    def _fmt(v) -> str:
        return _json.dumps(v, ensure_ascii=False, default=str)

    lines = []
    pos = 0
    while pos < len(raw):
        frame_len, pos = _read_varint(raw, pos)
        if frame_len == 0 or pos + frame_len > len(raw):
            break
        frame = raw[pos:pos+frame_len]; pos += frame_len
        if not frame:
            continue
        try:
            msg = _unpack(frame)
        except Exception:
            continue
        if not isinstance(msg, (list, tuple)) or not msg:
            continue

        msg_type = msg[0]

        if msg_type == 1:  # Invocation: [1, headers, invId, target, args, streamIds?]
            if len(msg) < 5:
                continue
            inv_id = msg[2]
            target = msg[3] or ""
            args = msg[4]
            id_part = f" [{inv_id}]" if inv_id else ""

            if target == "BeginInvokeDotNetFromJS" and isinstance(args, (list, tuple)) and len(args) >= 5:
                # args = [callId, assembly, method, dotNetObjectId, argsJson]
                call_id = args[0]
                assembly = args[1] or ""
                method = args[2] or "?"
                args_json_str = args[4]
                try:
                    inner = _json.loads(args_json_str) if isinstance(args_json_str, str) else args_json_str
                    inner_str = _fmt(inner)
                except Exception:
                    inner_str = str(args_json_str)[:300]
                ns = f"{assembly}::" if assembly else ""
                lines.append(f"[dotnet-invoke]{id_part} {ns}{method}({inner_str})")

            elif target == "EndInvokeJSFromDotNet" and isinstance(args, (list, tuple)) and len(args) >= 2:
                call_id = args[0]
                ok = "ok" if args[1] else "error"
                result = args[2] if len(args) > 2 else None
                try:
                    if isinstance(result, str) and result.startswith(("[", "{")):
                        result = _json.loads(result)
                except Exception:
                    pass
                lines.append(f"[js-result] [{call_id}] {ok} {_fmt(result)}")

            elif target in ("OnRenderCompleted", "OnAfterRenderAsync"):
                batch = args[0] if isinstance(args, (list, tuple)) and args else args
                lines.append(f"[render] {target} batch={batch}")

            else:
                # Annotate well-known Blazor Server circuit management calls
                annotated_args = _annotate_blazor_args(target, args)
                lines.append(f"[invoke]{id_part} {target}({annotated_args})")

        elif msg_type == 3:  # Completion: [3, headers, invId, resultKind, payload?]
            if len(msg) < 4:
                lines.append("[result:void]"); continue
            result_kind = msg[3]
            if result_kind == 1 and len(msg) > 4:
                lines.append(f"[result:error] {msg[4]}")
            elif result_kind == 2 and len(msg) > 4:
                lines.append(f"[result] {_fmt(msg[4])[:300]}")
            else:
                lines.append("[result:void]")

        elif msg_type == 6:
            lines.append("[ping]")

        elif msg_type == 7:
            err = msg[1] if len(msg) > 1 else ""
            lines.append(f"[close] {err}" if err else "[close]")

        else:
            lines.append(f"[type{msg_type}]")

    return "\n".join(lines) if lines else ""


def _decode_signalr_body(raw: bytes) -> str:
    """
    Decode a SignalR body — auto-detects text (JSON+0x1e) vs binary (MessagePack) protocol.

    Text protocol: JSON objects separated by 0x1e record separator.
    Binary protocol (blazorpack): varint-length-prefixed MessagePack frames.
    """
    import json
    import re as _re

    # --- Binary protocol (blazorpack / MessagePack) — check BEFORE text ---
    # Must come first because varint length bytes can coincidentally equal 0x1e
    if _is_signalr_binary(raw):
        decoded = _decode_msgpack_signalr(raw)
        if decoded:
            return decoded

    # --- Text protocol (0x1e record separator) ---
    if _SIGNALR_SEP.encode() in raw:
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = raw.decode("latin-1", errors="replace")

        _TYPE_LABELS = {1: "invoke", 2: "stream", 3: "result", 4: "stream-item",
                        5: "cancel", 6: "ping", 7: "close"}
        lines = []
        for segment in text.split(_SIGNALR_SEP):
            segment = segment.strip()
            if not segment:
                continue
            json_start = next((i for i, ch in enumerate(segment) if ch in ('{', '[')), -1)
            if json_start == -1:
                readable = _re.sub(r"[^\x20-\x7e]", "", segment)
                if readable.strip():
                    lines.append(f"[binary] {readable[:120]}")
                continue
            try:
                msg = json.loads(segment[json_start:])
            except (json.JSONDecodeError, ValueError):
                readable = _re.sub(r"[^\x20-\x7e]", "", segment)
                if readable.strip():
                    lines.append(readable[:120])
                continue
            msg_type = msg.get("type", "?")
            if msg_type == 1:
                target = msg.get("target", "?")
                args = json.dumps(msg.get("arguments", []), ensure_ascii=False)
                inv_id = msg.get("invocationId", "")
                id_part = f" [{inv_id}]" if inv_id else ""
                lines.append(f"[invoke]{id_part} {target}({args})")
            elif msg_type == 3:
                err = msg.get("error")
                if err:
                    lines.append(f"[result:error] {err[:200]}")
                else:
                    result = json.dumps(msg.get("result", ""), ensure_ascii=False)
                    lines.append(f"[result] {result[:300]}")
            elif msg_type == 6:
                lines.append("[ping]")
            elif msg_type == 7:
                lines.append(f"[close] {msg.get('error','')}" if msg.get("error") else "[close]")
            else:
                label = _TYPE_LABELS.get(msg_type, f"type{msg_type}")
                lines.append(f"[{label}] {segment[json_start:][:200]}")
        return "\n".join(lines) if lines else ""

    return ""


def _is_signalr_binary(raw: bytes) -> bool:
    """
    Return True if this looks like SignalR binary (MessagePack) protocol.

    SignalR binary frames: <varint-length><msgpack-fixarray>...
    The varint can be 1-5 bytes (continuation bit 0x80 set on all but the last).
    We skip varint bytes until we find one without 0x80, then check the next byte
    is a msgpack fixarray (0x90-0x9f).
    """
    if len(raw) < 2:
        return False
    # Skip varint bytes (up to 5)
    pos = 0
    for _ in range(5):
        if pos >= len(raw):
            return False
        b = raw[pos]; pos += 1
        if not (b & 0x80):  # last varint byte
            break
    # pos now points to first byte after varint — should be msgpack fixarray
    if pos < len(raw) and 0x90 <= raw[pos] <= 0x9f:
        return True
    return False


def _is_signalr_body(raw: bytes) -> bool:
    """Return True if the body looks like SignalR (text or binary protocol)."""
    if _is_signalr_binary(raw):
        return True
    # Text protocol: contains record separator AND the content around it looks like JSON
    sep = _SIGNALR_SEP.encode()
    if sep in raw:
        idx = raw.index(sep)
        before = raw[max(0, idx-1):idx]
        after = raw[idx+1:idx+2]
        # Record separator should be adjacent to JSON delimiters
        if before and before[-1:] in (b'}', b']') or after and after[:1] in (b'{', b'['):
            return True
        # Or it's the terminator at end of a JSON message
        if before and before[-1:] in (b'}', b']'):
            return True
        # Fallback: if most content around sep is printable ASCII
        sample = raw[:min(200, len(raw))].decode("utf-8", errors="replace")
        printable = sum(1 for c in sample if 0x20 <= ord(c) <= 0x7e or c in '\n\r\t')
        if printable > len(sample) * 0.5:
            return True
    return False


def _is_signalr_path(path: str) -> bool:
    p = (path or "").lower()
    return "_blazor" in p or "/signalr" in p or "/hub" in p or "/hubs/" in p


def _decode_body(raw: Optional[bytes], path: str = "") -> Optional[str]:
    """Decode a request/response body, applying SignalR decoding when appropriate."""
    if not raw:
        return None
    import re as _re
    if _is_signalr_body(raw):
        decoded = _decode_signalr_body(raw)
        if decoded:
            return decoded
        logger.debug(
            "SignalR body decode failed — showing raw fallback",
            path=path, first_bytes=raw[:16].hex(), body_len=len(raw),
        )
    text = raw.decode("utf-8", errors="replace")
    if _is_signalr_path(path):
        import re as _re2
        text = _re2.sub(r"^[\x00-\x08\x0b-\x1f\x7f�]+", "", text)
    return _re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text)


def _body_preview(raw: Optional[bytes], path: str = "") -> Optional[str]:
    """Generate a short body preview for the HTTP history table column."""
    if not raw:
        return None
    if _is_signalr_body(raw):
        decoded = _decode_signalr_body(raw)
        if decoded:
            first_line = decoded.split("\n")[0]
            return first_line[:120] if first_line else None
    import re as _re
    text = raw[:120].decode("utf-8", errors="replace")
    text = _re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text)
    return text if text.strip() else None


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
            "body_preview": _body_preview(self.request_body, self.path),
            "probe_payload": self.probe_payload,
            "ai_queued": self.ai_queued,
            "manual_note": self.manual_note,
            "import_hints": self.import_hints or [],
        }
        if include_bodies:
            d["request_headers"] = self.request_headers
            d["request_body"] = _decode_body(self.request_body, self.path)
            d["response_headers"] = self.response_headers
            d["response_body"] = _decode_body(self.response_body, self.path)
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

    def __init__(self):
        self._entries: Dict[str, ProxyEntry] = {}
        self._order: List[str] = []
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
        # service graph — auto-detects multi-host application boundaries
        self.service_graph = ServiceGraph()
        # discovery engine — enriches CheckTarget with tech stack, JS endpoints, call chains
        self.discovery_engine = DiscoveryEngine()
        # Active suggestions from AppContextWorker — hypotheses with no matching
        # proxy entry yet. Shown in dashboard AI Suggestions tab with "Test Now" option.
        self.active_suggestions: List[dict] = []
        # When True, new suggestions are automatically queued for scan
        self.auto_scan_suggestions: bool = False
        # Session-wide scan intelligence — accumulated across all endpoints/hosts.
        # The Coordinator reads and writes this on every scan.
        from dast.ai.session_intelligence import SessionIntelligence
        self.session_intelligence = SessionIntelligence()
        # GraphQL schemas discovered via introspection — keyed by endpoint URL.
        # Populated by the graphql_introspection plugin; read by the findings importer
        # to build correct query/mutation bodies when importing reports.
        # Value: {"types": [...], "mutations": {...}, "queries": {...}, "ts": float}
        self.graphql_schemas: Dict[str, dict] = {}
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
            # Add stub finding so the UI shows it before the scan completes
            stub = pf.get("stub")
            if stub and stub.get("title"):
                key = (stub.get("title", ""), stub.get("attack_type", ""), stub.get("parameter", ""))
                if not any(
                    (f.get("title", ""), f.get("attack_type", ""), f.get("parameter", "")) == key
                    for f in entry.findings
                ):
                    entry.findings.append(stub)

        entry.import_hints = existing_hints

        if not entry.queued_for_scan and not entry.scan_result:
            entry.queued_for_scan = True
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

    def set_plugin_manager(self, pm) -> None:
        self._plugin_manager = pm

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

        def _bg_analyse():
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
            except Exception:
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

    def add_finding(self, entry_id: str, finding: dict, scan_result: str) -> None:
        with self._lock:
            e = self._entries.get(entry_id)
            if not e:
                logger.warning("add_finding: entry not found", entry_id=entry_id, scan_result=scan_result)
                return
            if finding.get("title"):
                # Deduplicate: skip if same title + attack_type + parameter already recorded
                key = (finding.get("title", ""), finding.get("attack_type", ""), finding.get("parameter", ""))
                if any((f.get("title", ""), f.get("attack_type", ""), f.get("parameter", "")) == key for f in e.findings):
                    return
                # Auto-populate raw HTTP evidence from the parent entry when the
                # finding (agent or plugin) did not supply it. This ensures every
                # finding has at least the intercepted baseline pair for the report.
                if not finding.get("raw_request") and e.method and e.url:
                    try:
                        finding["raw_request"] = _format_raw_request(e)[:6000]
                    except Exception:
                        pass
                if not finding.get("raw_response") and e.response_status:
                    try:
                        finding["raw_response"] = _format_raw_response(e)[:6000]
                    except Exception:
                        pass
                e.findings.append(finding)
            # Never downgrade a confirmed vulnerable entry to safe/error via an empty sentinel
            if scan_result == "vulnerable" or e.scan_result != "vulnerable":
                e.scan_result = scan_result
        if e:
            self._notify(e)

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
        except Exception:
            pass

    def load_from_session_data(
        self,
        entries_data: list,
        cookies_data: dict,
        settings=None,
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

"""
Active vulnerability checks — lightweight httpx-based scanner.

Each check sends targeted payloads to one endpoint and matches the response
against known patterns. No browser required — fast enough to run inline as
requests pass through the proxy.

Checks implemented:
  - Reflected XSS
  - SQL injection (error-based + boolean-based)
  - Path traversal (LFI)
  - Server-Side Template Injection (SSTI)
  - OS command injection (blind time-based)
  - Open redirect
  - CRLF / header injection
  - SSRF (out-of-band detection via DNS interaction marker)
  - XML External Entity (XXE)
  - Insecure deserialization markers
  - HTTP method tampering (TRACE / TRACK)
"""

from __future__ import annotations

import asyncio
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import httpx

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.discovery.models import DiscoveryContext

logger = get_logger(__name__)


@dataclass
class ActiveFinding:
    title: str
    severity: str          # critical | high | medium | low
    cwe: str
    attack_type: str
    evidence: str
    payload: str
    parameter: str
    url: str
    request_method: str
    confirmed: bool = True
    bypass_validation: bool = False
    reasoning: str = ""


@dataclass
class ServiceContext:
    """
    Cross-service context injected into CheckTarget for Layer 2 scanning.
    Agents READ this to broaden their probes — they never mutate it.
    """
    group_id: str
    sibling_hosts: List[str]           # other hosts in the same service group
    shared_tokens: List[str]           # auth tokens seen on any host in the group
    shared_cookies: Dict[str, str]     # cookie name → value shared across group


@dataclass
class CheckTarget:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    params: List[dict]     # [{name, location, value}]
    raw_body: Optional[bytes] = None  # original bytes for multipart — never reencoded
    service_context: Optional[ServiceContext] = None  # None = no cross-service context
    discovery_context: Optional["DiscoveryContext"] = None  # None = no discovery data yet
    app_profile_hint: str = ""   # synthesised app intelligence from AppContextWorker
    threat_model_hint: str = ""  # architectural constraints from ThreatModelWorker
    code_hint: str = ""          # relevant source code snippets from code analysis
    import_hints: List[dict] = None  # [{parameter, payload, attack_type}] from imported reports
    named_sessions: List = None  # List[NamedSession] — for cross-session IDOR testing
    host_intel: Optional[object] = None  # HostIntel from SessionIntelligence — read-only for agents
    probe_diff_hint: str = ""    # per-param injection-context hypotheses from the probe-diff pass
    param_mining_hint: str = ""  # hidden parameters discovered by the automatic param-mining pass


# ── request/response capture ───────────────────────────────────────────────

def _fmt_http_pair(resp: httpx.Response, max_body: int = 4000) -> tuple[str, str]:
    """Format an httpx response into (raw_request, raw_response) strings."""
    req = resp.request
    req_headers = "\r\n".join(f"{k}: {v}" for k, v in req.headers.items())
    try:
        req_body = req.content.decode("utf-8", errors="replace")
    except Exception:
        req_body = ""
    raw_req = f"{req.method} {req.url} HTTP/1.1\r\n{req_headers}"
    if req_body:
        raw_req += f"\r\n\r\n{req_body}"

    resp_headers = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    try:
        resp_body = resp.text[:max_body]
    except Exception:
        resp_body = ""
    raw_resp = f"HTTP/1.1 {resp.status_code}\r\n{resp_headers}\r\n\r\n{resp_body}"

    return raw_req, raw_resp


# ── httpx client factory ───────────────────────────────────────────────────

def _client(proxy_url: Optional[str] = None, timeout: float = 10.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(timeout),
        verify=False,
        proxy=proxy_url or None,
    )


# ── parameter injection helpers ────────────────────────────────────────────

def _inject_query(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _inject_path(url: str, path_index: int, value: str) -> str:
    """Replace the path segment at ``path_index`` with ``value`` (percent-encoded).

    REST APIs carry identifiers in the path (``/users/v1/{username}``); the
    injection agents can only fuzz what lands in ``target.params``, so a path
    segment is exposed as an injectable surface with ``location == "path"`` and a
    ``path_index``. ``path_index`` is 0-based over the NON-EMPTY path components
    (the same enumeration the CheckTarget adapter uses), so leading/trailing
    slashes are preserved. The payload is percent-encoded so quotes/spaces/slashes
    travel intact in the path and are decoded server-side before reaching the
    vulnerable sink. Out-of-range indices leave the URL unchanged."""
    parsed = urlparse(url)
    raw_segments = parsed.path.split("/")
    non_empty_positions = [i for i, seg in enumerate(raw_segments) if seg]
    if path_index < 0 or path_index >= len(non_empty_positions):
        return url
    raw_segments[non_empty_positions[path_index]] = quote(value, safe="")
    return urlunparse(parsed._replace(path="/".join(raw_segments)))


def _inject_multipart(raw_body: bytes, param: str, value: str) -> bytes:
    """
    Inject a payload into a multipart request body.

    param encodes what to change:
      "multipart_filename:<part_name>"  — rewrites filename= in Content-Disposition
      "multipart_ct:<part_name>"        — rewrites the Content-Type header of the part
      "multipart_body:<part_name>"      — replaces the entire body of the part with value
                                          (used to test file content — e.g. replace an
                                          image with an XSS payload or SSRF probe URL)

    For filename/ct: the binary blob between the headers and the next boundary is untouched.
    For body: only the content section is replaced; headers (including filename) stay.
    """
    if not raw_body:
        return raw_body

    colon = param.find(":")
    if colon == -1:
        return raw_body
    kind = param[:colon]           # "multipart_filename" | "multipart_ct" | "multipart_body"
    part_name = param[colon + 1:]  # e.g. "artwork"

    encoded = value.encode("utf-8", errors="replace")
    name_tag = b'name="' + part_name.encode() + b'"'

    if kind == "multipart_body":
        # Find the part by its Content-Disposition name tag, then locate the CRLFCRLF
        # that separates headers from content, then replace everything up to the next
        # boundary marker. The headers (including filename and Content-Type) are preserved.
        disp_pos = raw_body.find(name_tag)
        if disp_pos == -1:
            return raw_body
        # Scan back to the start of this part's header block (the boundary line)
        header_end = raw_body.find(b"\r\n\r\n", disp_pos)
        if header_end == -1:
            return raw_body
        content_start = header_end + 4  # after CRLFCRLF

        # Find the next boundary — boundaries start with \r\n--
        next_boundary = raw_body.find(b"\r\n--", content_start)
        if next_boundary == -1:
            return raw_body

        return (
            raw_body[:content_start]
            + encoded
            + raw_body[next_boundary:]
        )

    # --- filename / ct: rewrite individual header fields, leave body bytes intact ---
    out = bytearray()
    i = 0

    while i < len(raw_body):
        end = raw_body.find(b"\r\n", i)
        if end == -1:
            out.extend(raw_body[i:])
            break
        line = raw_body[i:end]

        if kind == "multipart_filename":
            if (name_tag in line
                    and b"filename=" in line
                    and b"Content-Disposition" in line):
                line = re.sub(
                    rb'filename="[^"]*"',
                    b'filename="' + encoded + b'"',
                    line,
                )
        elif kind == "multipart_ct":
            prev_end = out.rfind(b"\r\n", 0, len(out) - 1)
            prev_line = out[prev_end + 2:] if prev_end != -1 else bytes(out)
            if (name_tag in prev_line and line.lower().startswith(b"content-type:")):
                line = b"Content-Type: " + encoded

        out.extend(line)
        out.extend(b"\r\n")
        i = end + 2

    return bytes(out)


def _inject_body(body: str, param: str, value: str, content_type: str,
                 location: str = "body") -> str:
    if not body:
        return body
    if "json" in content_type.lower() or location == "body_graphql":
        import json
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                if location == "body_graphql" and isinstance(data.get("variables"), dict):
                    # param may be a dot-notation path like "input.prompt"
                    keys = param.split(".")
                    target_obj = data["variables"]
                    for k in keys[:-1]:
                        if isinstance(target_obj, dict) and k in target_obj:
                            target_obj = target_obj[k]
                        else:
                            target_obj = None
                            break
                    if isinstance(target_obj, dict):
                        target_obj[keys[-1]] = value
                    else:
                        data["variables"][param] = value
                else:
                    # Support dot-notation for nested JSON: "address.city" → data["address"]["city"]
                    keys = param.split(".")
                    target_obj = data
                    for k in keys[:-1]:
                        if isinstance(target_obj, dict) and k in target_obj:
                            target_obj = target_obj[k]
                        else:
                            target_obj = None
                            break
                    if isinstance(target_obj, dict):
                        target_obj[keys[-1]] = value
                    else:
                        data[param] = value
                return json.dumps(data)
        except Exception as exc:
            logger.debug("failed to inject payload into JSON body; falling back to form-urlencoded", error=str(exc))
    # form-urlencoded fallback
    pairs = {}
    for part in body.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            pairs[k] = v
    pairs[param] = value
    return "&".join(f"{k}={v}" for k, v in pairs.items())


def _inject_header(headers: Dict[str, str], name: str, value: str) -> Dict[str, str]:
    """
    Return a copy of ``headers`` with header ``name`` set to ``value``.

    Header injection point: many apps trust request headers (User-Agent, Referer,
    X-Forwarded-For, ...) and pass them unsanitised into SQL, templates, logs or
    the response. Replacing the header value with a payload turns it into a
    first-class fuzzable entrypoint. Matching is case-insensitive so the existing
    header (whatever its original casing) is overwritten rather than duplicated.
    """
    new_headers = {key: val for key, val in headers.items() if key.lower() != name.lower()}
    new_headers[name] = value
    return new_headers


def _inject_cookie(headers: Dict[str, str], name: str, value: str) -> Dict[str, str]:
    """
    Return a copy of ``headers`` with cookie ``name`` in the Cookie header set to
    ``value``, preserving every other cookie.

    Cookie values are a classic injection entrypoint (SQLi/XSS via a tracking or
    preference cookie). Only the target cookie's value is replaced; the rest of
    the jar is left intact so the session/auth cookies keep working.
    """
    cookie_header = ""
    other_headers: Dict[str, str] = {}
    for key, val in headers.items():
        if key.lower() == "cookie":
            cookie_header = val
        else:
            other_headers[key] = val

    pairs: List[tuple[str, str]] = []
    replaced = False
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part:
            continue
        cookie_name, _, cookie_value = part.partition("=")
        if cookie_name.strip() == name:
            pairs.append((name, value))
            replaced = True
        else:
            pairs.append((cookie_name.strip(), cookie_value))
    if not replaced:
        pairs.append((name, value))

    other_headers["Cookie"] = "; ".join(f"{cookie_name}={cookie_value}" for cookie_name, cookie_value in pairs)
    return other_headers


def prepend_import_payloads(
    base_payloads: List[str],
    param_name: str,
    attack_type: str,
    target: "CheckTarget",
) -> List[str]:
    """
    Prepend payloads from imported report hints to the front of the seed list.

    When a report says "parameter X is vulnerable to sqli with payload Y", we try
    Y first before falling back to the generic YAML seeds. This gives the agent the
    best chance of reproducing the exact finding from the original report.
    """
    if not target.import_hints:
        return base_payloads
    priority: List[str] = []
    for hint in target.import_hints:
        hint_param = hint.get("parameter", "")
        hint_payload = hint.get("payload", "")
        hint_type = hint.get("attack_type", "")
        if not hint_payload:
            continue
        # Match by param name (exact or suffix for dot-notation) and attack type family
        param_match = (
            hint_param == param_name
            or param_name.endswith("." + hint_param)
            or hint_param.endswith("." + param_name)
            or not hint_param  # no param specified — try on every param
        )
        type_match = (
            not hint_type
            or hint_type == attack_type
            or hint_type.startswith(attack_type)
            or attack_type.startswith(hint_type)
        )
        if param_match and type_match and hint_payload not in priority:
            priority.append(hint_payload)
    if not priority:
        return base_payloads
    # Deduplicate: keep priority first, then remaining base payloads
    seen = set(priority)
    return priority + [p for p in base_payloads if p not in seen]


# Minimum delay between agent probe requests — prevents rate-limit bans
# and avoids flooding the target. Configurable via env DAST_PROBE_DELAY_MS.
import os as _os
_PROBE_DELAY = float(_os.environ.get("DAST_PROBE_DELAY_MS", "200")) / 1000.0

# Adaptive rate limiting: per-host delay multiplier increased on 429/503 responses.
# Keyed by hostname, value is current delay multiplier (1.0 = base delay).
_RATE_LIMIT_STATE: Dict[str, float] = {}
_RATE_LIMIT_LOCK = asyncio.Lock()

_RATE_LIMIT_BACKOFF_FACTOR = 3.0    # multiply delay by this on 429
_RATE_LIMIT_MAX_MULTIPLIER = 20.0   # cap at 20x base delay (~4s at default 200ms)
_RATE_LIMIT_RECOVERY_FACTOR = 0.8   # slowly recover after successful responses


async def _get_probe_delay(hostname: str) -> float:
    """Return current effective delay for a host, accounting for rate limiting."""
    multiplier = _RATE_LIMIT_STATE.get(hostname, 1.0)
    return _PROBE_DELAY * multiplier


async def _record_rate_limit(hostname: str) -> None:
    """Increase delay for this host after receiving a 429/503."""
    async with _RATE_LIMIT_LOCK:
        current = _RATE_LIMIT_STATE.get(hostname, 1.0)
        new_mult = min(current * _RATE_LIMIT_BACKOFF_FACTOR, _RATE_LIMIT_MAX_MULTIPLIER)
        _RATE_LIMIT_STATE[hostname] = new_mult
        logger.info(
            "Adaptive rate limit: backing off",
            host=hostname,
            delay_s=round(_PROBE_DELAY * new_mult, 2),
        )


async def _record_success(hostname: str) -> None:
    """Gradually recover delay for this host after successful responses."""
    current = _RATE_LIMIT_STATE.get(hostname, 1.0)
    if current > 1.0:
        async with _RATE_LIMIT_LOCK:
            _RATE_LIMIT_STATE[hostname] = max(1.0, current * _RATE_LIMIT_RECOVERY_FACTOR)


# ── host reachability circuit breaker ──────────────────────────────────────
# A host that cannot be reached (DNS failure, connection refused, proxy 502/504)
# will fail every single probe. Without a breaker, each agent keeps firing dozens
# of payloads at a dead host, flooding the history with status-less requests and
# wasting the whole scan budget. We track consecutive connection failures per host
# and, once the threshold is hit, short-circuit all further probes to that host.
_HOST_FAILURE_STATE: Dict[str, int] = {}   # hostname -> consecutive connection-failure count
_HOST_DEAD: set = set()                     # hostnames confirmed unreachable (breaker open)
_HOST_DEAD_AT: Dict[str, float] = {}        # hostname -> monotonic time the breaker tripped
_HOST_FAILURE_LOCK = asyncio.Lock()

# Consecutive connection failures before a host is declared unreachable. Small
# enough to stop the flood fast, large enough to tolerate a transient blip.
_HOST_DEAD_THRESHOLD = 5

# Once tripped, a host is retried after this cooldown rather than staying dead
# for the whole session. A transient overload (a burst of proxy 502s, a briefly
# saturated local target) must not silently disable active scanning of a host
# that has since recovered — the earlier permanent breaker was a sticky
# false-negative source. If the host is still down, the next few probes re-trip
# the breaker at negligible cost.
_HOST_DEAD_COOLDOWN_SECONDS = 120.0


def is_host_dead(hostname: str) -> bool:
    """True if this host's breaker is currently open.

    The breaker self-heals: once the cooldown since it tripped has elapsed, the
    host is given another chance (state cleared) and probing resumes.
    """
    if hostname not in _HOST_DEAD:
        return False
    tripped_at = _HOST_DEAD_AT.get(hostname)
    if tripped_at is not None and (time.monotonic() - tripped_at) >= _HOST_DEAD_COOLDOWN_SECONDS:
        _HOST_DEAD.discard(hostname)
        _HOST_DEAD_AT.pop(hostname, None)
        _HOST_FAILURE_STATE.pop(hostname, None)
        logger.info("Host breaker cooldown elapsed — re-enabling probes", host=hostname)
        return False
    return True


async def _record_connection_failure(hostname: str) -> bool:
    """
    Record a connection-level failure (DNS/refused/proxy-502) for a host.
    Returns True if this failure just tripped the breaker (host now dead).
    """
    async with _HOST_FAILURE_LOCK:
        if hostname in _HOST_DEAD:
            return False
        count = _HOST_FAILURE_STATE.get(hostname, 0) + 1
        _HOST_FAILURE_STATE[hostname] = count
        if count >= _HOST_DEAD_THRESHOLD:
            _HOST_DEAD.add(hostname)
            _HOST_DEAD_AT[hostname] = time.monotonic()
            logger.warning(
                "Host unreachable — circuit breaker open, skipping further probes",
                host=hostname, consecutive_failures=count,
                cooldown_s=_HOST_DEAD_COOLDOWN_SECONDS,
            )
            return True
    return False


async def _record_host_reachable(hostname: str) -> None:
    """A real response arrived — reset the failure counter for this host."""
    if _HOST_FAILURE_STATE.get(hostname):
        async with _HOST_FAILURE_LOCK:
            _HOST_FAILURE_STATE.pop(hostname, None)


def reset_host_reachability() -> None:
    """Clear all reachability state — call at the start of a fresh scan session."""
    _HOST_FAILURE_STATE.clear()
    _HOST_DEAD.clear()
    _HOST_DEAD_AT.clear()
    _HOST_LIMITERS.clear()
    _HOST_SCAN_GATE._in_flight.clear()


# Statuses the MITM proxy returns when it cannot reach the upstream host —
# treat these as connection failures, not real application responses.
_PROXY_UNREACHABLE_STATUSES = frozenset({502, 504})


# Global semaphore — hard ceiling on concurrent outgoing probe requests across all
# agents (resized at scan start to probe_concurrency * workers by the runner). This
# is the absolute cap; the per-host adaptive limiter below drives the *effective*
# concurrency down further whenever a target shows it cannot sustain the load.
_PROBE_SEM = asyncio.Semaphore(3)
_PROBE_SLOTS_TOTAL = 3  # mirror of the configured ceiling, used as the limiter's max


def set_probe_concurrency(total_slots: int) -> None:
    """Resize the global probe semaphore. Called by the runner when a scan starts."""
    global _PROBE_SEM, _PROBE_SLOTS_TOTAL
    _PROBE_SEM = asyncio.Semaphore(total_slots)
    _PROBE_SLOTS_TOTAL = max(1, total_slots)


# ── per-host adaptive concurrency limiter (latency-gradient AIMD) ────────────
# A single-worker target (a dev DVWA, a small app-server pool) cannot serve N
# probes in parallel: concurrent requests queue behind each other, so every
# request's latency grows roughly linearly with in-flight count while total
# throughput stays flat. Observed on DVWA under 16-way probing: a ~0.1s localhost
# round-trip inflated to 18-22s, past the client read timeout — time-based SLEEP
# probes were discarded, and the per-endpoint budget bought only a handful of
# requests, so blind-injection detection (which needs several clean probes) never
# finished. More concurrency there is strictly worse.
#
# This limiter watches each host's server round-trip (resp.elapsed, not wall-clock,
# so our own queue wait does not feed back) and applies AIMD, exactly like TCP
# congestion control: when latency inflates far past the host's uncontended
# baseline (or a probe times out) it multiplicatively halves the in-flight limit;
# when latency is healthy it grows the limit by one. Against a single-worker target
# it converges to near-serial (fast requests, clean timing, budget spent on many
# probes); against a target that genuinely scales it climbs back to the ceiling.
_LATENCY_INFLATION = 4.0      # rtt beyond baseline_min * this counts as congestion
_LATENCY_FLOOR_S = 1.0        # never treat a sub-second rtt as congestion
_CONCURRENCY_BACKOFF = 0.5    # multiplicative decrease on a congestion signal
_CONCURRENCY_RECOVER = 1.0    # additive increase when latency is healthy

_HOST_LIMITERS: "Dict[str, _HostConcurrencyLimiter]" = {}
_HOST_LIMITERS_LOCK = asyncio.Lock()


class _HostConcurrencyLimiter:
    """Adaptive in-flight cap for one host. See the module comment above for the
    congestion-control rationale. Not thread-safe; single event loop only."""

    def __init__(self, max_limit: int) -> None:
        self.max_limit = max(1, max_limit)
        self.limit = float(self.max_limit)
        self.in_flight = 0
        self.min_rtt: "Optional[float]" = None  # uncontended baseline, seconds
        # Sticky: set once this host has shown it cannot sustain concurrent load
        # (a congestion signal or a latency-inflation backoff). The endpoint-scan
        # gate reads it to clamp a host to serial scanning even if the operator
        # raised host_scan_concurrency — a target that chokes stays protected.
        self.saturated_seen = False
        self._cond = asyncio.Condition()

    async def acquire(self) -> None:
        async with self._cond:
            while self.in_flight >= max(1, int(self.limit)):
                await self._cond.wait()
            self.in_flight += 1

    async def release(self, rtt_s: "Optional[float]", congested: bool = False) -> None:
        async with self._cond:
            self.in_flight = max(0, self.in_flight - 1)
            self._update_limit(rtt_s, congested)
            # Wake everyone; each waiter re-checks the (possibly changed) limit.
            self._cond.notify_all()

    def _update_limit(self, rtt_s: "Optional[float]", congested: bool) -> None:
        if congested:
            self.limit = max(1.0, self.limit * _CONCURRENCY_BACKOFF)
            self.saturated_seen = True
            return
        if rtt_s is None or rtt_s <= 0:
            return
        if self.min_rtt is None or rtt_s < self.min_rtt:
            self.min_rtt = rtt_s
        ceiling = max((self.min_rtt or 0.0) * _LATENCY_INFLATION, _LATENCY_FLOOR_S)
        if rtt_s > ceiling:
            self.limit = max(1.0, self.limit * _CONCURRENCY_BACKOFF)
            self.saturated_seen = True
        else:
            self.limit = min(float(self.max_limit), self.limit + _CONCURRENCY_RECOVER)


async def _get_host_limiter(hostname: str) -> "_HostConcurrencyLimiter":
    """Return (creating on first use) the adaptive limiter for a host, sized to the
    current global ceiling."""
    async with _HOST_LIMITERS_LOCK:
        limiter = _HOST_LIMITERS.get(hostname)
        if limiter is None or limiter.max_limit != _PROBE_SLOTS_TOTAL:
            limiter = _HostConcurrencyLimiter(_PROBE_SLOTS_TOTAL)
            _HOST_LIMITERS[hostname] = limiter
        return limiter


# ── per-host endpoint-scan gate (endpoint-level politeness) ──────────────────
# The request limiter above throttles concurrent *probes*, but the runner still
# starts several endpoint SCANS in parallel (runner._scan_sem, sized to `workers`).
# Against a single-worker target that is self-defeating: N endpoint scans time-
# slice the host's one worker, so a scan whose slower agents run late — time-based
# blind (SLEEP/WAITFOR), or LFI walking a traversal list — can burn its whole
# per-endpoint deadline before its working probe is even sent, and the endpoint is
# scored a false "safe" (the observed run-to-run flaky LFI / blind detection).
# Serializing endpoint scans per host gives each scan the host's full throughput so
# it finishes within budget; it costs nothing on a single-worker target (its
# requests were already serial under the limiter) and only trades cross-endpoint
# parallelism on a genuinely scalable host, which the operator restores by raising
# host_scan_concurrency. Different hosts still scan fully in parallel — the gate is
# per host and the global _scan_sem remains the overall worker cap.
_DEFAULT_HOST_SCAN_CONCURRENCY = 1


class _HostScanGate:
    """Adaptive per-host cap on concurrently-running endpoint scans. Single event
    loop only. The allowance is `default_limit`, clamped to 1 for any host the
    request limiter has already caught saturating under load (sticky), so raising
    the knob for scalable targets never re-introduces starvation on a slow one."""

    def __init__(self) -> None:
        self.default_limit = _DEFAULT_HOST_SCAN_CONCURRENCY
        self._in_flight: "Dict[str, int]" = {}
        self._cond = asyncio.Condition()

    def configure(self, default_limit: int) -> None:
        self.default_limit = max(1, int(default_limit))

    def _allowed(self, hostname: str) -> int:
        limiter = _HOST_LIMITERS.get(hostname)
        if limiter is not None and limiter.saturated_seen:
            return 1
        return max(1, self.default_limit)

    async def acquire(self, hostname: str) -> None:
        async with self._cond:
            while self._in_flight.get(hostname, 0) >= self._allowed(hostname):
                await self._cond.wait()
            self._in_flight[hostname] = self._in_flight.get(hostname, 0) + 1

    async def release(self, hostname: str) -> None:
        async with self._cond:
            self._in_flight[hostname] = max(0, self._in_flight.get(hostname, 0) - 1)
            # Wake all waiters; each re-checks its own host's (possibly changed) allowance.
            self._cond.notify_all()


_HOST_SCAN_GATE = _HostScanGate()


def configure_host_scan_concurrency(default_limit: int) -> None:
    """Set how many endpoint scans may run concurrently against a single host.
    Called by the runner at scan start (default 1 — serialize per host)."""
    _HOST_SCAN_GATE.configure(default_limit)


async def acquire_host_scan_slot(hostname: str) -> None:
    """Block until this host may run another concurrent endpoint scan."""
    await _HOST_SCAN_GATE.acquire(hostname)


async def release_host_scan_slot(hostname: str) -> None:
    """Release an endpoint-scan slot for this host."""
    await _HOST_SCAN_GATE.release(hostname)


# Global lock serializing time-based blind probes (SLEEP/WAITFOR) across ALL agents
# and endpoints. A single sleeping request pins one of the target's application
# workers for the whole sleep duration; app servers (and especially a single-worker
# dev target) have a small worker pool, so N concurrent SLEEP probes queue behind
# each other and multiply the ambient latency every OTHER request measures against.
# Under 16-way probe concurrency that inflated a 0.1s localhost round-trip to
# 10-16s, which starved the per-endpoint budget so the injectable parameter's
# time-based probe never finished. Serializing keeps at most one sleep in flight,
# so the control/probe pair each stay fast and the differential is measured in a
# few seconds. This deliberately does NOT drain the whole probe pool (an earlier
# "quiesce everything" attempt did, starving concurrent non-time agents); fast
# content probes never take this lock.
_TIME_PROBE_LOCK = asyncio.Lock()


@asynccontextmanager
async def serialize_time_probe():
    """Hold the global time-probe lock around one control/probe measurement so no
    other agent's SLEEP is in flight at the same time (see _TIME_PROBE_LOCK)."""
    async with _TIME_PROBE_LOCK:
        yield


# Regexes that rewrite the sleep duration inside a time-based payload to an
# arbitrary value, preserving the exact query shape. Each template carries an `{n}`
# placeholder between the captured prefix/suffix backreferences. Used to build both
# the false control (sleep = 0) and the delay-scaling confirmation probe (sleep = a
# distinct value), following sqlmap's approach: only the server-side sleep should
# distinguish these otherwise-identical requests, and a real injection's measured
# delay tracks the requested one while ambient jitter does not.
_DELAY_SUBS: "List[tuple[re.Pattern, str]]" = [
    (re.compile(r"(SLEEP\s*\(\s*)\d+(?:\.\d+)?(\s*\))", re.IGNORECASE), r"\g<1>{n}\g<2>"),
    (re.compile(r"(pg_sleep\s*\(\s*)\d+(?:\.\d+)?(\s*\))", re.IGNORECASE), r"\g<1>{n}\g<2>"),
    (re.compile(r"(WAITFOR\s+DELAY\s+'0:0:)\d+(')", re.IGNORECASE), r"\g<1>{n}\g<2>"),
    (re.compile(r"(\bsleep\s+)\d+(?:\.\d+)?\b", re.IGNORECASE), r"\g<1>{n}"),
]


def scaled_delay_variant(payload: str, seconds: int) -> "Optional[str]":
    """Return `payload` with its sleep duration rewritten to `seconds` (same query
    shape), or None when no known sleep construct is present. `seconds=0` yields the
    false control; a distinct value yields the delay-scaling confirmation probe."""
    for pattern, template in _DELAY_SUBS:
        replacement = template.replace("{n}", str(int(seconds)))
        new_payload, count = pattern.subn(replacement, payload)
        if count:
            return new_payload
    return None


def zero_delay_variant(payload: str) -> "Optional[str]":
    """Return `payload` with its sleep duration zeroed (the false control for a
    true/false time differential), or None when no known sleep construct is present
    — the caller then falls back to a plain clean-value control."""
    return scaled_delay_variant(payload, 0)


async def _send(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: "Optional[str | bytes]",
    payload: Optional[str] = None,
    source: str = "agent",
    timeout: "Optional[float]" = None,
) -> "Optional[httpx.Response]":
    from urllib.parse import urlparse as _up
    hostname = _up(url).hostname or url

    # Circuit breaker: once a host is confirmed unreachable, stop probing it —
    # every further request would just fail and flood the history.
    if is_host_dead(hostname):
        return None

    limiter = await _get_host_limiter(hostname)
    async with _PROBE_SEM:
        await limiter.acquire()
        rtt_s: "Optional[float]" = None
        congested = False
        try:
            delay = await _get_probe_delay(hostname)
            await asyncio.sleep(delay)
            forward_headers = {
                k: v for k, v in headers.items()
                if k.lower() not in (
                    "host", "content-length", "transfer-encoding",
                    "connection", "accept-encoding", "x-dast-crawler",
                )
            }
            forward_headers["x-dast-source"] = source
            if payload is not None:
                # Truncate to keep headers small; proxy strips this before forwarding
                forward_headers["x-dast-payload"] = payload[:200]
            if isinstance(body, bytes):
                content = body
            elif body:
                content = body.encode()
            else:
                content = None
            # A time-based blind probe (SLEEP/WAITFOR) needs a read timeout longer
            # than the injected delay PLUS whatever ambient latency the target is
            # under from concurrent probing. Without it the SLEEP response exceeds
            # the default client timeout, the request is discarded (resp=None), and
            # the delay we were trying to measure is never observed. Callers pass an
            # explicit per-probe timeout for these; everything else uses the client
            # default.
            request_timeout = (
                httpx.Timeout(timeout) if timeout is not None else httpx.USE_CLIENT_DEFAULT
            )
            resp = await client.request(
                method=method,
                url=url,
                headers=forward_headers,
                content=content,
                timeout=request_timeout,
            )
            # Feed the server round-trip to the adaptive limiter. A time-based
            # SLEEP probe legitimately runs long, so it is not a congestion signal;
            # exclude it (the caller passes an explicit timeout for those).
            if timeout is None:
                rtt_s = response_elapsed_ms(resp) / 1000.0

            # A 502/504 from the MITM proxy means it could not reach the upstream
            # host (DNS failure, connection refused) — treat it as a connection
            # failure for the breaker, not a real application response.
            if resp.status_code in _PROXY_UNREACHABLE_STATUSES:
                await _record_connection_failure(hostname)
                return resp

            # Adaptive rate limiting: back off on 429/503, recover on success
            if resp.status_code in (429, 503):
                await _record_rate_limit(hostname)
                retry_after = resp.headers.get("retry-after", "")
                if retry_after.isdigit():
                    wait = min(int(retry_after), 30)
                    logger.info("Rate limited — honouring Retry-After", host=hostname, wait_s=wait)
                    await asyncio.sleep(wait)
            elif resp.status_code < 500:
                await _record_success(hostname)

            # Any real response (even a 4xx/5xx app error) proves the host is
            # reachable — reset the connection-failure counter.
            await _record_host_reachable(hostname)
            return resp
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ProxyError) as e:
            # True connection-level failure: DNS failure, connection refused,
            # connect timeout, or the MITM proxy could not reach upstream. The
            # host is unreachable — count it toward the breaker so a dead host
            # stops the scan instead of spinning.
            logger.debug("Active check connection failed", url=url, error=str(e))
            await _record_connection_failure(hostname)
            return None
        except Exception as e:
            # The connection was established but the exchange did not complete
            # (read/pool/write timeout, protocol error, socket read error). A
            # read timeout in particular is EXPECTED for time-based blind probes
            # (SLEEP/WAITFOR payloads) and proves the host is reachable — it must
            # NOT trip the breaker, or a slow endpoint would silently disable all
            # further active scanning of a perfectly live host. Treat it as a
            # reachable-but-slow response: reset the failure counter, drop this
            # probe's result.
            logger.debug("Active check request failed (host still reachable)", url=url, error=str(e))
            await _record_host_reachable(hostname)
            # A default-timeout request that did not complete is the strongest
            # congestion signal there is: the target could not answer in time under
            # the current load. Time-based probes (explicit timeout) time out for
            # benign reasons, so they do not count against concurrency.
            if timeout is None:
                congested = True
            return None
        finally:
            await limiter.release(rtt_s, congested)


def response_elapsed_ms(resp: "Optional[httpx.Response]") -> float:
    """Server round-trip time of a response in milliseconds.

    httpx measures `.elapsed` from the moment the request is written to when the
    response is fully read — entirely inside the `_PROBE_SEM` critical section and
    after the per-host probe delay. It therefore excludes the time an agent spent
    waiting to ACQUIRE the (small, 3-slot) probe semaphore, which under concurrent
    multi-agent load can dominate wall-clock timing and swamp the ~5s signal a
    time-based blind probe is trying to measure. Time-based detectors must compare
    this, not wall-clock, so a SLEEP that executed server-side is not masked by
    queue contention. Returns 0.0 when no response (timeout/connection failure) or
    when `.elapsed` is not yet populated.
    """
    if resp is None:
        return 0.0
    try:
        return resp.elapsed.total_seconds() * 1000
    except (RuntimeError, AttributeError):
        return 0.0


def get_rate_limit_state() -> Dict[str, float]:
    """Return current rate limit multipliers per host — for dashboard display."""
    return dict(_RATE_LIMIT_STATE)


# ── XSS ───────────────────────────────────────────────────────────────────

_XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<svg onload=alert(1)>',
]
_XSS_REFLECTED_RE = re.compile(
    r'<(?:img[^>]+onerror|script|svg[^>]+onload)[^>]*>',
    re.IGNORECASE,
)

async def check_xss(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    findings = []
    for param in target.params:
        for payload in _XSS_PAYLOADS[:2]:  # 2 payloads per param to keep scan fast
            if param["location"] == "query":
                url = _inject_query(target.url, param["name"], payload)
                resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
            elif param["location"] in ("body", "body_graphql"):
                body = _inject_body(target.body or "", param["name"], payload,
                                    target.headers.get("content-type", ""),
                                    location=param["location"])
                resp = await _send(client, target.method, target.url, target.headers, body, payload=payload)
            else:
                continue

            if resp is None:
                continue
            body_text = resp.text
            if payload in body_text and _XSS_REFLECTED_RE.search(body_text):
                findings.append(ActiveFinding(
                    title="Reflected Cross-Site Scripting (XSS)",
                    severity="high",
                    cwe="CWE-79",
                    attack_type="xss",
                    evidence=f"Payload reflected unencoded in response (status {resp.status_code})",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                ))
                break
    return findings


# ── SQL injection ──────────────────────────────────────────────────────────

# Error-based, boolean-based, and time-based (5s max — enough to confirm, not enough to cause DoS)
_SQLI_PAYLOADS = ["'", "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]
_SQLI_TIME_PAYLOADS = [
    "'; SELECT SLEEP(5)-- -",
    "' OR SLEEP(5)-- -",
    "1; WAITFOR DELAY '0:0:5'-- -",
    "1' AND SLEEP(5)-- -",
]
_SQLI_TIME_THRESHOLD_MS = 4500  # response must be >= 4.5s to confirm time-based
_SQLI_ERROR_RE = re.compile(
    r"you have an error in your sql syntax|unclosed quotation mark|"
    r"quoted string not properly terminated|pg_query\(\)|"
    r"ORA-\d{5}|Microsoft OLE DB Provider for SQL|"
    r"Syntax error.*SQL|SQLiteException|SQLITE_ERROR|"
    # SQLite / SQLAlchemy (Python/Flask/embedded) — surfaced when an injected
    # quote breaks the query; common and previously unmatched.
    r"sqlite3\.(?:Operational|Integrity|Programming|Database)Error|"
    r"unrecognized token|SQL logic error|"
    r"sqlalchemy\.exc\.(?:Operational|Programming)Error|"
    r"sql syntax.*near|near.*syntax error|warning.*mysql",
    re.IGNORECASE,
)

async def check_sqli(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    findings = []
    for param in target.params:
        for payload in _SQLI_PAYLOADS[:3]:
            if param["location"] == "query":
                url = _inject_query(target.url, param["name"], payload)
                resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
            elif param["location"] in ("body", "body_graphql"):
                body = _inject_body(target.body or "", param["name"], payload,
                                    target.headers.get("content-type", ""),
                                    location=param["location"])
                resp = await _send(client, target.method, target.url, target.headers, body, payload=payload)
            else:
                continue

            if resp is None:
                continue
            m = _SQLI_ERROR_RE.search(resp.text)
            if m:
                evidence_snippet = resp.text[max(0, m.start() - 30):m.end() + 60].strip()
                findings.append(ActiveFinding(
                    title="SQL Injection (Error-Based)",
                    severity="critical",
                    cwe="CWE-89",
                    attack_type="sqli",
                    evidence=f"SQL error in response: {evidence_snippet!r}",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                ))
                break
    return findings


async def check_sqli_timebased(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    """
    Blind time-based SQLi detection using 5-second delays.
    Confirms only when response time >= 4.5s (accounts for network jitter).
    Max delay per payload is 5s — well within safe limits.
    """
    findings = []
    for param in target.params:
        for payload in _SQLI_TIME_PAYLOADS:
            t0 = time.monotonic()
            if param["location"] == "query":
                url = _inject_query(target.url, param["name"], payload)
                resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
            elif param["location"] in ("body", "body_graphql"):
                body = _inject_body(target.body or "", param["name"], payload,
                                    target.headers.get("content-type", ""),
                                    location=param["location"])
                resp = await _send(client, target.method, target.url, target.headers, body, payload=payload)
            else:
                continue

            elapsed_ms = (time.monotonic() - t0) * 1000
            if resp is not None and elapsed_ms >= _SQLI_TIME_THRESHOLD_MS:
                findings.append(ActiveFinding(
                    title="SQL Injection (Time-Based Blind)",
                    severity="critical",
                    cwe="CWE-89",
                    attack_type="sqli",
                    evidence=f"Response delayed {elapsed_ms:.0f}ms with payload {payload!r} in '{param['name']}'",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                ))
                break  # one confirmed time-based finding per param is enough
    return findings


# ── Path traversal / LFI ──────────────────────────────────────────────────

_LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
_LFI_MATCH_RE = re.compile(r"root:.*:0:0:|\\[fonts\\]|\[boot loader\]")

async def check_path_traversal(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    findings = []
    for param in target.params:
        for payload in _LFI_PAYLOADS:
            if param["location"] == "query":
                url = _inject_query(target.url, param["name"], payload)
                resp = await _send(client, "GET", url, target.headers, None, payload=payload)
            elif param["location"] in ("body", "body_graphql"):
                body = _inject_body(target.body or "", param["name"], payload,
                                    target.headers.get("content-type", ""),
                                    location=param["location"])
                resp = await _send(client, target.method, target.url, target.headers, body, payload=payload)
            else:
                continue
            if resp and _LFI_MATCH_RE.search(resp.text):
                findings.append(ActiveFinding(
                    title="Path Traversal / Local File Inclusion",
                    severity="high",
                    cwe="CWE-22",
                    attack_type="lfi",
                    evidence=f"File content pattern detected in response for payload {payload!r}",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                ))
                break
    return findings


# ── SSTI ──────────────────────────────────────────────────────────────────

_SSTI_PAYLOADS = [
    ("{{8887*8893}}", "79014691"),
    ("${8887*8893}", "79014691"),
    ("<%= 8887*8893 %>", "79014691"),
    ("#{8887*8893}", "79014691"),
    ("*{8887*8893}", "79014691"),
]

async def check_ssti(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    findings = []
    for param in target.params:
        for payload, expected in _SSTI_PAYLOADS[:3]:
            if param["location"] == "query":
                url = _inject_query(target.url, param["name"], payload)
                resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
            elif param["location"] in ("body", "body_graphql"):
                body = _inject_body(target.body or "", param["name"], payload,
                                    target.headers.get("content-type", ""),
                                    location=param["location"])
                resp = await _send(client, target.method, target.url, target.headers, body, payload=payload)
            else:
                continue
            if resp and expected in resp.text and payload not in resp.text:
                findings.append(ActiveFinding(
                    title="Server-Side Template Injection (SSTI)",
                    severity="critical",
                    cwe="CWE-94",
                    attack_type="ssti",
                    evidence=f"Template expression {payload!r} evaluated to {expected!r} in response",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                ))
                break
    return findings


# ── Open redirect ──────────────────────────────────────────────────────────

_REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
]

async def check_open_redirect(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    findings = []
    for param in target.params:
        if not any(kw in param["name"].lower() for kw in
                   ("url", "redirect", "next", "return", "goto", "dest", "destination", "redir", "continue", "target")):
            continue
        for payload in _REDIRECT_PAYLOADS:
            if param["location"] == "query":
                url = _inject_query(target.url, param["name"], payload)
                resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
            else:
                continue
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                if "evil.example.com" in loc:
                    findings.append(ActiveFinding(
                        title="Open Redirect",
                        severity="medium",
                        cwe="CWE-601",
                        attack_type="open_redirect",
                        evidence=f"Server redirected to {loc!r} when payload {payload!r} injected into '{param['name']}'",
                        payload=payload,
                        parameter=param["name"],
                        url=target.url,
                        request_method=target.method,
                    ))
                    break
    return findings


# ── CRLF injection ─────────────────────────────────────────────────────────

_CRLF_PAYLOAD = "foo%0d%0aSet-Cookie:%20crlf=injected"
_CRLF_MATCH = "crlf=injected"

async def check_crlf(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    findings = []
    for param in target.params:
        if param["location"] != "query":
            continue
        url = _inject_query(target.url, param["name"], _CRLF_PAYLOAD)
        resp = await _send(client, "GET", url, target.headers, None, payload=_CRLF_PAYLOAD)
        if resp and _CRLF_MATCH in resp.headers.get("set-cookie", ""):
            findings.append(ActiveFinding(
                title="CRLF Injection / HTTP Response Splitting",
                severity="medium",
                cwe="CWE-113",
                attack_type="crlf",
                evidence=f"Injected Set-Cookie header appears in response for param '{param['name']}'",
                payload=_CRLF_PAYLOAD,
                parameter=param["name"],
                url=target.url,
                request_method=target.method,
            ))
    return findings


# ── HTTP method tampering ──────────────────────────────────────────────────

async def check_http_methods(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    findings = []
    for method in ("TRACE", "TRACK"):
        resp = await _send(client, method, target.url, target.headers, None, payload=method)
        if resp and resp.status_code == 200:
            if method in resp.text[:500].upper():
                findings.append(ActiveFinding(
                    title=f"Dangerous HTTP Method Enabled: {method}",
                    severity="low",
                    cwe="CWE-16",
                    attack_type="method_tamper",
                    evidence=f"{method} method accepted and echoed in response (status 200)",
                    payload=method,
                    parameter="",
                    url=target.url,
                    request_method=method,
                ))
    return findings


# ── XXE detection ──────────────────────────────────────────────────────────

_XXE_PAYLOAD = (
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
    '<root>&xxe;</root>'
)

async def check_xxe(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    ct = target.headers.get("content-type", "")
    if "xml" not in ct.lower():
        return []
    headers = dict(target.headers)
    headers["content-type"] = "application/xml"
    resp = await _send(client, target.method, target.url, headers, _XXE_PAYLOAD, payload="XXE")
    if resp and re.search(r"\b[a-zA-Z0-9_-]{1,64}\b", resp.text[:200]):
        if resp.status_code not in (400, 415, 422):
            return [ActiveFinding(
                title="Potential XML External Entity (XXE) Injection",
                severity="high",
                cwe="CWE-611",
                attack_type="xxe",
                evidence=f"XML with XXE entity accepted (status {resp.status_code}); verify file read manually",
                payload=_XXE_PAYLOAD[:80] + "...",
                parameter="body",
                url=target.url,
                request_method=target.method,
            )]
    return []


# ── IDOR ──────────────────────────────────────────────────────────────────────

_IDOR_ID_RE = re.compile(
    r'(?:^|_)(?:id|uuid|guid|node_?id|object_?id|resource_?id|user_?id|'
    r'account_?id|profile_?id|post_?id|item_?id|record_?id|entity_?id)(?:$|_)',
    re.IGNORECASE,
)
_NUMERIC_RE = re.compile(r'^\d{1,18}$')
_UUID_RE     = re.compile(
    r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$',
    re.IGNORECASE,
)
_PATH_ID_RE  = re.compile(r'/(\d{1,18}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)', re.IGNORECASE)


def _idor_neighbour(value: str) -> Optional[str]:
    if _NUMERIC_RE.match(value):
        n = int(value)
        return str(n + 1) if n > 0 else str(n + 2)
    if _UUID_RE.match(value):
        normalized = value.lower().replace("-", "")
        try:
            n = int(normalized, 16)
            h = f"{n + 1:032x}"
            return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
        except Exception:
            return None
    return None


def _idor_inject_path(url: str, original_id: str, probe_id: str) -> str:
    return re.sub(
        r'(/)' + re.escape(original_id) + r'((/)|$)',
        lambda m: m.group(1) + probe_id + m.group(2),
        url,
        count=1,
    )


def _idor_confirmed(baseline_status: int, baseline_text: str,
                    probe_status: int, probe_text: str) -> bool:
    # Auth/forbidden on probe → access correctly denied
    if probe_status in (401, 403):
        return False
    # Server error on probe → not an IDOR signal
    if probe_status >= 500:
        return False
    # Probe returned an error response
    if probe_status == 404:
        return False
    # Response must be non-trivially different from baseline
    if not probe_text or len(probe_text) < 20:
        return False
    # Try JSON comparison first
    try:
        import json as _json
        b = _json.loads(baseline_text)
        p = _json.loads(probe_text)
        # GraphQL-style: errors field means access denied
        if isinstance(p, dict) and p.get("errors"):
            return False
        # Null/empty data → not found or denied
        if isinstance(p, dict) and p.get("data") is None and "errors" not in p:
            pass  # fall through to text comparison
        if _json.dumps(b, sort_keys=True) == _json.dumps(p, sort_keys=True):
            return False  # identical data → same object
        return True
    except Exception as exc:
        logger.debug("failed to compare responses as JSON; falling back to text comparison", error=str(exc))
    # Fallback: text length changed significantly and content differs
    if probe_text.strip() == baseline_text.strip():
        return False
    size_ratio = len(probe_text) / max(len(baseline_text), 1)
    return 0.3 < size_ratio < 3.0  # similar size → real object, not error page


async def check_idor(target: CheckTarget, client: httpx.AsyncClient) -> List[ActiveFinding]:
    """
    Deterministic IDOR scanner — probes neighbour IDs across three injection points:
      1. Query string parameters (GET/POST)
      2. POST/PUT/PATCH JSON body fields
      3. URL path segments

    Confirmation requires: non-401/403/404/5xx response, non-empty body, and
    content that differs from the baseline (identical data → same object, not IDOR).
    JSON responses with GraphQL-style errors are treated as access denied.
    """
    findings: List[ActiveFinding] = []

    # ── Baseline ──────────────────────────────────────────────────────────────
    baseline_resp = await _send(client, target.method, target.url, target.headers, target.body)
    if baseline_resp is None:
        return []
    baseline_status = baseline_resp.status_code
    baseline_text   = baseline_resp.text

    # ── 1. Query and body parameters ──────────────────────────────────────────
    for param in target.params:
        name  = param["name"]
        value = param["value"]
        if not _IDOR_ID_RE.search(name):
            continue
        probe_id = _idor_neighbour(value)
        if not probe_id:
            continue

        if param["location"] == "query":
            probe_url  = _inject_query(target.url, name, probe_id)
            probe_resp = await _send(client, target.method, probe_url, target.headers, target.body)
        elif param["location"] in ("body", "body_graphql"):
            probe_body = _inject_body(
                target.body or "", name, probe_id,
                target.headers.get("content-type", ""),
                location=param["location"],
            )
            probe_resp = await _send(client, target.method, target.url, target.headers, probe_body)
        else:
            continue

        if probe_resp is None:
            continue
        if _idor_confirmed(baseline_status, baseline_text, probe_resp.status_code, probe_resp.text):
            findings.append(ActiveFinding(
                title="Insecure Direct Object Reference (IDOR)",
                severity="high",
                cwe="CWE-639",
                attack_type="idor",
                evidence=(
                    f"Parameter '{name}' changed from {value!r} to {probe_id!r}: "
                    f"server returned {probe_resp.status_code} with different non-empty data "
                    f"(baseline {baseline_status}, {len(baseline_text)} chars → "
                    f"probe {len(probe_resp.text)} chars)"
                ),
                payload=f"{name}={probe_id}",
                parameter=name,
                url=target.url,
                request_method=target.method,
            ))

    # ── 2. Path segment IDs ───────────────────────────────────────────────────
    path_matches = list(_PATH_ID_RE.finditer(urlparse(target.url).path))
    for match in path_matches:
        original_id = match.group(1)
        probe_id    = _idor_neighbour(original_id)
        if not probe_id:
            continue
        probe_url  = _idor_inject_path(target.url, original_id, probe_id)
        probe_resp = await _send(client, target.method, probe_url, target.headers, target.body)
        if probe_resp is None:
            continue
        if _idor_confirmed(baseline_status, baseline_text, probe_resp.status_code, probe_resp.text):
            findings.append(ActiveFinding(
                title="Insecure Direct Object Reference (IDOR) via URL Path",
                severity="high",
                cwe="CWE-639",
                attack_type="idor",
                evidence=(
                    f"Path ID {original_id!r} changed to {probe_id!r}: "
                    f"server returned {probe_resp.status_code} with different non-empty data "
                    f"(baseline {baseline_status}, {len(baseline_text)} chars → "
                    f"probe {len(probe_resp.text)} chars)"
                ),
                payload=probe_url,
                parameter=f"path:{original_id}",
                url=target.url,
                request_method=target.method,
            ))

    return findings


# ── taint marker seeding ─────────────────────────────────────────────────────

async def _inject_and_send(
    target: CheckTarget,
    client: httpx.AsyncClient,
    param: dict,
    value: str,
) -> "Optional[httpx.Response]":
    """
    Inject `value` into a single parameter (dispatching on its location) and send
    the request. Central dispatch shared by taint seeding; mirrors the per-location
    handling agents perform when probing.
    """
    location = param.get("location", "query")
    if location == "query":
        url = _inject_query(target.url, param["name"], value)
        return await _send(client, target.method, url, target.headers, target.body)
    if location in ("body", "body_graphql"):
        body = _inject_body(
            target.body or "", param["name"], value,
            target.headers.get("content-type", ""),
            location=location,
        )
        return await _send(client, target.method, target.url, target.headers, body)
    if location.startswith("multipart_"):
        raw = _inject_multipart(target.raw_body or b"", param["name"], value)
        return await _send(client, target.method, target.url, target.headers, raw)
    if location == "header":
        headers = _inject_header(target.headers, param["name"], value)
        return await _send(client, target.method, target.url, headers, target.body)
    if location == "cookie":
        headers = _inject_cookie(target.headers, param["name"], value)
        return await _send(client, target.method, target.url, headers, target.body)
    return None


async def seed_taint_markers(
    target: CheckTarget,
    client: httpx.AsyncClient,
    taint_store: Optional[object],
) -> int:
    """
    Inject one unique benign marker per entry point of this endpoint.

    Each parameter (query, body, header, cookie, multipart) gets its own marker so
    that when a marker later surfaces in some other response the correlator knows
    exactly which input point flowed to that output point. The marker is plain
    alphanumeric — no attack payload — so it maximises persistence (a WAF has no
    reason to block it) and is safe to store. The passive taint correlator picks up
    any cross-endpoint surfacing on subsequent traffic.

    Returns the number of markers successfully sent.
    """
    if taint_store is None or not target.params:
        return 0

    seeded = 0
    for param in target.params:
        location = param.get("location", "query")
        token = taint_store.mint(target.url, param["name"], location, target.method)
        try:
            response = await _inject_and_send(target, client, param, token)
        except Exception as exc:
            logger.debug(
                "Taint seed send failed",
                url=target.url, param=param.get("name"), error=str(exc),
            )
            continue
        if response is not None:
            seeded += 1
    if seeded:
        logger.info("Taint markers seeded", url=target.url, count=seeded)
    return seeded


# ── orchestrator ────────────────────────────────────────────────────────────

async def run_active_checks(
    target: CheckTarget,
    proxy_url: Optional[str] = None,
    timeout: float = 15.0,
    model_id: Optional[str] = None,
    confidence_threshold: float = 0.5,
    session_intelligence: Optional[object] = None,
    budget_seconds: Optional[float] = None,
    probe_diff: bool = False,
    taint_store: Optional[object] = None,
):
    """
    Run all active checks against a single endpoint via the Coordinator.

    Returns a list of AgentFinding objects (from dast.ai.agent_base).
    The Coordinator handles planning, parallel execution, and LLM validation.
    Falls back to running all agents when the LLM planner is unavailable.
    """
    import dast.agents  # noqa: F401 — triggers all Coordinator.register() calls
    from dast.scanners.collaborator import CollaboratorService
    from dast.ai.coordinator import Coordinator

    # Skip the entire pipeline (canary probes, LLM planner, agents) if this host
    # was already confirmed unreachable — no point spending a scan slot or LLM
    # call on a dead host.
    hostname = urlparse(target.url).hostname or target.url
    if is_host_dead(hostname):
        logger.info("Skipping scan — host previously unreachable", host=hostname, url=target.url)
        return []

    async with _client(proxy_url, timeout) as client:
        # Seed unique taint markers into every entry point before attacking, so
        # cross-endpoint data flows (stored/second-order) can be correlated as the
        # markers surface on later traffic. Best-effort — never block the scan.
        if taint_store is not None:
            try:
                await seed_taint_markers(target, client, taint_store)
            except Exception as exc:
                logger.warning("Taint seeding failed", url=target.url, error=str(exc))
        async with CollaboratorService() as collaborator:
            return await Coordinator.run(
                target, client, collaborator,
                model_id=model_id,
                confidence_threshold=confidence_threshold,
                session_intelligence=session_intelligence,
                budget_seconds=budget_seconds,
                probe_diff=probe_diff,
            )

"""
Session Intelligence — accumulates pentest observations per host and feeds
them back into the Coordinator planner on every subsequent scan.

Three sources feed this continuously:
  1. Passive traffic ingestion (session_store.complete_entry)
     Auth patterns, rate-limit signals, WAF 403 patterns, GraphQL endpoints,
     tech stack signals — extracted deterministically from every proxied entry,
     no LLM required.

  2. AppContextWorker write-back (app_context._apply_result)
     After each LLM synthesis cycle the worker writes pentest-relevant notes
     into HostIntel: endpoint surface, interesting params, privilege levels,
     auth model, inferred tech.  This enriches the coordinator prompt even
     before the first scan fires.

  3. Coordinator scan write-backs (coordinator._scan() and agents)
     Confirmed vulns, effective/ineffective attack types, structural errors,
     WAF payload-level block signals — written after every probe.

The coordinator reads to_planner_hint() and to_mutator_hint() before every
scan.  No threshold logic lives here — the caller decides when to read.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ── WAF fingerprints ──────────────────────────────────────────────────────
# Matched against response body (lowercase) to identify WAF vendor from a 403.
_WAF_SIGNATURES: List[Tuple[str, str]] = [
    ("cloudflare", "cloudflare"),
    ("cloudflare", "cf-ray"),
    ("aws waf", "aws-waf"),
    ("aws waf", "x-amzn-requestid"),
    ("akamai", "akamai ghost"),
    ("akamai", "akamai-cache"),
    ("imperva incapsula", "incapsula"),
    ("imperva incapsula", "_incap_ses"),
    ("f5 big-ip asm", "the requested url was rejected"),
    ("barracuda", "barracuda networks"),
    ("sucuri", "sucuri website firewall"),
    ("modsecurity", "mod_security"),
    ("modsecurity", "naxsi"),
    ("azure front door", "x-azure-ref"),
    ("fastly", "x-served-by"),
]


def _detect_waf(status: int, response_headers: Dict[str, str], body_prefix: str) -> Optional[str]:
    """
    Return WAF vendor string if a WAF is detected, else None.

    Fingerprints on a classic block status (403/406/429/503) OR on a recognised
    block-page signature in the body — the latter catches WAFs that answer 200
    with a block/challenge page, which a status-only check would miss.
    """
    from dast.agents.block_detector import detect_block

    if status not in (403, 406, 429, 503) and not detect_block(status, body_prefix).is_block:
        return None
    combined = body_prefix.lower() + " " + " ".join(
        f"{k}:{v}" for k, v in response_headers.items()
    ).lower()
    for vendor, signature in _WAF_SIGNATURES:
        if signature in combined:
            return vendor
    return None


# ── HostIntel ─────────────────────────────────────────────────────────────

@dataclass
class HostIntel:
    """Accumulated pentest intelligence for a single host."""

    host: str

    # ── From passive traffic ingestion ────────────────────────────────────

    # Auth header names seen on real user requests to this host
    auth_headers_seen: Set[str] = field(default_factory=set)

    # Cookie names seen — helps agents know what session tokens look like
    session_cookie_names: Set[str] = field(default_factory=set)

    # True if at least one session cookie was observed WITHOUT SameSite=Strict/Lax.
    # A cookie with SameSite=None (or no attribute) can be sent cross-origin by browsers,
    # which is required for CSWSH/CSRF to be exploitable.
    cookies_exploitable_cross_origin: bool = False

    # True if any response sent 429 or Retry-After
    rate_limit_observed: bool = False

    # WAF vendor if detected (from 403 response fingerprint)
    waf_vendor: Optional[str] = None

    # Response status code distribution — {status: count}
    status_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    # Endpoints observed: {method_path: count}  e.g. {"GET /api/users": 5}
    observed_endpoints: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Content types seen in responses — informs which agents are relevant
    response_content_types: Set[str] = field(default_factory=set)

    # GraphQL endpoints confirmed on this host
    graphql_endpoints: Set[str] = field(default_factory=set)

    # ── From AppContextWorker LLM synthesis ───────────────────────────────

    # Plain-language description of what the app does and its auth model
    # Written by AppContextWorker after LLM synthesis.
    app_summary: str = ""

    # Pentest notes from LLM synthesis: high-signal observations that don't fit
    # structured fields — e.g. "price param is client-controlled", "no CSRF on
    # state-changing endpoints", "UUIDs in path look sequential"
    pentest_notes: List[str] = field(default_factory=list)

    # ── From coordinator scan write-backs ─────────────────────────────────

    # Confirmed vulnerable params: {(path, param_name): [attack_type, ...]}
    confirmed_vulns: Dict[Tuple[str, str], List[str]] = field(
        default_factory=lambda: defaultdict(list)
    )

    # Attack types that produced at least one confirmed finding on this host
    effective_attack_types: Set[str] = field(default_factory=set)

    # Attack types that consistently produced no signal
    ineffective_attack_types: Set[str] = field(default_factory=set)

    # Structural errors per (path, operation) — coordinator skips known-broken paths
    structural_errors: Dict[Tuple[str, str], List[str]] = field(
        default_factory=lambda: defaultdict(list)
    )

    # WAF payload-level block signals: (payload_prefix, block_signal, attack_type)
    waf_observations: List[Tuple[str, str, str]] = field(default_factory=list)

    # Payloads that BYPASSED a block on this host: (payload, attack_type).
    # A bypass proven on one endpoint is a strong hint for the next endpoint of
    # the same host — the mutator is told to try the same technique first.
    waf_bypasses: List[Tuple[str, str]] = field(default_factory=list)

    # ── Blazor-specific (from BlazorDetectorPlugin) ────────────────────────

    blazor_circuits: List[dict] = field(default_factory=list)

    # ── Bookkeeping ───────────────────────────────────────────────────────
    ts: float = field(default_factory=time.time)

    # ── Passive ingestion methods ─────────────────────────────────────────

    def observe_entry(
        self,
        method: str,
        path: str,
        request_headers: Dict[str, str],
        response_status: int,
        response_headers: Dict[str, str],
        response_body_prefix: str,
        content_type: str,
        source: str,
    ) -> None:
        """
        Called for every proxied entry that is in scope and not from an agent.
        Extracts deterministic signals — no LLM.
        """
        # Auth headers present on real user requests
        _AUTH_NAMES = {
            "authorization", "cookie", "x-csrf-token", "x-xsrf-token",
            "x-auth-token", "x-api-key", "x-access-token",
        }
        for k in request_headers:
            if k.lower() in _AUTH_NAMES:
                self.auth_headers_seen.add(k.lower())

        # Session cookie names (not values)
        cookie_hdr = request_headers.get("cookie", "")
        if cookie_hdr:
            for part in cookie_hdr.split(";"):
                name = part.split("=")[0].strip()
                if name and len(name) <= 64:
                    self.session_cookie_names.add(name)

        # Rate limiting
        if response_status == 429 or "retry-after" in response_headers:
            self.rate_limit_observed = True

        # WAF detection from 403/406/503 responses
        if not self.waf_vendor:
            vendor = _detect_waf(response_status, response_headers, response_body_prefix)
            if vendor:
                self.waf_vendor = vendor

        # Track whether any session cookie is exploitable cross-origin.
        # SameSite=Strict or SameSite=Lax blocks cross-origin cookie sending;
        # SameSite=None or absent means browsers WILL send it cross-origin.
        if not self.cookies_exploitable_cross_origin:
            for header_name, header_val in (response_headers or {}).items():
                if header_name.lower() != "set-cookie":
                    continue
                values = header_val if isinstance(header_val, list) else [header_val]
                for cookie_str in values:
                    import re as _re
                    name_match = _re.match(r'([^=]+)=', cookie_str)
                    if not name_match:
                        continue
                    cookie_name = name_match.group(1).strip().lower()
                    if not _re.search(r'sess|auth|token|login|id', cookie_name, _re.IGNORECASE):
                        continue
                    has_strict_lax = bool(_re.search(
                        r'samesite\s*=\s*(strict|lax)', cookie_str, _re.IGNORECASE
                    ))
                    if not has_strict_lax:
                        self.cookies_exploitable_cross_origin = True
                        break

        # Status distribution
        self.status_counts[response_status] += 1

        # Endpoint inventory — skip high-cardinality dynamic segments
        if source not in ("agent", "scanner"):
            ep_key = f"{method} {path}"
            self.observed_endpoints[ep_key] = self.observed_endpoints.get(ep_key, 0) + 1
            # Cap to avoid unbounded growth on highly dynamic apps
            if len(self.observed_endpoints) > 500:
                # Drop least-seen endpoints
                sorted_eps = sorted(self.observed_endpoints.items(), key=lambda x: x[1])
                for ep, _ in sorted_eps[:50]:
                    del self.observed_endpoints[ep]

        # Content types seen
        ct = content_type.split(";")[0].strip().lower()
        if ct:
            self.response_content_types.add(ct)

        self.ts = time.time()

    def record_app_summary(self, summary: str) -> None:
        """Written by AppContextWorker after LLM synthesis."""
        if summary:
            self.app_summary = summary[:500]
            self.ts = time.time()

    def add_pentest_note(self, note: str) -> None:
        """Add an LLM-derived pentest note, deduplicating by content prefix."""
        note = note[:300]
        prefix = note[:60].lower()
        if any(n[:60].lower() == prefix for n in self.pentest_notes):
            return
        self.pentest_notes.append(note)
        # Keep most recent 30 notes — older ones are still in AppProfile
        if len(self.pentest_notes) > 30:
            self.pentest_notes = self.pentest_notes[-30:]
        self.ts = time.time()

    # ── Scan write-back methods ───────────────────────────────────────────

    def record_confirmed_vuln(self, path: str, param: str, attack_type: str) -> None:
        key = (path, param)
        if attack_type not in self.confirmed_vulns[key]:
            self.confirmed_vulns[key].append(attack_type)
        self.effective_attack_types.add(attack_type)
        self.ineffective_attack_types.discard(attack_type)
        self.ts = time.time()

    def record_scan_result(
        self,
        attack_type: str,
        found: bool,
        path: str,
        operation: str = "",
        structural_error: Optional[str] = None,
        waf_signal: Optional[Tuple[str, str]] = None,
    ) -> None:
        if structural_error:
            self.structural_errors[(path, operation)].append(structural_error)
        if waf_signal:
            payload_prefix, block_signal = waf_signal
            self.waf_observations.append((payload_prefix[:40], block_signal[:80], attack_type))
            if len(self.waf_observations) > 100:
                self.waf_observations = self.waf_observations[-100:]
        if not found and attack_type not in self.effective_attack_types:
            self.ineffective_attack_types.add(attack_type)
        self.ts = time.time()

    def record_bypass(self, attack_type: str, payload: str) -> None:
        """
        Record a payload that got through a block on this host. Reused by the
        mutator on later endpoints of the same host so a working bypass is tried
        first instead of being rediscovered from scratch.
        """
        if not payload:
            return
        entry = (payload[:120], attack_type)
        if entry not in self.waf_bypasses:
            self.waf_bypasses.append(entry)
            if len(self.waf_bypasses) > 50:
                self.waf_bypasses = self.waf_bypasses[-50:]
        self.ts = time.time()

    def record_auth_headers(self, headers: Dict[str, str]) -> None:
        _AUTH_NAMES = {"cookie", "authorization", "x-csrf-token", "x-xsrf-token", "x-auth-token"}
        for k in headers:
            if k.lower() in _AUTH_NAMES:
                self.auth_headers_seen.add(k.lower())

    def record_rate_limit(self) -> None:
        self.rate_limit_observed = True

    def has_structural_error_for(self, path: str, operation: str = "") -> Optional[str]:
        errors = self.structural_errors.get((path, operation))
        if errors:
            return errors[-1]
        if operation:
            errors = self.structural_errors.get((path, ""))
            return errors[-1] if errors else None
        return None

    # ── Blazor ───────────────────────────────────────────────────────────

    def record_blazor_observation(
        self,
        handler_id: int,
        event_name: str,
        component: str = "",
        input_fields: Optional[List[str]] = None,
        connection_id: str = "",
    ) -> None:
        if any(c.get("handler_id") == handler_id for c in self.blazor_circuits):
            return
        self.blazor_circuits.append({
            "handler_id": handler_id,
            "event_name": event_name,
            "component": component,
            "input_fields": input_fields or [],
            "connection_id": connection_id,
        })
        if len(self.blazor_circuits) > 200:
            self.blazor_circuits = self.blazor_circuits[-200:]
        self.ts = time.time()

    def get_blazor_handler_ids(self) -> List[int]:
        return [c["handler_id"] for c in reversed(self.blazor_circuits)]

    def get_blazor_input_fields(self) -> List[str]:
        seen: Set[str] = set()
        result: List[str] = []
        for c in reversed(self.blazor_circuits):
            for f in c.get("input_fields", []):
                if f not in seen:
                    seen.add(f)
                    result.append(f)
        return result

    # ── Coordinator-facing read methods ──────────────────────────────────

    def to_planner_hint(self, path: str, params: List[dict]) -> str:
        """
        Produce a concise natural-language hint for the LLM planner.
        Covers everything accumulated across all three ingestion sources.
        """
        lines: List[str] = []

        # App-level context from LLM synthesis
        if self.app_summary:
            lines.append(f"App context: {self.app_summary}")

        # Pentest notes from LLM synthesis
        for note in self.pentest_notes[-5:]:
            lines.append(f"Note: {note}")

        # Previously confirmed vulns on this host
        if self.confirmed_vulns:
            vuln_summary = "; ".join(
                f"{p} param={param} → {', '.join(types)}"
                for (p, param), types in list(self.confirmed_vulns.items())[:5]
            )
            lines.append(f"Previously confirmed vulns: {vuln_summary}")

        # Effective and ineffective attack types
        if self.effective_attack_types:
            lines.append(
                f"Attack types that worked on this host: {', '.join(sorted(self.effective_attack_types))}"
            )
        if self.ineffective_attack_types:
            lines.append(
                f"Attack types with no signal so far: {', '.join(sorted(self.ineffective_attack_types))}"
            )

        # Auth model observed
        if self.auth_headers_seen:
            lines.append(f"Auth mechanism: {', '.join(sorted(self.auth_headers_seen))}")
        if self.session_cookie_names:
            visible = sorted(self.session_cookie_names)[:8]
            lines.append(f"Session cookies observed: {', '.join(visible)}")

        # WAF
        if self.waf_vendor:
            lines.append(f"WAF detected: {self.waf_vendor} — evasion techniques may be needed")
        if self.waf_observations:
            recent = self.waf_observations[-3:]
            waf_str = "; ".join(f"{obs[2]}: {obs[1]}" for obs in recent)
            lines.append(f"WAF payload blocks observed: {waf_str}")

        # Rate limiting
        if self.rate_limit_observed:
            lines.append("Rate limiting observed — use conservative probe delay")

        # Structural errors for this specific path
        path_errors = {
            op: errs[-1]
            for (p, op), errs in self.structural_errors.items()
            if p == path and errs
        }
        for op, err in list(path_errors.items())[:3]:
            label = f"{path} [{op}]" if op else path
            lines.append(f"Structural error seen on {label}: {err}")

        # GraphQL
        if self.graphql_endpoints:
            lines.append(
                f"GraphQL endpoints on this host: {', '.join(sorted(self.graphql_endpoints))}"
            )

        # Content types — informs which attack surfaces exist
        interesting_ct = self.response_content_types & {
            "application/xml", "text/xml", "multipart/form-data",
            "application/x-www-form-urlencoded",
        }
        if interesting_ct:
            lines.append(f"Non-JSON content types observed: {', '.join(sorted(interesting_ct))}")

        return "\n".join(lines)

    def to_mutator_hint(self, attack_type: str) -> str:
        """
        Concise hint for the mutator: the WAF in use, what has been blocked, and
        which payloads already BYPASSED a block on this host. The bypass list is
        the payoff of Gap 2 — a technique proven on one endpoint is offered to
        the mutator first on the next endpoint of the same host.
        """
        lines: List[str] = []
        if self.waf_vendor:
            lines.append(f"WAF in use: {self.waf_vendor}")

        bypasses = [p for p, at in self.waf_bypasses if at == attack_type]
        if bypasses:
            lines.append("Payloads that already bypassed the block on this host (try these techniques first):")
            for payload in bypasses[-5:]:
                lines.append(f"  {payload!r}")

        relevant = [(p, sig) for p, sig, at in self.waf_observations if at == attack_type]
        if relevant:
            lines.append("Previously blocked payloads on this host (do not repeat verbatim):")
            for payload_prefix, signal in relevant[-5:]:
                lines.append(f"  starting with {payload_prefix!r} → {signal}")
        return "\n".join(lines)


# ── SessionIntelligence ───────────────────────────────────────────────────

class SessionIntelligence:
    """
    Per-session store of accumulated pentest intelligence, keyed by host.
    Thread-safe — the proxy runs in a multi-threaded context.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hosts: Dict[str, HostIntel] = {}

    def get(self, host: str) -> HostIntel:
        with self._lock:
            if host not in self._hosts:
                self._hosts[host] = HostIntel(host=host)
            return self._hosts[host]

    # ── Passive ingestion (called from session_store._bg_analyse) ─────────

    def observe_entry(
        self,
        host: str,
        method: str,
        path: str,
        request_headers: Dict[str, str],
        response_status: int,
        response_headers: Dict[str, str],
        response_body_prefix: str,
        content_type: str,
        source: str,
    ) -> None:
        """
        Called for every completed proxied entry.
        Extracts deterministic signals without LLM.
        """
        intel = self.get(host)
        with self._lock:
            intel.observe_entry(
                method=method,
                path=path,
                request_headers=request_headers,
                response_status=response_status,
                response_headers=response_headers,
                response_body_prefix=response_body_prefix,
                content_type=content_type,
                source=source,
            )

    # ── AppContextWorker write-back ───────────────────────────────────────

    def record_app_context(
        self,
        host: str,
        app_summary: str,
        pentest_notes: List[str],
    ) -> None:
        """Called by AppContextWorker after each LLM synthesis cycle."""
        intel = self.get(host)
        with self._lock:
            if app_summary:
                intel.record_app_summary(app_summary)
            for note in pentest_notes:
                intel.add_pentest_note(note)

    # ── Coordinator scan write-backs ──────────────────────────────────────

    def record_scan_complete(
        self,
        host: str,
        path: str,
        attack_type: str,
        found: bool,
        operation: str = "",
        confirmed_param: Optional[str] = None,
        structural_error: Optional[str] = None,
        waf_signal: Optional[Tuple[str, str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        rate_limited: bool = False,
        bypass_payload: Optional[str] = None,
    ) -> None:
        intel = self.get(host)
        with self._lock:
            intel.record_scan_result(
                attack_type, found, path, operation, structural_error, waf_signal
            )
            if found and confirmed_param:
                intel.record_confirmed_vuln(path, confirmed_param, attack_type)
            if auth_headers:
                intel.record_auth_headers(auth_headers)
            if rate_limited:
                intel.record_rate_limit()
            if bypass_payload:
                intel.record_bypass(attack_type, bypass_payload)

    def all_hosts(self) -> List[str]:
        with self._lock:
            return list(self._hosts.keys())

    def summary(self) -> dict:
        """For dashboard display."""
        with self._lock:
            return {
                host: {
                    "confirmed_vulns": len(intel.confirmed_vulns),
                    "effective_types": list(intel.effective_attack_types),
                    "structural_errors": sum(
                        len(v) for v in intel.structural_errors.values()
                    ),
                    "waf_vendor": intel.waf_vendor,
                    "waf_observations": len(intel.waf_observations),
                    "rate_limit": intel.rate_limit_observed,
                    "endpoints_observed": len(intel.observed_endpoints),
                    "pentest_notes": len(intel.pentest_notes),
                    "app_summary": bool(intel.app_summary),
                }
                for host, intel in self._hosts.items()
            }

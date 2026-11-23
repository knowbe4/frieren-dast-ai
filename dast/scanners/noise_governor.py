"""Noise governor — proactive per-host pacing for scanner-originated egress.

Round 3-G, borrowed from ARTEX 0.7.0's egress governor (BaaRai/ARTEX,
``egress/egress.go``): the legacy controls in ``active_checks`` are REACTIVE —
the AIMD limiter and the host breaker back off only after a 429/503 or latency
inflation already happened, and the base probe delay is a flat 200 ms. The
governor is PROACTIVE: an operator-chosen profile bounds every probe to N
req/s per host with a token bucket, caps in-flight requests per host and
globally, pauses the WHOLE host after a 429/503, and can override the probe
User-Agent. ``off`` (the default) is a strict passthrough — one cheap
``active()`` check, zero timing or behavior change.

Scope (v1, agreed in the 3-G plan): scanner noise only — the
``active_checks._send`` chokepoint (every agent probe/canary/baseline), the
``sqli_probe_tools`` clients and the copilot ``send_request``. NOT paced: the
operator's own browsing through the MITM proxy, login flows (spa_api /
flow_replayer already pace and budget themselves), the SPA crawler (own settle
sleeps; a lenient bucket is a follow-up), and the race-condition agent's
controlled burst (the burst IS the experiment — it passes ``pace=False``).
Smuggling raw sockets bypass httpx entirely and are naturally out.

Deliberately left out of v1 (ARTEX parity is a follow-up): GET dedup/
coalescing and 429/503 retries — probe payloads are deliberately varied and
often repeated by design (sqli/cmdi zero-control vs scaled-delay time oracles),
so replaying or sharing responses would break the experiments.

Acquisition order matters and follows ARTEX (``egress.go:206-246``): host
slot FIRST, then the token-bucket wait + jitter, global slot LAST — a caller
queued behind its host must not hold a global slot while it waits. Waits are
fail-open: capped at ``_MAX_WAIT_S`` so pacing can stall a probe but never
deadlock a scan (scan budgets still apply on top).
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# A paced wait longer than this proceeds anyway: a host paused for a huge
# Retry-After must not pin a scan worker forever (scan budgets are the real cap).
_MAX_WAIT_S = 60.0


@dataclass(frozen=True)
class Profile:
    """One noise profile — the concrete numbers come from ARTEX
    ``egress/egress.go:53-57`` (quiet/balanced/aggressive)."""

    name: str
    rps: float                 # token-bucket refill per host (requests/second)
    burst: int                 # bucket size per host (immediate first requests)
    per_host: int              # in-flight cap per host
    max_global: int            # in-flight cap across all hosts
    jitter_s: float            # uniform [0, jitter_s] added per request
    base_delay_s: float        # host pause after a 429/503 without Retry-After
    max_delay_s: float         # cap for any host pause (Retry-After included)


PROFILES: Dict[str, Profile] = {
    "quiet": Profile("quiet", rps=2.0, burst=4, per_host=1, max_global=8,
                     jitter_s=0.25, base_delay_s=2.0, max_delay_s=60.0),
    "balanced": Profile("balanced", rps=5.0, burst=10, per_host=2, max_global=16,
                        jitter_s=0.04, base_delay_s=1.0, max_delay_s=30.0),
    "aggressive": Profile("aggressive", rps=20.0, burst=40, per_host=4, max_global=32,
                          jitter_s=0.005, base_delay_s=0.5, max_delay_s=10.0),
}

# Injectable clock/sleep/random so tests drive time deterministically
# (the house pattern: monkeypatch the module-level helpers, no freezegun).
_now = time.monotonic
_sleep = asyncio.sleep
_uniform = random.uniform


class _HostState:
    """Per-host bucket + slots + counters. Counter mutation never awaits, so
    plain attributes are safe on a single event loop."""

    __slots__ = ("slots", "tokens", "last", "not_before",
                 "sent", "inflight", "peak_inflight")

    def __init__(self, profile: Profile) -> None:
        self.slots = asyncio.Semaphore(max(1, profile.per_host))
        self.tokens = float(profile.burst)
        self.last = _now()
        self.not_before = 0.0
        self.sent = 0
        self.inflight = 0
        self.peak_inflight = 0


class _PaceToken:
    """Holds one host slot + one global slot until ``release()``. Idempotent."""

    __slots__ = ("_gov", "_st", "_released")

    def __init__(self, gov: "_Governor", st: _HostState) -> None:
        self._gov = gov
        self._st = st
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        st = self._st
        st.inflight = max(0, st.inflight - 1)
        self._gov._global.release()
        st.slots.release()


class _Governor:
    """One active profile's state. Replaced atomically by ``set_profile`` —
    tokens issued by an older governor release against it, so an in-flight
    request is never stranded by a runtime profile switch."""

    def __init__(self, profile: Profile) -> None:
        self.profile = profile
        self._hosts: Dict[str, _HostState] = {}
        self._hosts_lock = asyncio.Lock()  # only guards host-state creation
        self._global = asyncio.Semaphore(max(1, profile.max_global))

    async def _host_state(self, host: str) -> _HostState:
        async with self._hosts_lock:
            st = self._hosts.get(host)
            if st is None:
                st = _HostState(self.profile)
                self._hosts[host] = st
            return st

    def _reserve_wait(self, st: _HostState) -> float:
        """Consume one token and return how long the caller must wait before
        sending (bucket deficit, or a live 429/503 host pause). No awaits —
        safe without the lock on a single loop."""
        now = _now()
        st.tokens = min(float(self.profile.burst),
                        st.tokens + (now - st.last) * self.profile.rps)
        st.last = now
        st.tokens -= 1.0
        return max(-st.tokens / self.profile.rps, st.not_before - now, 0.0)

    async def acquire(self, host: str) -> _PaceToken:
        st = await self._host_state(host)
        await st.slots.acquire()  # host slot FIRST
        global_acquired = False
        try:
            wait = self._reserve_wait(st)
            if wait > 0:
                await _sleep(min(wait, _MAX_WAIT_S))
            jitter = _uniform(0, self.profile.jitter_s) if self.profile.jitter_s > 0 else 0.0
            if jitter > 0:
                await _sleep(jitter)
            await self._global.acquire()  # global slot LAST
            global_acquired = True
        except BaseException:
            if global_acquired:
                self._global.release()
            st.slots.release()
            raise
        st.sent += 1
        st.inflight += 1
        st.peak_inflight = max(st.peak_inflight, st.inflight)
        return _PaceToken(self, st)

    def note_rate_limited(self, host: str, retry_after_s: Optional[float] = None) -> None:
        """Pause the WHOLE host after a 429/503 (ARTEX ``notBefore``): every
        subsequent acquire waits out the pause, not just the request that was
        rejected. Retry-After is honoured up to the profile cap; beyond it (or
        absent) the profile's base/max delay applies."""
        st = self._hosts.get(host)
        if st is None:  # never paced yet — nothing to un-pause
            return
        delay = self.profile.base_delay_s
        if retry_after_s is not None and retry_after_s > 0:
            delay = retry_after_s
        delay = min(delay, self.profile.max_delay_s)
        st.not_before = max(st.not_before, _now() + delay)

    def snapshot(self) -> Dict[str, object]:
        """Counters for the dashboard. Hosts with no traffic (or everything
        already at zero) are omitted, sorted by host, like ARTEX's Snapshot."""
        now = _now()
        hosts: List[Dict[str, object]] = []
        for name in sorted(self._hosts):
            st = self._hosts[name]
            if st.sent == 0 and st.inflight == 0 and st.not_before <= now:
                continue
            hosts.append({
                "host": name,
                "sent": st.sent,
                "inflight": st.inflight,
                "peak_inflight": st.peak_inflight,
                "backoff_remaining_s": round(max(st.not_before - now, 0.0), 1),
            })
        return {"profile": self.profile.name, "hosts": hosts,
                "total_sent": sum(st.sent for st in self._hosts.values())}


# ── module surface: one current governor, swapped atomically ─────────────────

_current: "Optional[_Governor]" = None
_user_agent: str = ""


def set_profile(name: str) -> bool:
    """Switch the active profile (response_cache.set_enabled semantics: the
    switch resets counters and drops in-flight state). Unknown names fall back
    to ``off`` and return False, like ARTEX's ProfileByName."""
    global _current
    profile = PROFILES.get((name or "").strip().lower())
    if profile is None:
        _current = None
        return False
    _current = _Governor(profile)
    logger.info("Noise profile set", profile=profile.name, rps=profile.rps,
                per_host=profile.per_host, max_global=profile.max_global)
    return True


def set_user_agent(ua: str) -> None:
    """Set the probe User-Agent override (applied only while a profile is
    active, and only to requests that carry none)."""
    global _user_agent
    _user_agent = (ua or "").strip()


def active() -> bool:
    """True when a profile is pacing egress. This is the hot-path check in
    ``_send`` — with ``off`` it is the only cost."""
    return _current is not None


def profile_name() -> str:
    return _current.profile.name if _current else "off"


def user_agent() -> str:
    return _user_agent if _current is not None else ""


def apply_user_agent(headers: Dict[str, str]) -> None:
    """Stamp the configured UA on ``headers`` unless the caller already set
    one (case-insensitive), ARTEX semantics — a captured target header wins."""
    ua = user_agent()
    if ua and not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = ua


async def acquire(host: str) -> "Optional[_PaceToken]":
    """Acquire one paced slot for ``host`` (host-keyed by the caller's
    hostname). Returns None when the profile is off — callers must handle
    both and release the token in ``finally``."""
    gov = _current
    if gov is None:
        return None
    return await gov.acquire(host)


def note_rate_limited(host: str, retry_after_s: Optional[float] = None) -> None:
    if _current is not None:
        _current.note_rate_limited(host, retry_after_s)


def snapshot() -> Dict[str, object]:
    if _current is None:
        return {"profile": "off", "hosts": [], "total_sent": 0}
    return _current.snapshot()


def reset() -> None:
    """Back to off + no UA. Used by the dashboard profile switch to off and
    by the test-suite isolation fixture."""
    global _current, _user_agent
    _current = None
    _user_agent = ""

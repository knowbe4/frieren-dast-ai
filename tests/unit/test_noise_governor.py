"""Noise governor tests (dast/scanners/noise_governor.py).

Deterministic time: the module exposes ``_now``/``_sleep``/``_uniform`` for
injection (the house pattern — monkeypatched clock, no freezegun). A fake
clock advances only when the governor sleeps, so bucket refill, host pauses,
jitter and the fail-open wait cap are all exercised without real delays.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from dast.scanners import active_checks as ac
from dast.scanners import noise_governor as gov


class _FakeClock:
    """Monotonic clock that advances only when the governor sleeps."""

    def __init__(self) -> None:
        self.t = 1000.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.t

    async def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


@pytest.fixture(autouse=True)
def _isolate():
    gov.reset()
    yield
    gov.reset()


def _install_clock(monkeypatch) -> _FakeClock:
    clock = _FakeClock()
    monkeypatch.setattr(gov, "_now", clock.now)
    monkeypatch.setattr(gov, "_sleep", clock.sleep)
    monkeypatch.setattr(gov, "_uniform", lambda a, _b: a)  # no jitter
    return clock


async def _acquire_release(host: str = "app.example.com"):
    token = await gov.acquire(host)
    assert token is not None
    token.release()
    return token


# ── profile lifecycle ────────────────────────────────────────────────────────

def test_off_is_passthrough():
    assert gov.active() is False
    assert gov.profile_name() == "off"
    assert gov.snapshot() == {"profile": "off", "hosts": [], "total_sent": 0}


@pytest.mark.asyncio
async def test_off_acquire_returns_none():
    assert await gov.acquire("app.example.com") is None


def test_set_profile_unknown_falls_back_to_off():
    assert gov.set_profile("turbo") is False
    assert gov.active() is False
    assert gov.set_profile("quiet") is True
    assert gov.active() is True and gov.profile_name() == "quiet"


def test_profile_switch_drops_state_and_counters():
    gov.set_profile("quiet")
    gov._current._hosts["old.example.com"] = gov._HostState(gov.PROFILES["quiet"])
    gov._current._hosts["old.example.com"].sent = 7
    gov.set_profile("balanced")
    snap = gov.snapshot()
    assert snap["profile"] == "balanced"
    assert snap["total_sent"] == 0 and snap["hosts"] == []


# ── token bucket ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_burst_covers_bucket_then_deficit(monkeypatch):
    clock = _install_clock(monkeypatch)  # quiet: burst 4, rps 2
    gov.set_profile("quiet")
    for _ in range(4):
        await _acquire_release()
    assert clock.sleeps == []  # burst tokens: no waiting at all
    await _acquire_release()
    # 5th spend drives the bucket to -1 → wait = 1/2 rps = 0.5s
    assert clock.sleeps and abs(clock.sleeps[-1] - 0.5) < 1e-9


@pytest.mark.asyncio
async def test_bucket_refills_over_time(monkeypatch):
    clock = _install_clock(monkeypatch)
    gov.set_profile("quiet")
    for _ in range(4):
        await _acquire_release()
    clock.t += 2.0  # 2s × 2 rps = 4 tokens refilled (capped at burst)
    await _acquire_release()
    assert clock.sleeps == []


@pytest.mark.asyncio
async def test_wait_is_fail_open_capped(monkeypatch):
    clock = _install_clock(monkeypatch)
    gov.set_profile("quiet")
    await _acquire_release()
    st = gov._current._hosts["app.example.com"]
    st.tokens = -1000.0  # a deficit of 500s must not stall a scan for 500s
    await _acquire_release()
    assert clock.sleeps[-1] == gov._MAX_WAIT_S


# ── 429/503 host pause ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rate_limit_pauses_whole_host(monkeypatch):
    clock = _install_clock(monkeypatch)
    gov.set_profile("quiet")  # base delay 2s
    await _acquire_release()
    gov.note_rate_limited("app.example.com")
    snap = gov.snapshot()
    assert snap["hosts"][0]["backoff_remaining_s"] == pytest.approx(2.0, abs=0.1)
    await _acquire_release()
    assert clock.sleeps[-1] == pytest.approx(2.0, abs=0.1)


@pytest.mark.asyncio
async def test_retry_after_is_capped_by_profile(monkeypatch):
    clock = _install_clock(monkeypatch)
    gov.set_profile("quiet")  # max delay 60s
    await _acquire_release()
    gov.note_rate_limited("app.example.com", retry_after_s=3600.0)
    await _acquire_release()
    assert clock.sleeps[-1] == 60.0


@pytest.mark.asyncio
async def test_rate_limit_ignores_unpaced_host():
    gov.set_profile("quiet")
    gov.note_rate_limited("never-seen.example.com")  # no state yet — must not raise
    assert gov.snapshot()["hosts"] == []


# ── in-flight slots ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_per_host_slot_serializes(monkeypatch):
    _install_clock(monkeypatch)
    gov.set_profile("quiet")  # per_host 1
    token1 = await gov.acquire("app.example.com")
    pending = asyncio.ensure_future(gov.acquire("app.example.com"))
    for _ in range(5):
        await asyncio.sleep(0)  # let the second acquire run up to the slot
    assert not pending.done()  # parked on the host slot, not sent
    token1.release()
    token2 = await asyncio.wait_for(pending, timeout=1)
    token2.release()


@pytest.mark.asyncio
async def test_global_slot_is_reserved_last(monkeypatch):
    _install_clock(monkeypatch)
    gov.set_profile("quiet")  # max_global 8
    tokens = await asyncio.gather(*[gov.acquire(f"h{i}.example.com") for i in range(8)])
    assert all(t is not None for t in tokens)
    pending = asyncio.ensure_future(gov.acquire("h8.example.com"))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not pending.done()  # global cap reached
    tokens[0].release()
    token9 = await asyncio.wait_for(pending, timeout=1)
    token9.release()


@pytest.mark.asyncio
async def test_release_is_idempotent(monkeypatch):
    _install_clock(monkeypatch)
    gov.set_profile("quiet")
    token = await gov.acquire("app.example.com")
    token.release()
    token.release()  # must not over-release the semaphores
    snap = gov.snapshot()
    assert snap["hosts"][0]["inflight"] == 0
    assert snap["hosts"][0]["sent"] == 1


# ── snapshot ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_omits_untouched_hosts_and_reports_peaks(monkeypatch):
    _install_clock(monkeypatch)
    gov.set_profile("quiet")
    t1 = await gov.acquire("a.example.com")
    t2 = await gov.acquire("b.example.com")  # quiet allows only 1 per host
    t2.release()
    t1.release()
    snap = gov.snapshot()
    assert [h["host"] for h in snap["hosts"]] == ["a.example.com", "b.example.com"]
    assert snap["hosts"][0]["sent"] == 1 and snap["hosts"][0]["peak_inflight"] == 1
    assert snap["total_sent"] == 2


# ── user agent ───────────────────────────────────────────────────────────────

def test_user_agent_applies_only_when_profile_active():
    gov.set_user_agent("DAST-AI/1.0 (+noise-profile)")
    assert gov.user_agent() == ""  # off: nothing applies
    headers: dict = {}
    gov.apply_user_agent(headers)
    assert headers == {}
    gov.set_profile("quiet")
    assert gov.user_agent() == "DAST-AI/1.0 (+noise-profile)"
    headers = {}
    gov.apply_user_agent(headers)
    assert headers["User-Agent"] == "DAST-AI/1.0 (+noise-profile)"


def test_user_agent_never_overrides_a_captured_header():
    gov.set_user_agent("DAST-AI/1.0")
    gov.set_profile("quiet")
    upper = {"User-Agent": "target-captured"}
    gov.apply_user_agent(upper)
    assert upper["User-Agent"] == "target-captured"
    lower = {"user-agent": "target-captured-lower"}
    gov.apply_user_agent(lower)
    assert lower["user-agent"] == "target-captured-lower"


def test_user_agent_persists_across_profile_switch_but_not_reset():
    gov.set_user_agent("DAST-AI/1.0")
    gov.set_profile("balanced")
    gov.set_profile("off")
    assert gov.user_agent() == ""  # UA only applies under an active profile
    gov.set_profile("aggressive")
    assert gov.user_agent() == "DAST-AI/1.0"  # the setting survives switches
    gov.reset()
    gov.set_profile("quiet")
    assert gov.user_agent() == ""  # reset() clears it (test isolation)


# ── wiring: the real _send walk under an active profile ──────────────────────

@pytest.fixture(autouse=True)
def _clean_breaker():
    ac.reset_host_reachability()
    yield
    ac.reset_host_reachability()


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(5.0))


@respx.mock
async def test_send_paces_and_injects_ua(monkeypatch):
    _install_clock(monkeypatch)  # no real sleeps while paced
    gov.set_profile("quiet")
    gov.set_user_agent("DAST-AI/1.0 (+noise)")
    route = respx.get("https://paced.example.com/a").mock(return_value=httpx.Response(200))

    async with _client() as client:
        resp = await ac._send(client, "GET", "https://paced.example.com/a", {}, None,
                              source="agent")

    assert resp is not None and resp.status_code == 200
    sent = route.calls.last.request
    assert sent.headers["user-agent"] == "DAST-AI/1.0 (+noise)"
    assert sent.headers["x-dast-source"] == "agent"
    snap = gov.snapshot()
    assert snap["hosts"][0]["host"] == "paced.example.com"
    assert snap["hosts"][0]["sent"] == 1


@respx.mock
async def test_send_respects_a_captured_ua(monkeypatch):
    _install_clock(monkeypatch)
    gov.set_profile("quiet")
    gov.set_user_agent("DAST-AI/1.0")
    route = respx.get("https://paced.example.com/b").mock(return_value=httpx.Response(200))

    async with _client() as client:
        await ac._send(client, "GET", "https://paced.example.com/b",
                       {"User-Agent": "captured/9"}, None)

    assert route.calls.last.request.headers["user-agent"] == "captured/9"


@respx.mock
async def test_429_pauses_host_for_subsequent_probes(monkeypatch):
    clock = _install_clock(monkeypatch)
    gov.set_profile("quiet")  # base host pause 2s
    respx.get("https://paced.example.com/c").mock(return_value=httpx.Response(429))
    async with _client() as client:
        resp = await ac._send(client, "GET", "https://paced.example.com/c", {}, None)
        assert resp.status_code == 429
        st = gov._current._hosts["paced.example.com"]
        assert st.not_before > clock.t  # the whole host is paused, not just this probe

        respx.get("https://paced.example.com/d").mock(return_value=httpx.Response(200))
        resp2 = await ac._send(client, "GET", "https://paced.example.com/d", {}, None)
        assert resp2.status_code == 200  # still sent — pacing, not blocking
    assert any(abs(s - 2.0) < 0.1 for s in clock.sleeps)  # pause waited out first


@respx.mock
async def test_pace_false_skips_the_governor_entirely(monkeypatch):
    _install_clock(monkeypatch)
    gov.set_profile("quiet")
    respx.get("https://paced.example.com/e").mock(return_value=httpx.Response(200))

    async with _client() as client:
        resp = await ac._send(client, "GET", "https://paced.example.com/e", {}, None,
                              pace=False)

    assert resp.status_code == 200  # the race-agent path: un-paced, un-counted
    assert gov.snapshot()["hosts"] == []


# ── dashboard route (GET /api/noise-status) ──────────────────────────────────

def test_noise_status_route():
    from types import SimpleNamespace

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from dast.proxy.api.status_routes import make_router

    ctx = SimpleNamespace(scan_queue_state=None, mcp_last_heartbeat=[0.0])
    app = FastAPI()
    app.include_router(make_router(ctx))
    client = TestClient(app)

    body = client.get("/api/noise-status").json()
    assert body["profile"] == "off"
    assert body["hosts"] == []
    assert "rate_limit_multipliers" in body

    gov.set_profile("quiet")
    gov.set_user_agent("DAST-AI/1.0")
    body = client.get("/api/noise-status").json()
    assert body["profile"] == "quiet"
    assert body["user_agent_set"] is True

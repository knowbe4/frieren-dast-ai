"""Unit tests for the process-wide login coordinator (dast/session/login_coordinator.py).

Before it, ~10 components logged in with only private per-instance guards — the
concrete bomb: run_validation_batch(max_concurrency=3) fired concurrent
adaptive_login calls with identical credentials against the same host.
"""

from __future__ import annotations

import asyncio

import pytest

from dast.session import login_coordinator as lc


@pytest.fixture(autouse=True)
def _fresh_coordinator():
    lc.reset_login_coordinator()
    yield
    lc.reset_login_coordinator()


def test_singleton_identity():
    assert lc.get_login_coordinator() is lc.get_login_coordinator()


def test_site_key_is_consistent_across_url_and_host_forms():
    coord = lc.get_login_coordinator()
    # URL and bare host of the same site resolve to the SAME key (one lock per product).
    assert (coord.site_key_for("https://app.example.com/login")
            == coord.site_key_for("app.example.com"))
    assert coord.site_key_for("app.example.com") != coord.site_key_for("other.example.com")
    # Garbage never raises.
    assert isinstance(coord.site_key_for(""), str)


def test_same_host_shares_one_lock_different_hosts_do_not():
    coord = lc.get_login_coordinator()
    assert coord.lock_for("app.example.com") is coord.lock_for("app.example.com")
    assert coord.lock_for("app.example.com") is not coord.lock_for("other.example.com")


@pytest.mark.asyncio
async def test_concurrent_logins_to_same_host_serialize():
    """Two concurrent login flows for the same host never overlap (max 1 in-lock)."""
    coord = lc.get_login_coordinator()
    active = 0
    max_active = 0

    async def fake_login(host):
        nonlocal active, max_active
        async with coord.lock_for(coord.site_key_for(host)):
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.02)
            active -= 1

    await asyncio.gather(
        fake_login("app.example.com"),
        fake_login("app.example.com"),
        fake_login("app.example.com"),
    )
    assert max_active == 1


@pytest.mark.asyncio
async def test_different_hosts_login_in_parallel():
    """Different products never block each other: both hold their locks at once."""
    coord = lc.get_login_coordinator()
    active = 0
    max_active = 0

    async def fake_login(host):
        nonlocal active, max_active
        async with coord.lock_for(coord.site_key_for(host)):
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.05)
            active -= 1

    await asyncio.gather(
        fake_login("alpha.example.com"),
        fake_login("beta.example.com"),
    )
    assert max_active == 2


# ── breaker bridge ───────────────────────────────────────────────────────────

def test_reset_without_worker_is_noop():
    coord = lc.get_login_coordinator()
    assert coord.reset_refresh_breaker("no worker") is False


def test_reset_reaches_registered_worker():
    coord = lc.get_login_coordinator()
    resets = []

    class _Worker:
        def reset(self, reason):
            resets.append(reason)

    coord.register_refresh_worker(_Worker())
    assert coord.reset_refresh_breaker("verified activation") is True
    assert resets == ["verified activation"]


@pytest.mark.asyncio
async def test_tool_style_login_resets_breaker_via_coordinator():
    """The 2-A deferral, closed: an in-process copilot-tool login (no runner
    handle) lands a fresh session → the scan-time breaker re-arms, because the
    runner registered the live worker into the coordinator."""
    from dast.session.refresh_worker import SessionRefreshWorker, _MAX_REAUTH_FAILURES

    coord = lc.get_login_coordinator()
    worker = SessionRefreshWorker(
        auth_url="https://app.example.com/login", username="u", password="p",
        pool=object(), session_manager=object())
    coord.register_refresh_worker(worker)
    for _ in range(_MAX_REAUTH_FAILURES):
        worker._register_failure("fail")
    assert worker._gave_up

    assert coord.reset_refresh_breaker("tool login landed")
    assert worker._gave_up is False

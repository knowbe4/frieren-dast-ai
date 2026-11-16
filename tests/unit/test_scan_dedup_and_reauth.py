"""
Unit tests for two reliability guards:
  1. Scan-time dedup normalises variable path segments (UUIDs/IDs) so the same
     logical endpoint is not re-scanned once per distinct ID.
  2. The session refresh worker's circuit breaker stops re-authenticating after
     repeated failures (stale credentials) instead of burning a browser context
     on every subsequent 401.
"""

from __future__ import annotations


from dast.proxy.scan_support import normalise_dedup_path as _normalise_dedup_path
from dast.session.refresh_worker import SessionRefreshWorker, _MAX_REAUTH_FAILURES


# ── path normalisation (dedup key) ──────────────────────────────────────────

class TestNormalisePath:
    def test_uuid_collapsed(self):
        a = _normalise_dedup_path("/api/ff6633c1-5ae4-404a-9c78-85d0119b712f/export")
        b = _normalise_dedup_path("/api/00000000-1111-2222-3333-444444444444/export")
        assert a == b == "/api/{id}/export"

    def test_numeric_id_collapsed(self):
        # _ID_RE matches numeric IDs of 2+ digits (avoids collapsing /v1/ etc).
        assert _normalise_dedup_path("/users/1024/profile") == _normalise_dedup_path("/users/55/profile")
        assert _normalise_dedup_path("/users/1024/profile") == "/users/{id}/profile"

    def test_hex_object_id_collapsed(self):
        a = _normalise_dedup_path("/doc/507f1f77bcf86cd799439011")
        assert a == "/doc/{id}"

    def test_distinct_endpoints_stay_distinct(self):
        assert _normalise_dedup_path("/api/users") != _normalise_dedup_path("/api/orders")

    def test_query_string_stripped(self):
        assert _normalise_dedup_path("/search?q=hello") == "/search"

    def test_dedup_key_matches_across_ids(self):
        # The scan-time dedup key shape: (method, host, normalised-path, operation).
        def key(path):
            return ("GET", "api.example.com", _normalise_dedup_path(path), "")
        assert key("/api/v1/accounts/777") == key("/api/v1/accounts/999")


# ── re-auth circuit breaker ─────────────────────────────────────────────────

def _make_worker() -> SessionRefreshWorker:
    return SessionRefreshWorker(
        auth_url="https://app.example.com/login",
        username="u", password="p",
        pool=object(), session_manager=object(),
    )


class TestReauthBreaker:
    def test_trips_after_threshold(self):
        w = _make_worker()
        for _ in range(_MAX_REAUTH_FAILURES):
            assert not w._gave_up
            w._register_failure("fail")
        assert w._gave_up
        assert w._consecutive_failures == _MAX_REAUTH_FAILURES

    def test_success_resets_counter(self):
        w = _make_worker()
        w._register_failure("fail")
        w._register_failure("fail")
        assert w._consecutive_failures == 2
        # Simulate the success branch of _reauth().
        w._consecutive_failures = 0
        assert not w._gave_up
        # Further failures start counting from zero again.
        w._register_failure("fail")
        assert w._consecutive_failures == 1
        assert not w._gave_up


# ── probe-aware trigger + recoverable breaker (round 2-A) ───────────────────

import asyncio
import time

import pytest

from dast.proxy.session_store import ProxyEntry


def _entry(status=401, source="proxy", probe_payload=None, location="", body=""):
    return ProxyEntry(
        id="e1", method="GET", url="https://app.example.com/api/things",
        host="app.example.com", path="/api/things",
        request_headers={}, request_body=None,
        response_status=status,
        response_headers={"location": location} if location else {},
        response_body=body.encode() if body else None,
        source=source, probe_payload=probe_payload,
    )


class TestProbeAwareTrigger:
    def test_copilot_probe_traffic_is_not_a_signal(self):
        # The copilot runs its own relogin ladder — a scan-time re-auth on top of it
        # double-logins the same account.
        from dast.session.refresh_worker import _is_expiry_signal
        assert _is_expiry_signal(_entry(401, source="copilot")) is False

    def test_injected_probe_403_is_not_a_signal(self):
        # x-dast-payload-tagged entries are the scanner's own authz probes; their
        # 401/403 are expected answers, not session death.
        from dast.session.refresh_worker import _is_expiry_signal
        assert _is_expiry_signal(_entry(403, probe_payload="' OR 1=1--")) is False

    def test_operator_traffic_401_still_signals(self):
        from dast.session.refresh_worker import _is_expiry_signal
        assert _is_expiry_signal(_entry(401, source="proxy")) is True
        assert _is_expiry_signal(_entry(401, source="browse")) is True


class TestBreakerRecovery:
    def test_reset_recovers_a_tripped_breaker(self):
        # The old breaker could only be cleared by restarting the process.
        w = _make_worker()
        for _ in range(_MAX_REAUTH_FAILURES):
            w._register_failure("fail")
        assert w._gave_up
        w.reset("profile activation landed a verified session")
        assert not w._gave_up
        assert w._consecutive_failures == 0
        # ...and it actually resumes: a new failure counts from zero, not trip-immediately.
        w._register_failure("fail")
        assert w._consecutive_failures == 1 and not w._gave_up

    def test_state_snapshot_shape(self):
        w = _make_worker()
        snap = w.state_snapshot()
        assert snap["active"] is True and snap["gave_up"] is False
        assert snap["consecutive_failures"] == 0
        assert snap["cooldown_active"] is False
        w._register_failure("creds rejected")
        assert w.state_snapshot()["last_failure_reason"] == "creds rejected"


@pytest.mark.asyncio
async def test_signals_during_cooldown_are_coalesced_not_dropped(monkeypatch):
    """Two signals land while the first re-auth runs: exactly ONE deferred re-check
    happens afterwards (the old code silently dropped both)."""
    w = _make_worker()
    calls = []

    async def fake_reauth():
        calls.append(time.monotonic())

    monkeypatch.setattr(w, "_reauth", fake_reauth)
    task = asyncio.create_task(w.run())
    try:
        w.on_entry(_entry(401))
        await asyncio.sleep(0.05)
        assert len(calls) == 1  # first signal processed immediately

        # These two arrive inside the cooldown window.
        w.on_entry(_entry(401))
        w.on_entry(_entry(401))
        await asyncio.sleep(0.05)
        assert len(calls) == 1  # NOT processed mid-cooldown
        assert w._pending_signal is True

        w._fire_coalesced()  # what the cooldown timer would do
        await asyncio.sleep(0.05)
        assert len(calls) == 2  # exactly one coalesced re-check
        assert w._pending_signal is False
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

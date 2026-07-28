"""
Unit tests for two reliability guards:
  1. Scan-time dedup normalises variable path segments (UUIDs/IDs) so the same
     logical endpoint is not re-scanned once per distinct ID.
  2. The session refresh worker's circuit breaker stops re-authenticating after
     repeated failures (stale credentials) instead of burning a browser context
     on every subsequent 401.
"""

from __future__ import annotations

import pytest

from dast.proxy.runner import _normalise_dedup_path
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

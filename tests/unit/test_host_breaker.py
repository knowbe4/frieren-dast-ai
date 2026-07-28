"""
Unit tests for the host reachability circuit breaker in active_checks.

A host that cannot be reached (DNS failure, connection refused, proxy 502/504)
must trip the breaker after a few consecutive failures, after which all further
probes to that host short-circuit instead of flooding the scan with dead
requests. A single real response must reset the failure counter.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from dast.scanners import active_checks as ac
from dast.scanners.active_checks import (
    _HOST_DEAD_THRESHOLD,
    _send,
    is_host_dead,
    reset_host_reachability,
)


@pytest.fixture(autouse=True)
def _clean_state():
    """Each test starts with a clean breaker."""
    reset_host_reachability()
    yield
    reset_host_reachability()


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(5.0))


class TestBreakerTrips:
    @respx.mock
    async def test_connection_errors_trip_breaker(self):
        respx.get("https://dead.example.com/x").mock(
            side_effect=httpx.ConnectError("Name or service not known")
        )
        async with _client() as client:
            for _ in range(_HOST_DEAD_THRESHOLD):
                assert not is_host_dead("dead.example.com")  # still trying
                await _send(client, "GET", "https://dead.example.com/x", {}, None)

        assert is_host_dead("dead.example.com")

    @respx.mock
    async def test_proxy_502_counts_as_unreachable(self):
        respx.get("https://gone.example.com/y").mock(
            return_value=httpx.Response(502)
        )
        async with _client() as client:
            for _ in range(_HOST_DEAD_THRESHOLD):
                await _send(client, "GET", "https://gone.example.com/y", {}, None)

        assert is_host_dead("gone.example.com")

    @respx.mock
    async def test_dead_host_short_circuits_without_request(self):
        route = respx.get("https://dead2.example.com/z").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with _client() as client:
            for _ in range(_HOST_DEAD_THRESHOLD):
                await _send(client, "GET", "https://dead2.example.com/z", {}, None)
            calls_when_dead = route.call_count

            # Further sends must NOT hit the network — breaker is open.
            result = await _send(client, "GET", "https://dead2.example.com/z", {}, None)

        assert result is None
        assert route.call_count == calls_when_dead


class TestBreakerResets:
    @respx.mock
    async def test_real_response_resets_counter(self):
        # A few failures, then a success, then more failures — must NOT trip,
        # because the success reset the consecutive-failure counter.
        route = respx.get("https://flaky.example.com/a")
        responses = (
            [httpx.ConnectError("x")] * (_HOST_DEAD_THRESHOLD - 1)
            + [httpx.Response(200, text="ok")]
            + [httpx.ConnectError("x")] * (_HOST_DEAD_THRESHOLD - 1)
        )
        route.mock(side_effect=responses)
        async with _client() as client:
            for _ in range(len(responses)):
                await _send(client, "GET", "https://flaky.example.com/a", {}, None)

        assert not is_host_dead("flaky.example.com")

    @respx.mock
    async def test_app_error_response_still_reachable(self):
        # A 404/500 from the app proves the host is reachable — never trips.
        respx.get("https://live.example.com/b").mock(
            return_value=httpx.Response(404)
        )
        async with _client() as client:
            for _ in range(_HOST_DEAD_THRESHOLD + 3):
                await _send(client, "GET", "https://live.example.com/b", {}, None)

        assert not is_host_dead("live.example.com")


def test_reset_clears_dead_hosts():
    ac._HOST_DEAD.add("x.example.com")
    ac._HOST_FAILURE_STATE["x.example.com"] = 9
    reset_host_reachability()
    assert not is_host_dead("x.example.com")
    assert "x.example.com" not in ac._HOST_FAILURE_STATE

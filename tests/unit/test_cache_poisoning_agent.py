"""
Unit tests for the web cache-poisoning agent.

The most important guarantees:
  * a reflected header that is CONFIRMED served from cache (marker survives a
    request WITHOUT the header) -> confirmed high finding;
  * a reflected header that is NOT cached -> medium, unconfirmed (LLM validates);
  * a keyed / non-reflecting header -> no finding;
  * a non-cacheable endpoint -> the agent bails without probing headers;
  * every probe carries a unique cache-buster so we never touch the shared key.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


from dast.agents import cache_poisoning_agent as cp


def _resp(status=200, body=b"<html>ok</html>", headers=None):
    r = MagicMock()
    r.status_code = status
    r.content = body
    r.text = body.decode("utf-8", errors="replace")
    r.headers = headers or {"content-type": "text/html", "cache-control": "public, max-age=60"}
    r.request = MagicMock()
    r.request.method = "GET"
    r.request.url = "https://in.scope/page"
    r.request.headers = {}
    r.request.content = b""
    return r


def _target(method="GET", url="https://in.scope/page", headers=None):
    t = MagicMock()
    t.method = method
    t.url = url
    t.headers = headers or {"host": "in.scope"}
    t.body = None
    t.params = []
    return t


def _run(coro):
    return asyncio.run(coro)


def test_non_get_method_skipped():
    agent = cp.CachePoisoningAgent()
    send = AsyncMock()
    with patch.object(cp, "_send", new=send):
        findings = _run(agent.run(_target(method="POST"), MagicMock()))
    assert findings == []
    assert send.call_count == 0


def test_non_cacheable_endpoint_bails_before_header_probes():
    """no-store baseline -> only the baseline request is sent, no header probes."""
    agent = cp.CachePoisoningAgent()
    calls: list = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        calls.append(url)
        return _resp(headers={"cache-control": "no-store"})

    with patch.object(cp, "_send", new=AsyncMock(side_effect=fake_send)):
        findings = _run(agent.run(_target(), MagicMock()))

    assert findings == []
    assert len(calls) == 1, "only the baseline probe should have been sent"


def test_redirect_response_is_not_probed():
    """A 3xx (e.g. '/' redirecting to a login) is never cacheable — the agent
    must send only the baseline and probe no unkeyed headers, even though the
    redirect carries no explicit no-store directive."""
    agent = cp.CachePoisoningAgent()
    calls: list = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        calls.append(url)
        return _resp(status=302, headers={"location": "https://in.scope/login"})

    with patch.object(cp, "_send", new=AsyncMock(side_effect=fake_send)):
        findings = _run(agent.run(_target(), MagicMock()))

    assert findings == []
    assert len(calls) == 1, "a redirect must not trigger header probes"


def test_no_cache_signal_response_is_not_probed():
    """A plain 200 with NO cache-indicator header and NO shared-cache directive
    is not treated as cacheable — positive evidence is required before probing."""
    agent = cp.CachePoisoningAgent()
    calls: list = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        calls.append(url)
        return _resp(headers={"content-type": "text/html"})

    with patch.object(cp, "_send", new=AsyncMock(side_effect=fake_send)):
        findings = _run(agent.run(_target(), MagicMock()))

    assert findings == []
    assert len(calls) == 1, "no cache evidence must mean no header probes"


def test_cache_indicator_header_enables_probing():
    """A cache-indicator header (x-cache) is positive proof a cache is in play,
    so the agent proceeds to probe unkeyed headers even without Cache-Control."""
    agent = cp.CachePoisoningAgent()
    calls: list = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        calls.append(url)
        return _resp(headers={"content-type": "text/html", "x-cache": "HIT"})

    with patch.object(cp, "_send", new=AsyncMock(side_effect=fake_send)):
        _run(agent.run(_target(), MagicMock()))

    assert len(calls) > 1, "x-cache present should allow header probes"


def test_confirmed_cache_poisoning():
    """Marker reflects AND survives a request without the header -> confirmed high."""
    agent = cp.CachePoisoningAgent()

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        marker = None
        # find any dastcp marker requested via X-Forwarded-Host-ish headers
        for v in headers.values():
            if "dastcp" in str(v):
                marker = str(v).split("dastcp")[1][:8]
                break
        # Baseline (no marker header) -> cacheable, no marker.
        if marker is None:
            # This is either the very first baseline or the confirm-without-header
            # request. Return the last poisoned marker if one is "cached".
            cached = getattr(fake_send, "_cached_marker", None)
            body = f"<html>host dastcp{cached}q</html>".encode() if cached else b"<html>ok</html>"
            return _resp(body=body)
        # Poison request: reflect the marker and remember it as cached.
        fake_send._cached_marker = marker
        return _resp(body=f"<html>host dastcp{marker}q</html>".encode())

    with patch.object(cp, "_send", new=AsyncMock(side_effect=fake_send)):
        findings = _run(agent.run(_target(), MagicMock()))

    assert findings, "expected at least one finding"
    confirmed = [f for f in findings if f.confirmed and f.bypass_validation]
    assert confirmed, "expected a confirmed cache-poisoning finding"
    assert confirmed[0].title == "Web Cache Poisoning"
    assert confirmed[0].severity == "high"


def test_reflected_but_not_cached_is_unconfirmed_medium():
    """Marker reflects in poison request but NOT in the header-less request."""
    agent = cp.CachePoisoningAgent()

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        marker = None
        for v in headers.values():
            if "dastcp" in str(v):
                marker = str(v)
                break
        if marker is None:
            # Baseline and confirm-without-header requests never reflect.
            return _resp(body=b"<html>clean</html>")
        # Poison request reflects the marker, but cache does not retain it.
        return _resp(body=f"<html>{marker}</html>".encode())

    with patch.object(cp, "_send", new=AsyncMock(side_effect=fake_send)):
        findings = _run(agent.run(_target(), MagicMock()))

    assert findings, "a reflected header should still produce an unconfirmed finding"
    assert all(not f.confirmed for f in findings)
    assert all(f.severity == "medium" for f in findings)
    assert all(not f.bypass_validation for f in findings)


def test_keyed_or_non_reflecting_header_yields_no_finding():
    """A header that never reflects produces no finding at all."""
    agent = cp.CachePoisoningAgent()

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        return _resp(body=b"<html>never reflects anything</html>")

    with patch.object(cp, "_send", new=AsyncMock(side_effect=fake_send)):
        findings = _run(agent.run(_target(), MagicMock()))

    assert findings == []


def test_cache_buster_is_unique_per_probe():
    """Each _cache_buster_url call appends a distinct dastcb param."""
    urls = {cp._cache_buster_url("https://in.scope/p") for _ in range(50)}
    assert len(urls) > 1, "cache-buster must vary between probes"
    assert all("dastcb" in u for u in urls)


def test_baseline_failure_returns_no_findings():
    agent = cp.CachePoisoningAgent()
    with patch.object(cp, "_send", new=AsyncMock(return_value=None)):
        findings = _run(agent.run(_target(), MagicMock()))
    assert findings == []


def test_marker_reflected_checks_redirect_headers():
    r = _resp(status=302, headers={"location": "https://dastcp123q.evil/x"})
    assert cp._marker_reflected(r, "dastcp123q") is True
    r2 = _resp(status=200, body=b"nothing")
    assert cp._marker_reflected(r2, "dastcp123q") is False

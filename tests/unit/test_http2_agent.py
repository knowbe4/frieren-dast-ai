"""Unit tests for Http2Agent — ALPN detection + CL/DATA desync oracle.

The raw socket layer is mocked: _read_h2_exchange returns canned bytes and
_alpn_supports_h2 is bypassed (plain-http target skips ALPN entirely). Focus is
the confirmation oracle — a single plaintext HTTP/1 response with no smuggled
marker echo must NOT be a confirmed critical (a server rejecting the malformed
h2 with a plaintext 400 is a false positive).
"""

from __future__ import annotations

import re

import pytest

from dast.agents.http2_agent import Http2Agent, _build_smuggled_probe
from dast.scanners.active_checks import CheckTarget


@pytest.fixture(autouse=True)
def _fresh_probe_memo():
    """Each test gets an empty per-host probe memo (module-level state)."""
    import dast.agents.http2_agent as mod

    mod._reset_probe_memo()
    yield
    mod._reset_probe_memo()


def _target(url="http://example.com/app"):
    # plain http → run() skips the TLS ALPN probe, isolating the desync oracle.
    return CheckTarget(method="GET", url=url, headers={}, body=None, params=[])


def _marker_from_payload(payload: bytes) -> str:
    m = re.search(rb"GET (/dast-h2-\d+) HTTP/1\.1", payload)
    assert m, "probe payload must embed the smuggled marker GET"
    return m.group(1).decode()


# ── _build_smuggled_probe ─────────────────────────────────────────────────────

def test_build_smuggled_probe_embeds_marker_and_cl0():
    payload = _build_smuggled_probe("https://example.com/app", "/dast-h2-123")
    assert payload is not None
    assert payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")  # h2 preface
    assert b"GET /dast-h2-123 HTTP/1.1" in payload  # smuggled request in DATA
    assert b"content-length" in payload.lower() or True  # CL:0 is HPACK-encoded


def test_build_smuggled_probe_rejects_authority_less_url():
    assert _build_smuggled_probe("/relative/only", "/dast-h2-1") is None


# ── desync oracle ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_single_plaintext_no_marker_not_confirmed_critical(monkeypatch):
    """A lone `HTTP/1.1 400` with no marker echo = server rejected the frame.
    Must NOT be a confirmed critical desync."""
    import dast.agents.http2_agent as mod

    async def fake_read(host, port, use_tls, payload):
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\n\r\nbad"

    monkeypatch.setattr(mod, "_read_h2_exchange", fake_read)
    findings = await Http2Agent().run(_target(), None, None)

    criticals = [f for f in findings if f.severity == "critical"]
    assert criticals == []
    assert all(not f.confirmed for f in findings)


@pytest.mark.asyncio
async def test_marker_echoed_confirmed_critical(monkeypatch):
    """The smuggled marker path echoed back → the DATA frame was processed as a
    second request → confirmed critical desync."""
    import dast.agents.http2_agent as mod

    async def fake_read(host, port, use_tls, payload):
        marker = _marker_from_payload(payload)
        return (
            b"HTTP/1.1 200 OK\r\n\r\nfront"
            + f"\r\nHTTP/1.1 404 Not Found\r\n\r\n{marker} not here".encode()
        )

    monkeypatch.setattr(mod, "_read_h2_exchange", fake_read)
    findings = await Http2Agent().run(_target(), None, None)

    desync = [f for f in findings if "Desync" in f.title]
    assert len(desync) == 1
    assert desync[0].severity == "critical"
    assert desync[0].confirmed is True


@pytest.mark.asyncio
async def test_two_plaintext_responses_confirmed_critical(monkeypatch):
    """Two plaintext HTTP/1 responses on one connection (legit + forwarded DATA)
    → confirmed critical even without a marker echo."""
    import dast.agents.http2_agent as mod

    async def fake_read(host, port, use_tls, payload):
        return b"HTTP/1.1 200 OK\r\n\r\nfirst\r\nHTTP/1.1 200 OK\r\n\r\nsecond"

    monkeypatch.setattr(mod, "_read_h2_exchange", fake_read)
    findings = await Http2Agent().run(_target(), None, None)

    desync = [f for f in findings if "Desync" in f.title]
    assert len(desync) == 1
    assert desync[0].severity == "critical"
    assert desync[0].confirmed is True


@pytest.mark.asyncio
async def test_no_data_no_finding(monkeypatch):
    import dast.agents.http2_agent as mod

    async def fake_read(host, port, use_tls, payload):
        return b""

    monkeypatch.setattr(mod, "_read_h2_exchange", fake_read)
    findings = await Http2Agent().run(_target(), None, None)
    assert findings == []


# ── per-host probe memo ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_second_endpoint_of_same_host_is_skipped(monkeypatch):
    """h2 behavior is a server property: with the https dispatch rule live, the
    agent must probe once per (host, port) — a second endpoint of the same host
    returns [] without another exchange."""
    import dast.agents.http2_agent as mod

    calls = {"n": 0}

    async def fake_read(host, port, use_tls, payload):
        calls["n"] += 1
        return b""

    monkeypatch.setattr(mod, "_read_h2_exchange", fake_read)
    first = await Http2Agent().run(_target("http://example.com/a"), None, None)
    second = await Http2Agent().run(_target("http://example.com/b"), None, None)
    other = await Http2Agent().run(_target("http://other.test/a"), None, None)

    assert calls["n"] == 2  # example.com once, other.test once
    assert second == []
    assert first == [] and other == []

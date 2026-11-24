"""CSWSH agent tests (4-B): handshake builder, verdict, discovery channel.

The raw transport is faked (patch of ``_send_handshake`` + ``is_host_dead``,
the smuggling-suite pattern); builder asserts pin the wire format; the
observer test pins the focus-hint discovery channel.
"""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock

import dast.agents  # noqa: F401 — populates the Coordinator registry
import pytest

from dast.ai.coordinator import Coordinator
from dast.scanners.active_checks import CheckTarget


def _target(url="https://app.example.com/ws", cookie=True):
    headers = {"cookie": "sid=victim"} if cookie else {"x-app": "1"}
    return CheckTarget(method="GET", url=url, headers=headers, body=None, params=[])


def _accept_for(key: str) -> str:
    digest = hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    return base64.b64encode(digest).decode()


@pytest.fixture(autouse=True)
def _fresh_registry():
    from dast.ai import provider_health

    provider_health.reset()
    yield
    provider_health.reset()


def _install(monkeypatch, status=101, accept_key=None):
    """Patch the transport; returns (handshakes, accept_expected)."""
    import dast.agents.cswsh_agent as mod

    handshakes: list = []

    async def fake_send_handshake(host, port, use_tls, payload):
        handshakes.append({"host": host, "port": port, "use_tls": use_tls,
                           "payload": payload.decode("latin-1")})
        key = handshakes[-1]["payload"].split("Sec-WebSocket-Key: ")[1].split("\r\n")[0]
        accept = _accept_for(key) if accept_key is None else accept_key
        head = (f"HTTP/1.1 {status} Switching Protocols\r\n"
                f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n")
        return mod._parse_head(head.encode("latin-1"))

    def fake_dead(host):
        return False

    monkeypatch.setattr(mod, "_send_handshake", fake_send_handshake)
    monkeypatch.setattr(mod, "is_host_dead", fake_dead)
    return handshakes


@pytest.mark.asyncio
async def test_101_with_attacker_origin_and_cookie_is_high_confirmed(monkeypatch):
    from dast.agents.cswsh_agent import CswshAgent, _EVIL_ORIGIN

    handshakes = _install(monkeypatch, status=101)
    target = _target(cookie=True)
    target.focus_attack_types = ["websocket"]  # observer hint channel
    findings = await CswshAgent().run(target, MagicMock(), None)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].cwe == "CWE-346"
    assert findings[0].confirmed is True
    hs = handshakes[0]["payload"]
    assert "Upgrade: websocket" in hs
    assert f"Origin: {_EVIL_ORIGIN}" in hs
    assert "cookie: sid=victim" in hs          # victim socket position
    assert "Host: app.example.com" in hs
    key = hs.split("Sec-WebSocket-Key: ")[1].split("\r\n")[0]
    base64.b64decode(key)                      # valid b64, 16 raw bytes
    assert len(base64.b64decode(key)) == 16


@pytest.mark.asyncio
async def test_101_without_session_cookie_is_info_unconfirmed(monkeypatch):
    from dast.agents.cswsh_agent import CswshAgent

    target = _target(cookie=False)
    target.focus_attack_types = ["websocket"]
    _install(monkeypatch, status=101)
    findings = await CswshAgent().run(target, MagicMock(), None)
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].confirmed is False


@pytest.mark.asyncio
async def test_non_101_origin_rejected_is_no_finding(monkeypatch):
    from dast.agents.cswsh_agent import CswshAgent

    _install(monkeypatch, status=403)
    findings = await CswshAgent().run(_target(), MagicMock(), None)
    assert findings == []


@pytest.mark.asyncio
async def test_bad_accept_is_not_reported(monkeypatch):
    from dast.agents.cswsh_agent import CswshAgent

    _install(monkeypatch, status=101, accept_key="garbage-accept")
    findings = await CswshAgent().run(_target(), MagicMock(), None)
    assert findings == []


@pytest.mark.asyncio
async def test_plain_http_endpoint_without_hint_is_skipped(monkeypatch):
    from dast.agents.cswsh_agent import CswshAgent

    handshakes = _install(monkeypatch, status=101)
    target = _target()
    target.focus_attack_types = []
    findings = await CswshAgent().run(target, MagicMock(), None)
    assert findings == []
    assert handshakes == []  # no WS hint → no probes at all


def test_registered():
    assert "cswsh" in Coordinator._registry


# ── discovery channel: the observer tags 101 entries with the cswsh focus ────

@pytest.mark.asyncio
async def test_observer_sets_cswsh_focus_hint(monkeypatch):

    from dast.plugins import websocket_observer as obs

    obs._seen_endpoints.clear()

    class _Store:
        def add_finding(self, *a, **k): pass

    entry = SimpleNamespace(
        id="1", source="proxy", host="app.example.com", path="/ws",
        url="https://app.example.com/ws", method="GET",
        request_headers={"upgrade": "websocket", "origin": "https://app.example.com",
                         "cookie": "sid=1"},
        response_status=101, focus_attack_types=None,
    )
    await obs.WebsocketObserverPlugin().on_entry(entry, _Store())
    assert entry.focus_attack_types == ["cswsh"]

"""Replay route tests (3-I mini-Repeater): POST /api/replay/{entry_id}.

The route rebuilds the request from the RAW stored fields, strips hop-by-hop
and internal headers, tags it x-dast-source: replay and sends it proxy-routed
(httpx mock via respx — no real network, same as the host-breaker suite).
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from dast.proxy.session_store import SessionStore


@pytest.fixture
def store():
    return SessionStore()


@pytest.fixture
def client(store):
    from fastapi.testclient import TestClient

    from dast.proxy.dashboard_server import build_app

    app = build_app(store=store, scan_queue=asyncio.Queue())
    with TestClient(app, base_url="http://127.0.0.1") as c:
        yield c


def _seed(store, headers=None, body=b"a=1&x=1"):
    entry_id = store.new_entry(
        "POST", "https://example.com/api/thing",
        headers if headers is not None else {
            "content-type": "application/json", "cookie": "sid=old",
            "x-dast-source": "scan", "host": "example.com",
        },
        body,
    )
    store.complete_entry(entry_id, status=200, response_headers={}, response_body=b"{}",
                         duration_ms=5.0)
    return entry_id


def test_unknown_entry_returns_404(client):
    resp = client.post("/api/replay/does-not-exist", json={})
    assert resp.status_code == 404


@respx.mock
async def test_replay_strips_and_retags_headers(client, store):
    entry_id = _seed(store)
    route = respx.post("https://example.com/api/thing").mock(
        return_value=httpx.Response(200, json={"ok": True}))

    resp = client.post(f"/api/replay/{entry_id}", json={})

    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True and data["status"] == 200
    assert data["replayed_from"] == entry_id
    sent = route.calls.last.request
    assert sent.headers["x-dast-source"] == "replay"        # retagged
    assert sent.headers["cookie"] == "sid=old"              # captured cookie kept
    assert sent.headers["content-type"] == "application/json"
    assert "x-dast-crawler" not in sent.headers
    assert sent.content == b"a=1&x=1"                        # raw body, unmodified


@respx.mock
async def test_replay_response_shape_and_recorded_flag(client, store):
    entry_id = _seed(store)
    respx.post("https://example.com/api/thing").mock(
        return_value=httpx.Response(404, text="nope"))

    resp = client.post(f"/api/replay/{entry_id}", json={})

    data = resp.json()
    assert data["status"] == 404
    assert data["body"] == "nope"
    assert data["truncated"] is False
    assert data["duration_ms"] >= 0
    # TestClient wires ctx.runner=None → no proxy → direct send, not recorded
    assert data["recorded"] is False


def test_replay_oversized_body_returns_413(client, store):
    entry_id = _seed(store, body=b"x" * (8 * 1024 * 1024 + 1))
    resp = client.post(f"/api/replay/{entry_id}", json={})
    assert resp.status_code == 413


@respx.mock
async def test_replay_error_returns_502(client, store):
    entry_id = _seed(store)
    respx.post("https://example.com/api/thing").mock(
        side_effect=httpx.ConnectError("down"))

    resp = client.post(f"/api/replay/{entry_id}", json={})
    assert resp.status_code == 502


# ── source classification: 'replay' passes through and is excluded from intel ─

def test_new_entry_resolves_replay_source(store):
    # the proxy server reads x-dast-source and passes it as the source= arg
    entry_id = store.new_entry(
        "GET", "https://example.com/x", {"x-dast-source": "replay"}, None,
        source="replay")
    entry = store.get_entry(entry_id)
    assert entry.source == "replay"


def test_replay_entries_do_not_consume_pending_imports(store):
    """A replay is operator verification, not discovery — it must not swallow
    imported-finding stubs (which enqueue scans) the way live traffic would."""
    store.pending_import_findings = [
        {"path": "/api/thing", "method": "POST", "payload": "x", "attack_type": "sqli"},
    ]
    entry_id = store.new_entry(
        "POST", "https://example.com/api/thing", {"x-dast-source": "replay"}, None)
    entry = store.get_entry(entry_id)
    entry.source = "replay"

    store._drain_pending_findings(entry)

    # the stub survived: nothing was matched, nothing was injected or queued
    assert len(store.pending_import_findings) == 1
    assert entry.import_hints == []
    assert entry.queued_for_scan is False


def test_live_entries_still_consume_pending_imports(store):
    """Control for the exclusion above: same stub, live proxy traffic consumes it."""
    store.pending_import_findings = [
        {"path": "/api/thing", "method": "POST", "attack_type": "sqli",
         "hints": [{"parameter": "x", "payload": "y", "attack_type": "sqli"}]},
    ]
    entry_id = store.new_entry(
        "POST", "https://example.com/api/thing", {}, None)
    entry = store.get_entry(entry_id)
    entry.source = "proxy"

    store._drain_pending_findings(entry)

    assert store.pending_import_findings == []
    assert entry.import_hints

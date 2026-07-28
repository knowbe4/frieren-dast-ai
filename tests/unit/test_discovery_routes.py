"""
Route tests for the content-discovery API.

Confirms the scope safety gate at the HTTP boundary: an out-of-scope URL is
rejected with 400 and never enqueued; an in-scope URL is accepted and enqueued.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client_and_queue(monkeypatch):
    from dast.proxy import proxy_settings as ps
    from dast.proxy.api import status_routes as status_mod
    from dast.proxy.dashboard_server import build_app
    from dast.proxy.plugin_manager import PluginManager
    from dast.proxy.intercept_store import InterceptStore
    from dast.proxy.session_store import SessionStore

    async def _noop(ctx):
        return None
    monkeypatch.setattr(status_mod, "prefetch_ai_status", _noop)

    settings = ps.ProxySettings()
    # Only in.scope is included; everything else is out of scope.
    settings._scope_rules = [{"kind": "include", "host": "in.scope", "enabled": True}]

    discovery_queue: asyncio.Queue = asyncio.Queue()
    app = build_app(
        store=SessionStore(),
        scan_queue=asyncio.Queue(),
        settings=settings,
        plugin_manager=PluginManager(),
        intercept_store=InterceptStore(),
        discovery_queue=discovery_queue,
    )
    return TestClient(app), discovery_queue


def test_out_of_scope_url_rejected_and_not_enqueued(client_and_queue):
    client, queue = client_and_queue
    r = client.post("/api/discovery", json={"url": "https://out.of.scope/"})
    assert r.status_code == 400
    assert queue.qsize() == 0


def test_missing_url_rejected(client_and_queue):
    client, queue = client_and_queue
    r = client.post("/api/discovery", json={})
    assert r.status_code == 400
    assert queue.qsize() == 0


def test_in_scope_url_accepted_and_enqueued(client_and_queue):
    client, queue = client_and_queue
    r = client.post("/api/discovery", json={"url": "https://in.scope/"})
    assert r.status_code == 200
    assert r.json().get("ok") is True
    assert queue.qsize() == 1
    job = queue.get_nowait()
    assert job["url"] == "https://in.scope/"
    assert job["dirs"] is True and job["files"] is True and job["graphql"] is True


def test_stop_route_enqueues_stop(client_and_queue):
    client, queue = client_and_queue
    r = client.post("/api/discovery/stop")
    assert r.status_code == 200
    assert queue.get_nowait() == {"action": "stop"}

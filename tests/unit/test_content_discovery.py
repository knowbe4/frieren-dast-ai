"""
Unit tests for content discovery (forced browsing).

The single most important guarantee is the SCOPE SAFETY test: content discovery
must NEVER issue a probe to an out-of-scope host. The other tests cover soft-404
filtering, hit classification, and the dead-host circuit breaker.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.scanners import content_discovery as cd


def _resp(status: int, body: bytes = b"body", content_type: str = "text/html"):
    r = MagicMock()
    r.status_code = status
    r.content = body
    r.headers = {"content-type": content_type}
    return r


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    # Never touch the reachability globals or the wordlist files by accident.
    monkeypatch.setattr(cd, "reset_host_reachability", lambda: None)
    monkeypatch.setattr(cd, "is_host_dead", lambda h: False)
    # Small deterministic wordlists.
    monkeypatch.setattr(
        cd,
        "load_wordlist",
        lambda name: {
            "directories": ["admin", "backup"],
            "files": ["robots.txt", "config.php"],
            "graphql": ["graphql"],
        }[name],
    )


def test_out_of_scope_target_issues_no_probe():
    """The hard safety guarantee: an out-of-scope base URL probes nothing."""
    settings = MagicMock()
    settings.is_in_scope.return_value = False
    send = AsyncMock()
    with patch.object(cd, "_send", new=send), patch.object(cd, "_client"):
        hits = _run(cd.run_content_discovery("https://evil.example/", {}, settings))
    assert hits == []
    assert send.call_count == 0, "must not send any request to an out-of-scope host"


def test_per_path_out_of_scope_paths_are_skipped():
    """Even for an in-scope host, individual out-of-scope paths are never probed."""
    settings = MagicMock()
    # host in scope, but any URL containing 'admin' is out of scope
    settings.is_in_scope.side_effect = lambda url: "admin" not in url

    probed: list[str] = []

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        probed.append(url)
        return _resp(404)  # everything 404 so we only assert on what was probed

    with patch.object(cd, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(cd, "_client"):
        _run(cd.run_content_discovery("https://in.scope/", {}, settings, include_graphql=False))

    assert not any("admin" in u for u in probed), "out-of-scope path must never be requested"
    assert any("backup" in u for u in probed), "in-scope paths should still be probed"


def test_hit_detection_and_classification():
    settings = MagicMock()
    settings.is_in_scope.return_value = True

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        if "nonexistent" in url:
            return _resp(404)  # soft-404 baseline: not found
        if url.rstrip("/").endswith("graphql"):
            return _resp(200, b'{"data":null}', "application/json")
        if url.rstrip("/").endswith("admin"):
            return _resp(200, b"<html>admin</html>")
        return _resp(404)

    with patch.object(cd, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(cd, "_client"):
        hits = _run(cd.run_content_discovery("https://in.scope/", {}, settings))

    kinds = {(h["kind"], h["status"]) for h in hits}
    assert ("graphql", 200) in kinds
    assert ("dir", 200) in kinds
    # 404s are never hits
    assert all(h["status"] != 404 for h in hits)


def test_soft_404_filtered():
    """A 200 whose body matches the not-found baseline is discarded as a soft-404."""
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    generic = b"<html>not found generic page</html>"

    async def fake_send(client, method, url, headers, body, payload=None, source="agent"):
        # EVERYTHING returns 200 with the same generic body — a soft-404 server.
        return _resp(200, generic)

    with patch.object(cd, "_send", new=AsyncMock(side_effect=fake_send)), \
         patch.object(cd, "_client"):
        hits = _run(cd.run_content_discovery("https://in.scope/", {}, settings))

    assert hits == [], "soft-404 responses must not be reported as hits"


def test_dead_host_short_circuits(monkeypatch):
    settings = MagicMock()
    settings.is_in_scope.return_value = True
    monkeypatch.setattr(cd, "is_host_dead", lambda h: True)  # host already dead
    send = AsyncMock(return_value=_resp(200))
    with patch.object(cd, "_send", new=send), patch.object(cd, "_client"):
        hits = _run(cd.run_content_discovery("https://in.scope/", {}, settings))
    # baseline probe may be attempted once; but the candidate loop must break immediately.
    assert hits == []

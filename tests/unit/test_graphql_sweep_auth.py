"""Regression tests for graphql_sweep auth resolution on browser-preferred hosts.

The breadth-sweep tool used to read ONLY the global cookie jar, so on origin-gated /
browser-preferred hosts (where a login profile's cookies live in a NAMED session, not the
global jar) it sent no usable auth and every operation 401/403'd — the sweep aborted with
"all canary probes auth_blocked". These assert that a probe's OUTGOING request now carries the
named-session cookie (and a resolved Bearer), with the global-jar fallback intact for
non-copilot callers. No live network: httpx.AsyncClient is faked.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import dast.tools.graphql_sweep_tools as sweep

_URL = "https://app.example.com/graphql"
_HOST = "app.example.com"
_SCHEMA = {
    "introspected": True,
    "queries": {"me": {"args": [], "return_type": ""}},
    "mutations": {},
}


class _FakeStore:
    """Store whose GLOBAL jar is empty but whose NAMED session has the real cookies."""

    def __init__(self, named: Dict[str, List[dict]] | None = None,
                 global_jar: Dict[str, List[dict]] | None = None) -> None:
        self._named = named or {}
        self._global = global_jar or {}

    def get_named_session_cookies_for_host(self, session_name: str, host: str) -> list:
        return self._named.get(host, [])

    def get_cookies_for_host(self, host: str) -> list:
        return self._global.get(host, [])


class _FakeResponse:
    status_code = 200

    def json(self) -> Dict[str, Any]:
        return {"data": {"me": {"id": 1}}}


class _FakeClient:
    """Captures the headers of the one POST the probe makes."""

    captured: Dict[str, str] = {}

    def __init__(self, *a, **k) -> None:
        pass

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *a) -> bool:
        return False

    async def post(self, url: str, *, content: bytes, headers: Dict[str, str]) -> _FakeResponse:
        type(self).captured = dict(headers)
        return _FakeResponse()


def _run_probe(ctx) -> Dict[str, Any]:
    from dast.graphql.query_builder import build_operation  # noqa: F401 (ensure importable)

    semaphore = asyncio.Semaphore(1)
    return asyncio.run(
        sweep._probe_operation(ctx, _URL, _SCHEMA, "query", "me", semaphore)
    )


@pytest.fixture(autouse=True)
def _patch_httpx(monkeypatch):
    import httpx

    _FakeClient.captured = {}
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    # Keep the query builder deterministic / schema-agnostic.
    import dast.graphql.query_builder as qb
    monkeypatch.setattr(qb, "build_operation", lambda schema, kind, name: {
        "query": "query Me { me { id } }", "variables": {}, "operation_name": "Me",
    })


def test_sweep_uses_named_session_cookies_when_global_jar_empty():
    store = _FakeStore(named={_HOST: [{"name": "sess", "value": "NAMED_COOKIE"}]},
                       global_jar={_HOST: []})
    # A copilot ctx: _session carries a session_name, so the NAMED session is the source.
    ctx = SimpleNamespace(
        store=store,
        _session=SimpleNamespace(session_name="profile-1"),
        source_label="copilot",
        browser=None,
        proxy_url="http://127.0.0.1:8080",
        is_in_scope=lambda url: True,
    )

    result = _run_probe(ctx)

    assert result["classification"] == "data_returned"
    cookie = _FakeClient.captured.get("Cookie", "")
    assert "sess=NAMED_COOKIE" in cookie, f"named-session cookie not attached: {_FakeClient.captured!r}"


def test_sweep_attaches_resolved_bearer():
    store = _FakeStore(named={_HOST: [{"name": "sess", "value": "NAMED_COOKIE"}]})

    async def _ensure_fresh_bearer(store, host, path, browser=None):
        return {"token": "TOK123"}  # no exp -> fresh

    ctx = SimpleNamespace(
        store=store,
        _session=SimpleNamespace(session_name="profile-1",
                                 _ensure_fresh_bearer=_ensure_fresh_bearer),
        source_label="copilot",
        browser=None,
        proxy_url="http://127.0.0.1:8080",
        is_in_scope=lambda url: True,
    )

    _run_probe(ctx)

    assert _FakeClient.captured.get("Authorization") == "Bearer TOK123"


def test_sweep_falls_back_to_global_jar_for_non_copilot_callers():
    # No _session / session_name (MCP or raw agent caller) -> global jar is the source.
    store = _FakeStore(named={_HOST: [{"name": "sess", "value": "NAMED_COOKIE"}]},
                       global_jar={_HOST: [{"name": "glob", "value": "GLOBAL_COOKIE"}]})
    ctx = SimpleNamespace(
        store=store,
        _session=None,
        source_label="agent",
        browser=None,
        proxy_url="http://127.0.0.1:8080",
        is_in_scope=lambda url: True,
    )

    _run_probe(ctx)

    cookie = _FakeClient.captured.get("Cookie", "")
    assert "glob=GLOBAL_COOKIE" in cookie
    assert "NAMED_COOKIE" not in cookie

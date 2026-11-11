"""Tests for the prime_session tool — auto-minting a sub-app session cookie through the proxy.

Uses only the generic PLACEHOLDER sub-app map seeded by tests/unit/conftest.py, where 'beta'
declares a prime descriptor ({endpoint:/beta/session, cookie:_beta_session}) and 'alpha' does not.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import dast.tools.prime_tools as pt
from dast.tools.prime_tools import _prime_session


class _Resp:
    def __init__(self, status=200):
        self.status_code = status


class _Client:
    """Fake httpx.AsyncClient. Records the request; on response, simulates the proxy ingesting
    the Set-Cookie into the shared jar (store.cookies) when *value* is not None."""

    def __init__(self, store, host, cookie, value, status=200):
        self._store, self._host, self._cookie = store, host, cookie
        self._value, self._status = value, status
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None):
        self.calls.append((method, url, headers or {}))
        if self._value is not None:
            self._store.cookies.setdefault(self._host, {})[self._cookie] = self._value
        return _Resp(self._status)


class _Store:
    def __init__(self):
        self.cookies = {}  # host -> {name: value}

    def get_cookies_for_host(self, host):
        return [{"name": n, "value": v} for n, v in self.cookies.get(host, {}).items()]


def _engine(bearer=None):
    tokens = {}
    if bearer:
        tokens = {"app.example.com": {"by_app": {"beta": {"token": bearer}}}}
    return SimpleNamespace(_session_cookies={}, _bearer_tokens=tokens, session_name=None)


def _ctx(store, engine, in_scope=True):
    return SimpleNamespace(is_in_scope=lambda u: in_scope, proxy_url="http://127.0.0.1:8080",
                           store=store, _session=engine)


@pytest.mark.asyncio
async def test_prime_session_mints_and_seeds(monkeypatch):
    store = _Store()
    engine = _engine(bearer="B.T.K")
    client = _Client(store, "app.example.com", "_beta_session", "COOKIEVAL")
    monkeypatch.setattr(pt.httpx, "AsyncClient", lambda **kw: client)

    r = await _prime_session(_ctx(store, engine), {"host": "app.example.com", "app": "beta"})

    assert r["ok"] and r["primed"] and r["verified"]
    assert r["cookie"] == "_beta_session"
    method, url, headers = client.calls[0]
    assert method == "GET" and url == "https://app.example.com/beta/session"
    assert headers["Authorization"] == "Bearer B.T.K"          # rode the app Bearer
    # seeded the engine overlay so the scoped _apply_session_auth path carries it on retry
    assert engine._session_cookies["_beta_session"] == "COOKIEVAL"


@pytest.mark.asyncio
async def test_prime_session_noop_when_already_present(monkeypatch):
    store = _Store()
    store.cookies["app.example.com"] = {"_beta_session": "EXISTING"}
    engine = _engine(bearer="B.T.K")
    calls = {"n": 0}

    class _NoCall:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, *a, **k):
            calls["n"] += 1
            return _Resp(200)

    monkeypatch.setattr(pt.httpx, "AsyncClient", lambda **kw: _NoCall())
    r = await _prime_session(_ctx(store, engine), {"host": "app.example.com", "app": "beta"})

    assert r["ok"] and r["primed"] is False and r["verified"]
    assert calls["n"] == 0                                     # idempotent: no request issued


@pytest.mark.asyncio
async def test_prime_session_no_bearer_returns_clean_error():
    store = _Store()
    r = await _prime_session(_ctx(store, _engine(bearer=None)),
                             {"host": "app.example.com", "app": "beta"})
    assert r["ok"] is False and "Bearer" in r["error"]


@pytest.mark.asyncio
async def test_prime_session_app_without_prime_lists_primeable():
    store = _Store()
    r = await _prime_session(_ctx(store, _engine()), {"host": "app.example.com", "app": "alpha"})
    assert r["ok"] is False and "no session-prime" in r["error"]
    assert "beta" in r["error"]                                # beta is primeable in the placeholder


@pytest.mark.asyncio
async def test_prime_session_endpoint_sets_no_cookie(monkeypatch):
    store = _Store()
    engine = _engine(bearer="T")
    client = _Client(store, "app.example.com", "_beta_session", value=None, status=403)
    monkeypatch.setattr(pt.httpx, "AsyncClient", lambda **kw: client)

    r = await _prime_session(_ctx(store, engine), {"host": "app.example.com", "app": "beta"})
    assert r["ok"] is False and r["verified"] is False and r["primed"] is False
    assert r["prime_status"] == 403


@pytest.mark.asyncio
async def test_prime_session_out_of_scope():
    store = _Store()
    r = await _prime_session(_ctx(store, _engine(bearer="T"), in_scope=False),
                             {"host": "app.example.com", "app": "beta"})
    assert r["ok"] is False and "out of scope" in r["error"]


@pytest.mark.asyncio
async def test_prime_session_requires_host_and_app():
    store = _Store()
    assert (await _prime_session(_ctx(store, _engine()), {"app": "beta"}))["ok"] is False
    assert (await _prime_session(_ctx(store, _engine()), {"host": "app.example.com"}))["ok"] is False

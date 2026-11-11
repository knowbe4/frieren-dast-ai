"""Tests for the prime_session tool — auto-minting a sub-app session cookie through the proxy.

Uses only the generic PLACEHOLDER sub-app map seeded by tests/unit/conftest.py, where 'beta'
declares a prime descriptor ({endpoint:/beta/session, cookie:_beta_session}) and 'alpha' does not.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import dast.tools.prime_tools as pt
from dast.tools.prime_tools import _prime_session


class _Headers:
    """Minimal httpx.Headers stand-in supporting get_list + get for set-cookie."""
    def __init__(self, set_cookies=None):
        self._sc = list(set_cookies or [])

    def get_list(self, key):
        return self._sc if key.lower() == "set-cookie" else []

    def get(self, key, default=None):
        if key.lower() == "set-cookie":
            return self._sc[0] if self._sc else default
        return default


class _Resp:
    def __init__(self, status=200, payload=None, set_cookies=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.headers = _Headers(set_cookies)

    def json(self):
        return self._payload


class _Client:
    """Fake httpx.AsyncClient. request() records the prime call and (when *value* is not None)
    returns a response whose Set-Cookie (re)issues the session cookie. get() serves an optional
    /spa/session payload for the Bearer fallback."""

    def __init__(self, store, host, cookie, value, status=200, spa_payload=None):
        self._store, self._host, self._cookie = store, host, cookie
        self._value, self._status = value, status
        self._spa_payload = spa_payload or {"user": {"attributes": {}}}
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None):
        self.calls.append(("GET", url, headers or {}))
        return _Resp(200, self._spa_payload)

    async def request(self, method, url, headers=None):
        self.calls.append((method, url, headers or {}))
        sc = [f"{self._cookie}={self._value}; Path=/"] if self._value is not None else []
        return _Resp(self._status, set_cookies=sc)


class _Store:
    def __init__(self):
        self.cookies = {}  # host -> {name: value}

    def get_cookies_for_host(self, host):
        return [{"name": n, "value": v} for n, v in self.cookies.get(host, {}).items()]

    def import_playwright_cookies(self, cookies):
        n = 0
        for c in cookies:
            dom = (c.get("domain") or "").lstrip(".").lower()
            if c.get("name") and dom:
                self.cookies.setdefault(dom, {})[c["name"]] = c.get("value", "")
                n += 1
        return n


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
async def test_prime_session_primes_even_when_cookie_name_present(monkeypatch):
    # Cookie-store frameworks set the session cookie for ANONYMOUS sessions too, so a present
    # cookie name does NOT mean authenticated — prime_session must still hit the endpoint and
    # (re)issue the authenticated session, reporting cookie_rotated when the value changes.
    store = _Store()
    store.cookies["app.example.com"] = {"_beta_session": "ANON"}
    engine = _engine(bearer="B.T.K")
    client = _Client(store, "app.example.com", "_beta_session", "AUTHED")
    monkeypatch.setattr(pt.httpx, "AsyncClient", lambda **kw: client)

    r = await _prime_session(_ctx(store, engine), {"host": "app.example.com", "app": "beta"})

    assert r["ok"] and r["primed"] and r["verified"]
    assert r["cookie_rotated"] is True                         # anon -> authenticated value
    assert any(c[1].endswith("/beta/session") for c in client.calls)   # it DID prime


@pytest.mark.asyncio
async def test_prime_session_no_bearer_returns_clean_error(monkeypatch):
    # No cached/history Bearer, and /spa/session exposes no betaJwt -> no Bearer to prime with.
    store = _Store()
    client = _Client(store, "app.example.com", "_beta_session", value=None,
                     spa_payload={"user": {"attributes": {}}})
    monkeypatch.setattr(pt.httpx, "AsyncClient", lambda **kw: client)
    r = await _prime_session(_ctx(store, _engine(bearer=None)),
                             {"host": "app.example.com", "app": "beta"})
    assert r["ok"] is False and "Bearer" in r["error"]


@pytest.mark.asyncio
async def test_prime_session_bearer_from_spa_session_fallback(monkeypatch):
    # No cached/history Bearer, but /spa/session exposes user.attributes.betaJwt -> prime with it.
    store = _Store()
    client = _Client(store, "app.example.com", "_beta_session", value="COOKIEVAL",
                     spa_payload={"user": {"attributes": {"betaJwt": "SPA.FIELD.TOKEN"}}})
    monkeypatch.setattr(pt.httpx, "AsyncClient", lambda **kw: client)
    r = await _prime_session(_ctx(store, _engine(bearer=None)),
                             {"host": "app.example.com", "app": "beta"})
    assert r["ok"] and r["primed"] and r["verified"]
    # the prime GET rode the /spa/session field token as the Bearer
    prime_call = [c for c in client.calls if c[0] == "GET" and c[1].endswith("/beta/session")][0]
    assert prime_call[2]["Authorization"] == "Bearer SPA.FIELD.TOKEN"


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

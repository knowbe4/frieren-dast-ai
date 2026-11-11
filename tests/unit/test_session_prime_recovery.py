"""Tests for CopilotSession._maybe_prime_subapp — the inline prime-on-auth-fail recovery LADDER.

When a send_request to a primeable sub-app fails not_authorized/403, the engine tries both login
mechanisms with fallback: (1) cookie prime via prime_session + retry; (2) if still failing, browser
activation (browser_navigate the nav URL) + retry. Uses the conftest placeholder map where 'beta'
(prefix /beta) declares BOTH modes and 'alpha' declares no prime.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from dast.ai.copilot.session import CopilotSession

_AUTHFAIL = {"status": 200, "body": '{"error":{"message":"not_authorized"},"data":null}'}
_OK = {"status": 200, "body": '{"data":{"__typename":"Queries"}}'}


def _session():
    s = CopilotSession("s-prime", focus_hosts=["app.example.com"])
    s._apply_session_auth = lambda ctx, args: None   # isolate from the real store
    return s


def _ctx(browser=True):
    return SimpleNamespace(browser=object()) if browser else SimpleNamespace()


def _run_tool(calls, *, prime_ok=True, send_results=None):
    """Fake run_tool. send_results feeds successive send_request retries (in order)."""
    sr = iter(send_results or [])

    async def rt(ctx, name, args):
        calls.append((name, dict(args)))
        if name == "prime_session":
            return {"ok": prime_ok, "verified": prime_ok, "primed": prime_ok,
                    "cookie": "_beta_session"}
        if name == "browser_navigate":
            return {"ok": True, "status": 200}
        if name == "send_request":
            try:
                return next(sr)
            except StopIteration:
                return dict(_OK)
        return {"ok": True}
    return rt


_ARGS = {"url": "https://app.example.com/beta/graphql", "method": "POST"}


@pytest.mark.asyncio
async def test_cookie_prime_authenticates_first():
    s = _session()
    calls = []
    out = await s._maybe_prime_subapp(_ctx(), "send_request", dict(_ARGS), _AUTHFAIL,
                                      _run_tool(calls, send_results=[_OK]))
    assert out is not None and out["body"] == _OK["body"]
    # cookie mechanism authenticated -> no browser activation attempted
    assert [c[0] for c in calls] == ["prime_session", "send_request"]


@pytest.mark.asyncio
async def test_falls_back_to_browser_activation_when_cookie_fails():
    s = _session()
    calls = []
    # cookie retry still not_authorized -> nav -> retry OK
    out = await s._maybe_prime_subapp(_ctx(browser=True), "send_request", dict(_ARGS), _AUTHFAIL,
                                      _run_tool(calls, send_results=[_AUTHFAIL, _OK]))
    assert out is not None and out["body"] == _OK["body"]
    assert [c[0] for c in calls] == ["prime_session", "send_request", "browser_navigate", "send_request"]
    # browser_navigate went to the sub-app's activation URL
    nav_call = [c for c in calls if c[0] == "browser_navigate"][0]
    assert nav_call[1]["url"] == "https://app.example.com/beta/home"


@pytest.mark.asyncio
async def test_browser_activation_only_when_no_cookie_mode(monkeypatch):
    # A sub-app whose prime declares ONLY nav (no endpoint/cookie): skip prime_session, go to nav.
    from dast.session import subapp_map
    monkeypatch.setattr(subapp_map, "prime_for_app",
                        lambda app: {"endpoint": "", "method": "", "cookie": "", "referer": "",
                                     "nav": "/beta/home"} if app == "beta" else None)
    s = _session()
    calls = []
    out = await s._maybe_prime_subapp(_ctx(browser=True), "send_request", dict(_ARGS), _AUTHFAIL,
                                      _run_tool(calls, send_results=[_OK]))
    assert out is not None and out["body"] == _OK["body"]
    assert [c[0] for c in calls] == ["browser_navigate", "send_request"]   # no prime_session


@pytest.mark.asyncio
async def test_no_browser_means_only_cookie_mechanism():
    s = _session()
    calls = []
    # cookie retry fails and there is no browser -> return the failing retry, no nav
    out = await s._maybe_prime_subapp(_ctx(browser=False), "send_request", dict(_ARGS), _AUTHFAIL,
                                      _run_tool(calls, send_results=[_AUTHFAIL]))
    assert out is not None and "not_authorized" in out["body"]
    assert [c[0] for c in calls] == ["prime_session", "send_request"]       # no browser_navigate


@pytest.mark.asyncio
async def test_both_mechanisms_fail_returns_latest_failure():
    s = _session()
    calls = []
    out = await s._maybe_prime_subapp(_ctx(browser=True), "send_request", dict(_ARGS), _AUTHFAIL,
                                      _run_tool(calls, send_results=[_AUTHFAIL, _AUTHFAIL]))
    assert out is not None and "not_authorized" in out["body"]
    assert [c[0] for c in calls] == ["prime_session", "send_request", "browser_navigate", "send_request"]


@pytest.mark.asyncio
async def test_noop_when_not_auth_fail():
    s = _session()
    calls = []
    out = await s._maybe_prime_subapp(_ctx(), "send_request", dict(_ARGS), dict(_OK),
                                      _run_tool(calls))
    assert out is None and calls == []


@pytest.mark.asyncio
async def test_noop_when_path_not_primeable():
    s = _session()
    calls = []
    for path in ("/alpha/graphql", "/other/thing"):
        args = {"url": f"https://app.example.com{path}"}
        out = await s._maybe_prime_subapp(_ctx(), "send_request", args, _AUTHFAIL, _run_tool(calls))
        assert out is None
    assert calls == []


@pytest.mark.asyncio
async def test_bounded_to_one_ladder_per_host_app():
    s = _session()
    await s._maybe_prime_subapp(_ctx(browser=True), "send_request", dict(_ARGS), _AUTHFAIL,
                                _run_tool([], send_results=[_AUTHFAIL, _AUTHFAIL]))
    calls2 = []
    out = await s._maybe_prime_subapp(_ctx(browser=True), "send_request", dict(_ARGS), _AUTHFAIL,
                                      _run_tool(calls2, send_results=[_OK]))
    assert out is None and calls2 == []       # second time: ladder already spent for (host, app)

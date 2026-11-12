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


@pytest.mark.asyncio
async def test_learned_nav_preferred_over_hardcoded():
    # A learned activation recipe for (site/host, beta) should be used by the browser-activation
    # mechanism instead of the hardcoded prime.nav ('/beta/home').
    from dast.session import activation_recipe as ar
    ar.record_activation("app.example.com", "beta", "/LEARNED/studio")
    s = _session()
    calls = []
    out = await s._maybe_prime_subapp(_ctx(browser=True), "send_request", dict(_ARGS), _AUTHFAIL,
                                      _run_tool(calls, send_results=[_AUTHFAIL, _OK]))
    assert out is not None and out["body"] == _OK["body"]
    nav_call = [c for c in calls if c[0] == "browser_navigate"][0]
    assert nav_call[1]["url"] == "https://app.example.com/LEARNED/studio"   # learned, not /beta/home


@pytest.mark.asyncio
async def test_records_activation_recipe_on_browser_success():
    # With no learned recipe, the hardcoded prime.nav is used; on a successful browser activation
    # the nav that worked is persisted as a learned recipe (reinforce/seed).
    from dast.session import activation_recipe as ar
    assert ar.activation_nav("app.example.com", "beta") is None
    s = _session()
    out = await s._maybe_prime_subapp(_ctx(browser=True), "send_request", dict(_ARGS), _AUTHFAIL,
                                      _run_tool([], send_results=[_AUTHFAIL, _OK]))
    assert out is not None and out["body"] == _OK["body"]
    assert ar.activation_nav("app.example.com", "beta") == "/beta/home"     # recorded on success


@pytest.mark.asyncio
async def test_await_subapp_bearer_returns_true_when_captured():
    # Once the SPA's authed call (Bearer on the sub-app's probe path) is in history, the bounded
    # wait returns True immediately so the retry rides the captured Bearer (no race).
    class _Store:
        def all_entries(self):
            return [{"host": "app.example.com", "path": "/beta/graphql", "source": "proxy",
                     "id": "e1", "request_headers": {"Authorization": "Bearer live.token.x"}}]
    s = _session()
    ok = await s._await_subapp_bearer(_Store(), "app.example.com", "beta", tries=3, interval=0.01)
    assert ok is True


@pytest.mark.asyncio
async def test_await_subapp_bearer_false_without_store_or_probe():
    s = _session()
    assert await s._await_subapp_bearer(None, "app.example.com", "beta", tries=2, interval=0.01) is False

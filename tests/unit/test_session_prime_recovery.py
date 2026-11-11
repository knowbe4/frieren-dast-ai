"""Tests for CopilotSession._maybe_prime_subapp — the inline prime-on-auth-fail recovery.

When a send_request to a primeable sub-app (one with a `prime` descriptor in the local sub-app
map) fails with not_authorized/403 because the session COOKIE is missing, the engine mints it once
via prime_session and re-runs the request. Uses the placeholder map from conftest where 'beta' is
primeable (prefix /beta, cookie _beta_session) and 'alpha' is not.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from dast.ai.copilot.session import CopilotSession


def _session():
    s = CopilotSession("s-prime", focus_hosts=["app.example.com"])
    # isolate: _apply_session_auth would touch a real store; stub it to a no-op.
    s._apply_session_auth = lambda ctx, args: None
    return s


def _run_tool(calls, *, prime_ok=True, rerun_status=200):
    async def rt(ctx, name, args):
        calls.append((name, dict(args)))
        if name == "prime_session":
            return {"ok": prime_ok, "verified": prime_ok, "primed": prime_ok,
                    "app": args.get("app"), "cookie": "_beta_session"}
        return {"ok": True, "status": rerun_status, "body": "{}"}
    return rt


_FAIL = {"status": 403, "body": '{"error":"not_authorized"}', "final_url": ""}


@pytest.mark.asyncio
async def test_primes_then_reruns_on_subapp_auth_fail():
    s = _session()
    calls = []
    args = {"url": "https://app.example.com/beta/graphql", "method": "POST"}
    out = await s._maybe_prime_subapp(SimpleNamespace(), "send_request", args, _FAIL,
                                      _run_tool(calls, rerun_status=200))
    assert out is not None and out["status"] == 200
    assert [c[0] for c in calls] == ["prime_session", "send_request"]
    assert calls[0][1] == {"host": "app.example.com", "app": "beta"}
    assert ("app.example.com", "beta") in s._primed_subapps


@pytest.mark.asyncio
async def test_triggers_on_200_not_authorized_body():
    s = _session()
    calls = []
    result = {"status": 200, "body": '{"error":"not_authorized"}'}
    args = {"url": "https://app.example.com/beta/graphql"}
    out = await s._maybe_prime_subapp(SimpleNamespace(), "send_request", args, result,
                                      _run_tool(calls))
    assert out is not None and calls[0][0] == "prime_session"


@pytest.mark.asyncio
async def test_noop_when_not_auth_fail():
    s = _session()
    calls = []
    result = {"status": 200, "body": '{"data":{}}'}
    args = {"url": "https://app.example.com/beta/graphql"}
    out = await s._maybe_prime_subapp(SimpleNamespace(), "send_request", args, result,
                                      _run_tool(calls))
    assert out is None and calls == []


@pytest.mark.asyncio
async def test_noop_when_path_not_a_primeable_subapp():
    s = _session()
    calls = []
    # /alpha is a sub-app but has NO prime descriptor; /other is not a sub-app at all.
    for path in ("/alpha/graphql", "/other/thing"):
        args = {"url": f"https://app.example.com{path}"}
        out = await s._maybe_prime_subapp(SimpleNamespace(), "send_request", args, _FAIL,
                                          _run_tool(calls))
        assert out is None
    assert calls == []


@pytest.mark.asyncio
async def test_primes_even_when_cookie_name_already_present():
    # A session cookie name present does NOT mean authenticated (anon sessions set it too);
    # a not_authorized response must still trigger priming.
    s = _session()
    s._session_cookies["_beta_session"] = "ANON"
    calls = []
    args = {"url": "https://app.example.com/beta/graphql"}
    out = await s._maybe_prime_subapp(SimpleNamespace(), "send_request", args, _FAIL,
                                      _run_tool(calls, rerun_status=200))
    assert out is not None and out["status"] == 200
    assert [c[0] for c in calls] == ["prime_session", "send_request"]


@pytest.mark.asyncio
async def test_no_rerun_when_prime_fails():
    s = _session()
    calls = []
    args = {"url": "https://app.example.com/beta/graphql"}
    out = await s._maybe_prime_subapp(SimpleNamespace(), "send_request", args, _FAIL,
                                      _run_tool(calls, prime_ok=False))
    assert out is None
    assert [c[0] for c in calls] == ["prime_session"]      # tried once, did NOT re-run


@pytest.mark.asyncio
async def test_bounded_to_one_attempt_per_host_app():
    s = _session()
    args = {"url": "https://app.example.com/beta/graphql"}
    calls1 = []
    await s._maybe_prime_subapp(SimpleNamespace(), "send_request", args, _FAIL,
                                _run_tool(calls1, prime_ok=False))
    calls2 = []
    out = await s._maybe_prime_subapp(SimpleNamespace(), "send_request", args, _FAIL,
                                      _run_tool(calls2))
    assert out is None and calls2 == []                    # second time: no prime attempt

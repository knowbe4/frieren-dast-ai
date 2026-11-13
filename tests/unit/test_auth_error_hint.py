"""Auth-error classification + sub-app recovery for browser_fetch.

- A: ``_auth_error_hint`` returns a ``[AUTH]`` guidance note on 401/403/auth-body
  responses so the model classifies them as auth (not WAF) errors.
- B: ``_maybe_prime_subapp`` fires for ``browser_fetch`` (not just ``send_request``)
  and retries via ``send_request`` after priming.
- Regression: existing ``send_request`` 403 recovery is unchanged.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import patch

import pytest

from dast.ai.copilot.session import CopilotSession, _auth_error_hint


# ── A: _auth_error_hint ─────────────────────────────────────────────────────


def test_auth_error_hint_401():
    result = {"ok": True, "status": 401, "body": "Unauthorized"}
    hint = _auth_error_hint(result, {"url": "https://app.target.test/api/data"})
    assert hint.startswith("[AUTH]")
    assert "401" in hint
    assert "authentication error" in hint


def test_auth_error_hint_403():
    result = {"ok": True, "status": 403, "body": "Forbidden"}
    hint = _auth_error_hint(result, {"url": "https://app.target.test/api/data"})
    assert hint.startswith("[AUTH]")
    assert "403" in hint


def test_auth_error_hint_body_not_authenticated():
    result = {"ok": True, "status": 200, "body": '{"detail":"Not authenticated"}'}
    hint = _auth_error_hint(result, {"url": "https://app.target.test/reports/graphql"})
    assert hint.startswith("[AUTH]")
    assert "not a WAF" in hint


def test_auth_error_hint_body_not_authorized():
    result = {"ok": True, "status": 200, "body": '{"error":"not_authorized"}'}
    hint = _auth_error_hint(result, {"url": "https://app.target.test/store/graphql"})
    assert hint.startswith("[AUTH]")


def test_auth_error_hint_clean_200():
    result = {"ok": True, "status": 200, "body": '{"data":{"users":[]}}'  }
    hint = _auth_error_hint(result, {"url": "https://app.target.test/api/data"})
    assert hint == ""


def test_auth_error_hint_429_rate_limit():
    result = {"ok": True, "status": 429, "body": "Too Many Requests"}
    hint = _auth_error_hint(result, {"url": "https://app.target.test/api/data"})
    assert hint == ""


def test_auth_error_hint_503_not_auth():
    result = {"ok": True, "status": 503, "body": "Service Unavailable"}
    hint = _auth_error_hint(result, {"url": "https://app.target.test/api/data"})
    assert hint == ""


def test_auth_error_hint_suggests_get_app_token():
    result = {"ok": True, "status": 403, "body": "Forbidden"}
    hint = _auth_error_hint(result, {"url": "https://app.target.test/reports/graphql"})
    assert "get_app_token" in hint
    assert "send_request" in hint


# ── B: _browser_fetch_as_send_request ────────────────────────────────────────


def test_browser_fetch_as_send_request_basic():
    args = {
        "url": "https://app.target.test/reports/graphql",
        "method": "POST",
        "body": '{"query":"{ __schema { queryType { name } } }"}',
        "headers": {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Authorization": "Bearer stale-token",
            "Cookie": "session=abc",
        },
    }
    out = CopilotSession._browser_fetch_as_send_request(args)
    assert out["url"] == args["url"]
    assert out["method"] == "POST"
    assert out["body"] == args["body"]
    assert "Authorization" not in out.get("headers", {})
    assert "Cookie" not in out.get("headers", {})
    assert out["headers"]["Content-Type"] == "application/json"
    assert out["headers"]["X-Requested-With"] == "XMLHttpRequest"


def test_browser_fetch_as_send_request_get_no_body():
    args = {"url": "https://app.target.test/spa/session"}
    out = CopilotSession._browser_fetch_as_send_request(args)
    assert out["url"] == args["url"]
    assert "method" not in out
    assert "body" not in out


# ── B: _maybe_prime_subapp fires for browser_fetch ───────────────────────────


@pytest.mark.asyncio
async def test_prime_subapp_fires_for_browser_fetch():
    """browser_fetch 403 on a sub-app path triggers priming + retry via send_request."""
    session = CopilotSession(
        session_id="test-auth",
        focus_hosts=["app.target.test"],
    )

    browser_fetch_result = {"ok": True, "status": 403, "body": "not_authorized"}
    send_request_result = {"ok": True, "status": 200, "body": '{"data":{}}'}

    call_log: list = []

    async def fake_run_tool(ctx: Any, name: str, args: Dict[str, Any]) -> dict:
        call_log.append(name)
        if name == "prime_session":
            return {"ok": True, "verified": True}
        if name == "send_request":
            return send_request_result
        return browser_fetch_result

    ctx = SimpleNamespace(store=None, browser=None)

    with patch("dast.session.subapp_map.prime_for_app",
               return_value={"endpoint": "/reports/session", "cookie": "_reports_session"}), \
         patch("dast.session.site_map.site_for_host", return_value="test"), \
         patch("dast.session.auth_provider.subapp_for_path", return_value="reports"), \
         patch("dast.session.activation_recipe.activation_nav", return_value=None), \
         patch("dast.session.activation_recipe.learn_from_history", return_value=None), \
         patch("dast.proxy.auth_headers.extract_auth_headers", return_value={}):
        result = await session._maybe_prime_subapp(
            ctx, "browser_fetch",
            {"url": "https://app.target.test/reports/graphql", "method": "POST"},
            browser_fetch_result,
            fake_run_tool,
        )

    assert result is not None
    assert result["status"] == 200
    assert "prime_session" in call_log
    assert "send_request" in call_log
    assert "browser_fetch" not in call_log[1:]


@pytest.mark.asyncio
async def test_prime_subapp_still_works_for_send_request():
    """Regression: send_request 403 recovery retries as send_request (unchanged)."""
    session = CopilotSession(
        session_id="test-auth",
        focus_hosts=["app.target.test"],
    )

    fail_result = {"ok": True, "status": 403, "body": "not_authorized"}
    ok_result = {"ok": True, "status": 200, "body": '{"data":{}}'}

    call_log: list = []

    async def fake_run_tool(ctx: Any, name: str, args: Dict[str, Any]) -> dict:
        call_log.append(name)
        if name == "prime_session":
            return {"ok": True, "verified": True}
        if name == "send_request" and len([c for c in call_log if c == "send_request"]) > 0:
            return ok_result
        return fail_result

    ctx = SimpleNamespace(store=None, browser=None)

    with patch("dast.session.subapp_map.prime_for_app",
               return_value={"endpoint": "/reports/session", "cookie": "_reports_session"}), \
         patch("dast.session.site_map.site_for_host", return_value="test"), \
         patch("dast.session.auth_provider.subapp_for_path", return_value="reports"), \
         patch("dast.session.activation_recipe.activation_nav", return_value=None), \
         patch("dast.session.activation_recipe.learn_from_history", return_value=None), \
         patch("dast.proxy.auth_headers.extract_auth_headers", return_value={}):
        result = await session._maybe_prime_subapp(
            ctx, "send_request",
            {"url": "https://app.target.test/reports/graphql", "method": "POST"},
            fail_result,
            fake_run_tool,
        )

    assert result is not None
    assert "prime_session" in call_log
    assert "send_request" in call_log


@pytest.mark.asyncio
async def test_prime_subapp_skips_non_authfail():
    """A clean 200 from browser_fetch does not trigger priming."""
    session = CopilotSession(
        session_id="test-auth",
        focus_hosts=["app.target.test"],
    )

    ok_result = {"ok": True, "status": 200, "body": '{"data":{}}'}
    call_log: list = []

    async def fake_run_tool(ctx: Any, name: str, args: Dict[str, Any]) -> dict:
        call_log.append(name)
        return ok_result

    ctx = SimpleNamespace(store=None, browser=None)

    with patch("dast.session.subapp_map.prime_for_app",
               return_value={"endpoint": "/x", "cookie": "_c"}), \
         patch("dast.session.site_map.site_for_host", return_value="test"), \
         patch("dast.session.auth_provider.subapp_for_path", return_value="reports"), \
         patch("dast.session.activation_recipe.activation_nav", return_value=None), \
         patch("dast.session.activation_recipe.learn_from_history", return_value=None):
        result = await session._maybe_prime_subapp(
            ctx, "browser_fetch",
            {"url": "https://app.target.test/reports/graphql"},
            ok_result,
            fake_run_tool,
        )

    assert result is None
    assert "prime_session" not in call_log

"""Unit tests for the LoginStrategy seam (dast/browser/login_strategies/base.py):
the shared LoginResult/LoginContext types and the serialization contract the HTTP route
and agent tools depend on."""

from __future__ import annotations

import pytest

from dast.browser.login_strategies.base import (
    LoginContext,
    LoginResult,
    current_url,
    looks_authenticated,
)


def test_login_result_defaults():
    r = LoginResult(ok=True, engine="deterministic", url="https://app.example/dash")
    assert r.llm_steps == 0 and r.actions == [] and r.error == ""
    # Internal driver signals default to the non-committal values.
    assert r.terminal is False and r.reachable is None and r.endpoint == ""


def test_to_dict_keys_are_the_public_contract():
    # The HTTP route and tools return to_dict() verbatim — the internal signals
    # (terminal/reachable/endpoint) must NOT leak into it.
    r = LoginResult(ok=False, engine="llm", url="u", llm_steps=3,
                    actions=[{"action": "fill"}], error="x",
                    terminal=True, reachable=False, endpoint="/api/login")
    assert set(r.to_dict()) == {"ok", "engine", "url", "llm_steps", "actions", "error"}
    assert r.to_dict() == {"ok": False, "engine": "llm", "url": "u", "llm_steps": 3,
                           "actions": [{"action": "fill"}], "error": "x"}


def test_login_cascade_result_is_the_same_type():
    # Back-compat: every `from dast.browser.login_cascade import LoginCascadeResult` caller
    # still works because it is an alias of LoginResult.
    from dast.browser.login_cascade import LoginCascadeResult
    assert LoginCascadeResult is LoginResult


def test_login_context_defaults():
    ctx = LoginContext(browser=object(), url="https://app.example/login",
                       email="a@b.c", password="pw")
    assert ctx.prior == [] and ctx.store is None and ctx.session is None
    assert ctx.max_llm_steps == 8 and ctx.flow is None and ctx.proxy_port is None


def test_looks_authenticated_suffix_and_heuristic():
    # Explicit success suffix is ground truth.
    assert looks_authenticated("https://app.example/dashboard", "/dashboard") is True
    assert looks_authenticated("https://app.example/login", "/dashboard") is False
    # Heuristic: a login/SSO URL is not authenticated; an app URL is.
    assert looks_authenticated("https://app.example/login", None) is False
    assert looks_authenticated("https://okta.com/authorize", None) is False
    assert looks_authenticated("https://app.example/home", None) is True


@pytest.mark.asyncio
async def test_current_url_reads_snapshot_and_degrades():
    class _B:
        async def snapshot(self):
            return {"url": "https://app.example/x"}
    assert await current_url(_B()) == "https://app.example/x"

    class _Broken:
        async def snapshot(self):
            raise RuntimeError("no page")
    assert await current_url(_Broken()) == ""

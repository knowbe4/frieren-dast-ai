"""Unit tests for FormStrategy (dast/browser/login_strategies/form.py) — the deterministic
form-fill wrapper. The reachable/terminal classification must reproduce the cascade's old
`_form_unreachable` gate exactly, so the spa_api fall-through keeps firing only when the form
could not be reached (incl. the raise path)."""

from __future__ import annotations

import pytest

from dast.browser.login_strategies.base import LoginContext, LoginResult
from dast.browser.login_strategies.form import FormStrategy


class _Browser:
    """A browser whose login() returns a scripted dict, or raises when `exc` is set."""

    def __init__(self, result=None, exc=None):
        self._result = result
        self._exc = exc

    async def login(self, url, email, password):
        if self._exc is not None:
            raise self._exc
        return self._result


def _ctx(browser, *, success_url_suffix="/dashboard"):
    return LoginContext(browser=browser, url="https://app.x/login", email="a@x.com",
                        password="pw", success_url_suffix=success_url_suffix)


@pytest.mark.asyncio
async def test_form_success_is_reachable_ok():
    b = _Browser({"logged_in": True, "url": "https://app.x/dashboard"})
    r = await FormStrategy().attempt(_ctx(b))
    assert isinstance(r, LoginResult)
    assert r.ok is True and r.engine == "deterministic" and r.reachable is True
    assert r.terminal is False


@pytest.mark.asyncio
async def test_form_mfa_is_terminal():
    b = _Browser({"logged_in": False, "mfa_required": True, "url": "https://app.x/mfa"})
    r = await FormStrategy().attempt(_ctx(b))
    assert r.ok is False and r.terminal is True and r.error == "mfa_required"


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [
    "no email field found",
    "no password field found after submit",
    "no submit button actionable",   # substring match on "no submit button"
])
async def test_form_unreachable_errors_set_reachable_false(error):
    b = _Browser({"logged_in": False, "url": "https://app.x/login", "error": error})
    r = await FormStrategy().attempt(_ctx(b))
    assert r.ok is False and r.reachable is False   # -> cascade falls through to spa_api


@pytest.mark.asyncio
async def test_form_reached_but_failed_is_reachable_true():
    # A reached form that rejected the credentials stays reachable -> left to the LLM, not spa_api.
    b = _Browser({"logged_in": False, "url": "https://app.x/login", "error": "invalid credentials"})
    r = await FormStrategy().attempt(_ctx(b))
    assert r.ok is False and r.reachable is True


@pytest.mark.asyncio
async def test_form_raise_is_unreachable():
    b = _Browser(exc=RuntimeError("submit never actionable"))
    r = await FormStrategy().attempt(_ctx(b))
    assert r.ok is False and r.reachable is False
    assert "form login raised" in r.error


@pytest.mark.asyncio
async def test_form_logged_in_but_still_on_login_url_is_not_ok():
    # logged_in=True but the URL is still a login page (suffix mismatch) -> not authenticated.
    b = _Browser({"logged_in": True, "url": "https://app.x/login"})
    r = await FormStrategy().attempt(_ctx(b))
    assert r.ok is False and r.reachable is True

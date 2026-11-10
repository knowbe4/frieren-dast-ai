"""Tests for the browser_login_adaptive placeholder-credential guard.

A planner that lacks the real password must never have a stand-in like ``<UNKNOWN>``
forwarded to a live login — that is noise at best and an account lockout at worst. The
tool refuses obvious placeholders before any network call.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import dast.browser.login_cascade as login_cascade
from dast.tools.login_tools import _adaptive_login, _looks_like_placeholder


@pytest.mark.parametrize("value", [
    "<UNKNOWN>", "<your_password>", "<email>", "unknown", "UNKNOWN", "REDACTED",
    "changeme", "placeholder", "your_password", "n/a", "TODO",
])
def test_placeholder_values_detected(value: str) -> None:
    assert _looks_like_placeholder(value) is True


@pytest.mark.parametrize("value", [
    "1234password1234", "luanp@gsec.kb4.it", "hunter2", "", "correct horse battery",
    "p4ssw0rd!", "admin",
    # A real password with a stray 1-char bracket is NOT a placeholder (precision).
    "P@ss<w>ord",
])
def test_real_values_not_flagged(value: str) -> None:
    assert _looks_like_placeholder(value) is False


@pytest.mark.asyncio
async def test_adaptive_login_refuses_placeholder_password(monkeypatch) -> None:
    called = {"cascade": False}

    async def _boom(*a, **k):  # must never run for a placeholder credential
        called["cascade"] = True
        raise AssertionError("adaptive_login cascade must not be called")

    monkeypatch.setattr(login_cascade, "adaptive_login", _boom)
    ctx = SimpleNamespace(browser=object(), is_in_scope=lambda u: True,
                          store=None, _session=None)
    result = await _adaptive_login(ctx, {
        "url": "https://app.example.com/login",
        "email": "user@example.com",
        "password": "<UNKNOWN>",
    })
    assert result["ok"] is False
    assert "placeholder" in result["error"].lower()
    assert called["cascade"] is False


@pytest.mark.asyncio
async def test_adaptive_login_refuses_placeholder_email(monkeypatch) -> None:
    async def _boom(*a, **k):
        raise AssertionError("cascade must not be called")

    monkeypatch.setattr(login_cascade, "adaptive_login", _boom)
    ctx = SimpleNamespace(browser=object(), is_in_scope=lambda u: True,
                          store=None, _session=None)
    result = await _adaptive_login(ctx, {
        "url": "https://app.example.com/login",
        "email": "<your_email>",
        "password": "realpassword123",
    })
    assert result["ok"] is False
    assert "placeholder" in result["error"].lower()

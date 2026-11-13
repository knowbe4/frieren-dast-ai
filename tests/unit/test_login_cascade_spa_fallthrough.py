"""adaptive_login must fall through to the SPA JSON-API strategy on ANY non-MFA
deterministic failure — including when AgentBrowser.login RAISES (e.g. a disabled
submit button times out). Regression: the fallback used to be gated on three
"form unreachable" error strings, so a raised/other form failure skipped SPA and the
login failed. Token-free: a fake browser + a monkeypatched spa_api.attempt.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from dast.browser import login_cascade
from dast.browser.login_strategies import spa_api


class _FakeBrowser:
    def __init__(self, *, login_result: Dict[str, Any] | None = None,
                 login_raises: bool = False) -> None:
        self._login_result = login_result or {}
        self._login_raises = login_raises
        self.login_called = 0

    async def login(self, url: str, email: str, password: str, totp_secret=None) -> Dict[str, Any]:
        self.login_called += 1
        if self._login_raises:
            raise RuntimeError("Locator.click: Timeout 30000ms exceeded (disabled button)")
        return self._login_result


def _install_spa(monkeypatch, result: Dict[str, Any]):
    calls = []

    async def fake_attempt(browser, url, email, password, **kwargs):
        calls.append(url)
        return result

    monkeypatch.setattr(spa_api, "attempt", fake_attempt)
    return calls


@pytest.mark.asyncio
async def test_spa_fallthrough_when_form_login_raises(monkeypatch):
    calls = _install_spa(monkeypatch, {"ok": True, "logged_in": True,
                                       "engine": "spa_api", "url": "https://app.example.com/"})
    browser = _FakeBrowser(login_raises=True)
    result = await login_cascade.adaptive_login(
        browser, "https://app.example.com/login", "u@example.com", "pw")
    assert result.ok is True and result.engine == "spa_api"
    assert calls == ["https://app.example.com/login"]  # SPA was attempted despite the raise


@pytest.mark.asyncio
async def test_spa_fallthrough_on_disabled_submit(monkeypatch):
    # A disabled submit button now yields "no submit button actionable" (not a raise),
    # which matches the form-unreachable gate -> SPA is attempted.
    calls = _install_spa(monkeypatch, {"ok": True, "logged_in": True,
                                       "engine": "spa_api", "url": "https://app.example.com/"})
    browser = _FakeBrowser(login_result={"logged_in": False, "url": "https://app.example.com/login",
                                          "error": "no submit button actionable after email"})
    result = await login_cascade.adaptive_login(
        browser, "https://app.example.com/login", "u@example.com", "pw")
    assert result.ok is True and result.engine == "spa_api"
    assert calls == ["https://app.example.com/login"]


@pytest.mark.asyncio
async def test_mfa_does_not_attempt_spa(monkeypatch):
    calls = _install_spa(monkeypatch, {"ok": True, "logged_in": True, "engine": "spa_api"})
    browser = _FakeBrowser(login_result={"logged_in": False, "mfa_required": True,
                                          "url": "https://app.example.com/mfa"})
    result = await login_cascade.adaptive_login(
        browser, "https://app.example.com/login", "u@example.com", "pw")
    assert result.ok is False and result.error == "mfa_required"
    assert calls == []  # MFA is a human wall — SPA must NOT be attempted

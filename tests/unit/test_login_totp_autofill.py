"""Unit test for AgentBrowser._try_totp_autofill — the MFA OTP auto-fill path.

Uses a fake Playwright page so no browser is launched. Verifies that a valid seed
produces a filled+submitted code and that leaving the MFA wall reports success,
while the field value equals a real pyotp code (never a logged/hardcoded value).
"""

from __future__ import annotations

import pyotp
import pytest

from dast.browser.agent_browser import AgentBrowser

_SEED = "JBSWY3DPEHPK3PXP"
_MFA_URL = "https://identity.example.com/u/mfa-otp-challenge?state=abc"
_DONE_URL = "https://app.example.com/dashboard"


class _FakeField:
    def __init__(self):
        self.value = None

    async def is_visible(self):
        return True

    async def fill(self, v):
        self.value = v

    async def press(self, _key):
        pass


class _FakeLocator:
    def __init__(self, field, count=1):
        self._field = field
        self._count = count

    async def count(self):
        return self._count

    @property
    def first(self):
        return self._field


class _NavCtx:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakePage:
    def __init__(self, field, on_submit):
        self._field = field
        self._on_submit = on_submit
        self.url = _MFA_URL

    def locator(self, sel):
        # Only the OTP selectors match; everything else is absent.
        if "code" in sel or "one-time-code" in sel or "otp" in sel \
                or "numeric" in sel or "tel" in sel or "totp" in sel or "token" in sel:
            return _FakeLocator(self._field)
        return _FakeLocator(self._field, count=0)

    async def wait_for_timeout(self, _ms):
        pass

    async def wait_for_load_state(self, *_a, **_k):
        pass

    def expect_navigation(self, **_k):
        return _NavCtx()


class _FakeSubmit:
    def __init__(self, page):
        self._page = page

    async def click(self):
        # Simulate the server accepting the OTP and redirecting off the MFA wall.
        self._page.url = _DONE_URL


@pytest.mark.asyncio
async def test_totp_autofill_fills_valid_code_and_detects_success(monkeypatch):
    field = _FakeField()
    page = _FakePage(field, on_submit=None)
    browser = AgentBrowser(headless=True)

    async def _fake_find_submit(_page):
        return _FakeSubmit(page)

    monkeypatch.setattr(browser, "_find_submit", _fake_find_submit)

    accepted = await browser._try_totp_autofill(page, _SEED)

    assert accepted is True
    assert page.url == _DONE_URL
    # The filled value is a real, currently-valid TOTP code for the seed.
    assert field.value and pyotp.TOTP(_SEED).verify(field.value)


@pytest.mark.asyncio
async def test_totp_autofill_reports_failure_when_still_on_mfa(monkeypatch):
    field = _FakeField()
    page = _FakePage(field, on_submit=None)
    browser = AgentBrowser(headless=True)

    async def _fake_find_submit(_page):
        class _NoOpSubmit:
            async def click(self):
                pass  # code rejected: stays on the MFA wall
        return _NoOpSubmit()

    monkeypatch.setattr(browser, "_find_submit", _fake_find_submit)

    accepted = await browser._try_totp_autofill(page, _SEED)

    assert accepted is False
    assert page.url == _MFA_URL

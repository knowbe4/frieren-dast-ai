"""Unit tests for the stale-saved-session self-heal.

- session_is_provisioned classifies guest vs real vs unknown.
- activate_login_profile re-logs in from the saved credential when the reused session is
  stale/guest, keeps a valid one, and leaves a cookie-only profile (no creds) untouched.
"""

from __future__ import annotations

import pytest

from dast.session.account_state import session_is_provisioned


def test_session_is_provisioned_classifies():
    assert session_is_provisioned({"account": {"id": -1}}) is False
    assert session_is_provisioned({"guest": True}) is False
    assert session_is_provisioned({"account": {"id": 10001}}) is True
    assert session_is_provisioned({"user": {"account_id": 601738}}) is True
    assert session_is_provisioned({"something": "else"}) is None
    assert session_is_provisioned("not a dict") is None


class _Cred:
    def __init__(self, username="u@x", secret="pw"):
        self.username = username
        self.secret = secret


class _Profile:
    def __init__(self, slug="p", creds=True, saved_cookies=True):
        self.slug = slug
        self.name = slug
        self.auth_url = "https://app.example.com/login" if creds else ""
        self.credentials = [_Cred()] if creds else []
        self.privilege_level = ""
        self.saved_session = {"cookies": [{"name": "sid", "value": "x", "domain": "app.example.com"}]} \
            if saved_cookies else {}


class _Store:
    def save_named_session_from_playwright(self, **k):
        return None
    def import_playwright_cookies(self, cookies):
        return len(cookies)


class _Browser:
    def __init__(self):
        self.resynced = False
    async def resync_cookies(self):
        self.resynced = True
        return 1


class _Ctx:
    def __init__(self, store, browser):
        self.store = store
        self.browser = browser
        self._session = None


@pytest.mark.asyncio
async def test_activate_relogins_on_stale_guest(monkeypatch):
    import dast.tools.session_tools as st

    # The handler imports load_profile from the store module locally — patch it there.
    import dast.profiles.store as store_mod
    monkeypatch.setattr(store_mod, "load_profile", lambda slug: _Profile())

    # The reused session is guest.
    async def _guest(browser, base_url):
        return False
    monkeypatch.setattr(st, "_login_profile_with_credentials",
                        _mk_async_return({"ok": True, "slug": "p", "logged_in": True,
                                          "_relogged": True}))
    import dast.session.account_state as acct
    monkeypatch.setattr(acct, "session_is_authenticated", _guest)

    ctx = _Ctx(_Store(), _Browser())
    result = await st._activate_login_profile(ctx, {"slug": "p"})
    assert result.get("_relogged") is True  # fell through to fresh credential login
    assert ctx.browser.resynced is True


@pytest.mark.asyncio
async def test_activate_keeps_valid_session(monkeypatch):
    import dast.tools.session_tools as st
    import dast.profiles.store as store_mod
    monkeypatch.setattr(store_mod, "load_profile", lambda slug: _Profile())

    async def _real(browser, base_url):
        return True
    import dast.session.account_state as acct
    monkeypatch.setattr(acct, "session_is_authenticated", _real)
    # If it wrongly re-logs in, this sentinel would show up.
    monkeypatch.setattr(st, "_login_profile_with_credentials",
                        _mk_async_return({"_relogged": True}))

    ctx = _Ctx(_Store(), _Browser())
    result = await st._activate_login_profile(ctx, {"slug": "p"})
    assert result.get("_relogged") is None  # kept the reused session
    assert result.get("ok") is True


@pytest.mark.asyncio
async def test_activate_cookie_only_profile_no_relogin(monkeypatch):
    import dast.tools.session_tools as st
    import dast.profiles.store as store_mod
    # Profile has saved cookies but NO credentials — nothing to re-login with.
    monkeypatch.setattr(store_mod, "load_profile", lambda slug: _Profile(creds=False))

    called = {"probe": False}
    async def _probe(browser, base_url):
        called["probe"] = True
        return False
    import dast.session.account_state as acct
    monkeypatch.setattr(acct, "session_is_authenticated", _probe)

    ctx = _Ctx(_Store(), _Browser())
    result = await st._activate_login_profile(ctx, {"slug": "p"})
    assert result.get("ok") is True
    assert called["probe"] is False  # no creds -> probe/self-heal skipped entirely


def _mk_async_return(value):
    async def _f(*a, **k):
        return value
    return _f

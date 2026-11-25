"""
The crawler/explorer launcher must seed the REAL authenticated session from a
live Browse login (Playwright storage_state: httpOnly cookies + localStorage),
falling back to the Set-Cookie cookie jar only when no login is available.
Regression for: SPA crawler ran logged-out because the jar never captured the
console's httpOnly session cookies.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from dast.proxy import browser_session


class _LiveSession:
    def __init__(self, state):
        self._state = state

    async def get_storage_state(self):
        return self._state


def _run(coro):
    return asyncio.run(coro)


def test_prefers_live_browse_storage_state():
    state = {"cookies": [{"name": "sess", "value": "x"}], "origins": [{"origin": "https://h", "localStorage": []}]}
    store = SimpleNamespace(active_browse_session=_LiveSession(state), auth_storage_state=None,
                            get_crawl_cookies=lambda: [{"name": "jaronly", "value": "1"}])
    assert _run(browser_session._auth_storage_state(store)) == state


def test_falls_back_to_persisted_blob_when_no_live_session():
    blob = {"cookies": [{"name": "persisted", "value": "y"}], "origins": []}
    store = SimpleNamespace(active_browse_session=None, auth_storage_state=blob,
                            get_crawl_cookies=lambda: [])
    assert _run(browser_session._auth_storage_state(store)) == blob


def test_none_when_no_auth_available():
    store = SimpleNamespace(active_browse_session=None, auth_storage_state=None,
                            get_crawl_cookies=lambda: [])
    assert _run(browser_session._auth_storage_state(store)) is None


def test_empty_storage_state_is_ignored():
    empty = {"cookies": [], "origins": []}
    store = SimpleNamespace(active_browse_session=_LiveSession(empty), auth_storage_state=None,
                            get_crawl_cookies=lambda: [])
    assert _run(browser_session._auth_storage_state(store)) is None


def test_live_session_error_falls_back_to_blob():
    class _Boom:
        async def get_storage_state(self):
            raise RuntimeError("context closed")
    blob = {"cookies": [{"name": "p", "value": "1"}], "origins": []}
    store = SimpleNamespace(active_browse_session=_Boom(), auth_storage_state=blob,
                            get_crawl_cookies=lambda: [])
    assert _run(browser_session._auth_storage_state(store)) == blob


# ─── active login-profile (named) session cookie seeding ────────────────────
# When a copilot run authenticated via activate_login_profile, the crawler must
# seed THAT named session's cookies (host-scoped) rather than the shared jar.


def _named_store():
    """Store stub exposing the named-session accessors the helper uses."""
    scoped = [{"name": "sess", "value": "profile", "domain": "app.example", "path": "/"}]
    full = scoped + [{"name": "sso", "value": "x", "domain": "id.example", "path": "/"}]
    return SimpleNamespace(
        get_named_session_cookies_for_host=lambda name, host: list(scoped)
        if name == "acct_a" and host == "app.example" else [],
        get_named_session_cookies=lambda name: list(full) if name == "acct_a" else [],
    )


def test_named_session_cookies_host_scoped():
    store = _named_store()
    cookies = browser_session._named_session_cookies(store, "acct_a", "app.example")
    assert [c["name"] for c in cookies] == ["sess"]


def test_named_session_cookies_fall_back_to_full_set_when_host_unscoped():
    store = _named_store()
    # Host has no scoped match -> fall back to the session's full cookie set.
    cookies = browser_session._named_session_cookies(store, "acct_a", "other.example")
    assert {c["name"] for c in cookies} == {"sess", "sso"}


def test_named_session_cookies_empty_without_session_name():
    store = _named_store()
    assert browser_session._named_session_cookies(store, None, "app.example") == []


def test_named_session_cookies_never_raises():
    class _Boom:
        def get_named_session_cookies_for_host(self, name, host):
            raise RuntimeError("store locked")
        def get_named_session_cookies(self, name):
            raise RuntimeError("store locked")
    assert browser_session._named_session_cookies(_Boom(), "acct_a", "app.example") == []

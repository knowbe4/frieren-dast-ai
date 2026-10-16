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

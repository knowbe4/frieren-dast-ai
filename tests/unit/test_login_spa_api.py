"""Unit tests for the SPA JSON-API login strategy (dast/browser/login_strategies/spa_api.py).

Mocks the browser + store so no network/browser is needed: verifies endpoint detection
order, success-vs-error-body discrimination, and that a successful login syncs cookies into
the jar + arms the session's auto-relogin.
"""

from __future__ import annotations

import pytest

from dast.browser.login_strategies import spa_api


class _FakeBrowser:
    """Browser whose api_post answers per-endpoint from a routing table."""

    def __init__(self, responder):
        self._responder = responder  # (url) -> {"ok","status","text"}
        self.navigated = []
        self.posts = []
        self._cookies_full = [{"name": "_knowbe4_session_new", "value": "s", "domain": "app.x"}]

    async def navigate(self, url, timeout_ms=20000):
        self.navigated.append(url)
        return {"ok": True, "url": url}

    async def api_post(self, url, headers=None, body=None):
        self.posts.append(url)
        return self._responder(url)

    async def export_cookies(self):
        return {"_knowbe4_session_new": "s", "CSRF-TOKEN": "tok"}

    async def export_cookies_full(self):
        return list(self._cookies_full)


class _FakeStore:
    def __init__(self):
        self.imported = None

    def import_playwright_cookies(self, cookies):
        self.imported = cookies
        return len(cookies)


class _FakeSession:
    def __init__(self):
        self._session_cookies = {}
        self._last_login = None


@pytest.mark.asyncio
async def test_spa_api_success_syncs_cookies_and_arms_relogin():
    def responder(url):
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/app/dashboard"}'}
    browser = _FakeBrowser(responder)
    store = _FakeStore()
    session = _FakeSession()
    result = await spa_api.attempt(browser, "https://app.x/app/login", "a@x.com", "pw",
                                   store=store, session=session)
    assert result["ok"] is True and result["engine"] == "spa_api"
    assert result["endpoint"].endswith("/spa/auth/login")      # first candidate wins
    assert store.imported is not None and result["cookies"] == 1   # jar sync happened
    assert session._session_cookies.get("_knowbe4_session_new") == "s"
    assert session._last_login == {"url": "https://app.x/app/login", "email": "a@x.com", "password": "pw"}


@pytest.mark.asyncio
async def test_spa_api_skips_s3_nosuchkey_then_succeeds_on_next_endpoint():
    # First candidate routes to an S3 fallback (404 NoSuchKey) — must NOT be read as success;
    # the strategy tries the next endpoint.
    def responder(url):
        if url.endswith("/spa/auth/login"):
            return {"ok": True, "status": 404, "text": "<Error><Code>NoSuchKey</Code></Error>"}
        if url.endswith("/api/auth/login"):
            return {"ok": True, "status": 200, "text": '{"redirectTo":"/dashboard"}'}
        return {"ok": True, "status": 404, "text": "not found"}
    browser = _FakeBrowser(responder)
    result = await spa_api.attempt(browser, "https://app.x/app/login", "a@x.com", "pw",
                                   store=_FakeStore(), session=_FakeSession())
    assert result["ok"] is True
    assert result["endpoint"].endswith("/api/auth/login")


@pytest.mark.asyncio
async def test_spa_api_error_body_is_not_success():
    def responder(url):
        return {"ok": True, "status": 200, "text": '{"error":"invalid credentials"}'}
    browser = _FakeBrowser(responder)
    result = await spa_api.attempt(browser, "https://app.x/app/login", "a@x.com", "pw")
    assert result["ok"] is False


@pytest.mark.asyncio
async def test_spa_api_all_endpoints_fail():
    def responder(url):
        return {"ok": True, "status": 404, "text": "not found"}
    browser = _FakeBrowser(responder)
    result = await spa_api.attempt(browser, "https://app.x/app/login", "a@x.com", "pw")
    assert result["ok"] is False and result["logged_in"] is False


@pytest.mark.asyncio
async def test_spa_api_respects_scope_gate():
    def responder(url):
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/dashboard"}'}
    browser = _FakeBrowser(responder)
    # Deny every candidate: no endpoint is attempted, no success.
    result = await spa_api.attempt(browser, "https://app.x/app/login", "a@x.com", "pw",
                                   in_scope=lambda u: False)
    assert result["ok"] is False
    assert browser.posts == []       # scope gate blocked all posts

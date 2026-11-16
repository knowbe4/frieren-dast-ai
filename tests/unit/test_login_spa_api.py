"""Unit tests for the SPA JSON-API login strategy (dast/browser/login_strategies/spa_api.py).

Mocks the browser + store so no network/browser is needed: verifies endpoint detection
order, success-vs-error-body discrimination, and that a successful login syncs cookies into
the jar + arms the session's auto-relogin.
"""

from __future__ import annotations

import json as _json

import pytest

from dast.browser.login_strategies import spa_api


class _FakeBrowser:
    """Browser whose api_post answers per-endpoint from a routing table."""

    def __init__(self, responder, api_get_routes=None):
        self._responder = responder  # (url) -> {"ok","status","text"}
        self._api_get_routes = api_get_routes or {}  # url -> api_get response
        self.navigated = []
        self.posts = []
        self.gets = []
        self._cookies_full = [{"name": "_knowbe4_session_new", "value": "s", "domain": "app.x"}]

    async def navigate(self, url, timeout_ms=20000):
        self.navigated.append(url)
        return {"ok": True, "url": url}

    async def api_post(self, url, headers=None, body=None):
        self.posts.append(url)
        return self._responder(url)

    async def api_get(self, url):
        self.gets.append(url)
        return self._api_get_routes.get(url, {"ok": True, "status": 200, "text": ""})

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


# ── SpaApiStrategy (the LoginStrategy adapter over attempt()) ──

from dast.browser.login_strategies.base import LoginContext, LoginResult  # noqa: E402
from dast.browser.login_strategies.spa_api import SpaApiStrategy  # noqa: E402


def _ctx(prior=None):
    return LoginContext(browser=object(), url="https://app.x/login", email="a@x.com",
                        password="pw", prior=list(prior or []))


@pytest.mark.asyncio
async def test_spa_api_strategy_can_attempt_truth_table():
    s = SpaApiStrategy()
    # Ordered first (learned win): nothing tried yet -> run it.
    assert await s.can_attempt(_ctx([])) is True
    # Preceding form could not REACH a form -> run the DOM-independent JSON path.
    unreachable = LoginResult(ok=False, engine="deterministic", url="u", reachable=False)
    assert await s.can_attempt(_ctx([unreachable])) is True
    # Form WAS reached but failed (invalid creds / extra step) -> skip; leave it to the LLM.
    reached = LoginResult(ok=False, engine="deterministic", url="u", reachable=True)
    assert await s.can_attempt(_ctx([reached])) is False


@pytest.mark.asyncio
async def test_spa_api_strategy_maps_attempt_dict_to_login_result(monkeypatch):
    async def fake_attempt(browser, url, email, password, **kw):
        return {"ok": True, "logged_in": True, "engine": "spa_api",
                "endpoint": "https://app.x/api/login", "url": url, "status": 200}
    monkeypatch.setattr(spa_api, "attempt", fake_attempt)
    result = await SpaApiStrategy().attempt(_ctx([]))
    assert isinstance(result, LoginResult)
    assert result.ok is True and result.engine == "spa_api"
    assert result.endpoint == "https://app.x/api/login" and result.url == "https://app.x/login"


@pytest.mark.asyncio
async def test_spa_api_strategy_maps_failure(monkeypatch):
    async def fake_attempt(browser, url, email, password, **kw):
        return {"ok": False, "logged_in": False, "engine": "spa_api", "error": "no endpoint"}
    monkeypatch.setattr(spa_api, "attempt", fake_attempt)
    result = await SpaApiStrategy().attempt(_ctx([]))
    assert result.ok is False and result.error == "no endpoint"


@pytest.mark.asyncio
async def test_spa_api_rejects_success_shaped_body_when_session_probes_contradicted():
    """A success-shaped 2xx is NOT a session: when the structural probe positively
    contradicts (origin root is a 401 wall), the candidate is skipped and the login
    fails instead of journaling a poisoned winner."""
    def responder(url):
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/app/dashboard"}'}
    browser = _FakeBrowser(responder, api_get_routes={
        "https://app.x/": {"ok": False, "status": 401, "text": ""},
    })
    result = await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                                   store=_FakeStore(), session=_FakeSession())
    assert result.get("ok") is False
    assert result.get("logged_in") is False
    # The root probe actually ran (the confirm is not a no-op).
    assert "https://app.x/" in browser.gets


@pytest.mark.asyncio
async def test_spa_api_accepts_when_probe_confirms_session():
    """Success-shaped body + non-wall root + a session-looking cookie → accepted
    (and the result surfaces the verification verdict)."""
    def responder(url):
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/app/dashboard"}'}
    browser = _FakeBrowser(responder)
    result = await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                                   store=_FakeStore(), session=_FakeSession())
    assert result.get("ok") is True
    assert result.get("verified") is True


@pytest.mark.asyncio
async def test_spa_api_probe_expect_cookie_gates_success():
    """A configured expect_cookie is a hard expectation: missing → contradicted →
    the candidate is rejected even though the body looked successful."""
    from dast.session.account_state import AuthProbeConfig

    def responder(url):
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/app/dashboard"}'}
    browser = _FakeBrowser(responder)
    probe = AuthProbeConfig(expect_cookie="app_session")
    result = await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                                   store=_FakeStore(), session=_FakeSession(), probe=probe)
    assert result.get("ok") is False

    # ...and present → accepted.
    probe2 = AuthProbeConfig(expect_cookie="_knowbe4_session_new")
    browser2 = _FakeBrowser(responder)
    result2 = await spa_api.attempt(browser2, "https://app.x/login", "e@x", "p",
                                    store=_FakeStore(), session=_FakeSession(), probe=probe2)
    assert result2.get("ok") is True
    assert result2.get("verified") is True


# ── anti-spray: early-stop on credential rejection / 404 / 429 ───────────────

@pytest.mark.asyncio
async def test_early_stops_when_login_endpoint_rejects_credentials():
    """A 401 from a real login endpoint means the credentials are wrong — spraying
    the same credentials at 4 more endpoints only feeds account-lockout counters."""
    posts_per_endpoint = {}

    def responder(url):
        posts_per_endpoint[url] = posts_per_endpoint.get(url, 0) + 1
        return {"ok": True, "status": 401, "text": '{"error": "invalid credentials"}'}

    browser = _FakeBrowser(responder)
    result = await spa_api.attempt(browser, "https://app.x/login", "e@x", "WRONG",
                                   store=_FakeStore(), session=_FakeSession())
    assert result.get("ok") is False
    assert "credentials rejected" in result.get("error", "")
    # Only ONE endpoint was sprayed — not the full 5-endpoint grid.
    assert len(browser.posts) <= 5
    assert len(posts_per_endpoint) == 1


@pytest.mark.asyncio
async def test_404_skips_endpoint_variants_but_keeps_trying_other_endpoints():
    """404 means 'not this endpoint': skip remaining shapes for it, still try the
    next candidate endpoint (which succeeds)."""

    def responder(url):
        if url.endswith("/spa/auth/login"):
            return {"ok": True, "status": 404, "text": "not found"}
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/app"}'}

    browser = _FakeBrowser(responder)
    result = await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                                   store=_FakeStore(), session=_FakeSession())
    assert result.get("ok") is True
    # Exactly one POST hit the missing endpoint, then the next endpoint succeeded.
    assert browser.posts.count("https://app.x/spa/auth/login") == 1
    assert result.get("endpoint") == "https://app.x/api/auth/login"


@pytest.mark.asyncio
async def test_429_stops_entire_spray():
    def responder(url):
        return {"ok": True, "status": 429, "text": "too many attempts"}

    browser = _FakeBrowser(responder)
    result = await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                                   store=_FakeStore(), session=_FakeSession())
    assert result.get("ok") is False
    assert "rate-limited" in result.get("error", "")
    assert len(browser.posts) == 1


@pytest.mark.asyncio
async def test_post_budget_cap():
    """A 200-with-error-body endpoint (no early-stop trigger) still cannot exceed
    the global POST budget."""
    def responder(url):
        return {"ok": True, "status": 200, "text": '{"message": "try again"}'}

    browser = _FakeBrowser(responder)
    await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                          store=_FakeStore(), session=_FakeSession())
    assert len(browser.posts) <= 10


@pytest.mark.asyncio
async def test_401_on_non_loginish_endpoint_does_not_stop():
    """A 401 from an endpoint whose path isn't login/auth-shaped only means 'not
    this endpoint' — the cascade keeps trying (and the login-shaped endpoint
    succeeds)."""

    def responder(url):
        if url.endswith("/api/data"):
            return {"ok": True, "status": 401, "text": "denied"}
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/app"}'}

    browser = _FakeBrowser(responder)
    result = await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                                   endpoints=["https://app.x/api/data",
                                              "https://app.x/api/login"],
                                   store=_FakeStore(), session=_FakeSession())
    assert result.get("ok") is True
    assert result.get("endpoint") == "https://app.x/api/login"


# ── multi-convention CSRF headers ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_csrf_headers_cover_three_framework_conventions():
    class _CookieBrowser(_FakeBrowser):
        async def export_cookies(self):
            return {"XSRF-TOKEN": "ang123", "csrftoken": "dj456", "CSRF-TOKEN": "kb789"}

    headers = await spa_api._csrf_headers(_CookieBrowser(responder=lambda u: {}))
    assert headers["X-CSRF-Token"] == "kb789"      # Spring/KnowBe4 style
    assert headers["X-XSRF-TOKEN"] == "ang123"     # Angular/Laravel style
    assert headers["X-CSRFToken"] == "dj456"       # Django style
    assert headers["Content-Type"] == "application/json"


# ── timezone + TOTP arming ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_default_timezone_is_local_not_fortaleza():
    import time as _time
    assert spa_api._local_timezone() == _time.tzname[_time.daylight]
    variants = spa_api._body_variants("e@x", "p", spa_api._local_timezone())
    assert all(v.get("browser_timezone") != "America/Fortaleza" for v in variants)


@pytest.mark.asyncio
async def test_totp_secret_is_armed_into_last_login():
    """MFA accounts: the cascade carries ctx.totp_secret (already may_use_totp-gated
    upstream); _sync_session must arm it or auto-relogin dies at the OTP step."""

    def responder(url):
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/app"}'}

    browser = _FakeBrowser(responder)
    session = _FakeSession()
    result = await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                                   store=_FakeStore(), session=session,
                                   totp_secret="JBSWY3DPEHPK3PXP")
    assert result.get("ok") is True
    assert session._last_login.get("totp_secret") == "JBSWY3DPEHPK3PXP"


@pytest.mark.asyncio
async def test_no_totp_secret_keeps_last_login_shape_unchanged():
    def responder(url):
        return {"ok": True, "status": 200, "text": '{"redirectTo":"/app"}'}

    browser = _FakeBrowser(responder)
    session = _FakeSession()
    await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                          store=_FakeStore(), session=session)
    assert set(session._last_login.keys()) == {"url", "email", "password"}


@pytest.mark.asyncio
async def test_learned_body_shape_is_tried_first(monkeypatch):
    """The journal's body_shape moves the matching variant to the front of the
    first POST (fast + low-spray learned logins)."""
    from dast.session import login_journal
    login_journal.record("https://app.x/login", "success", strategy="spa_api",
                         endpoint="https://app.x/api/auth/login",
                         body_shape="password,username", success_url="https://app.x/login")

    posts = []

    def responder(url):
        return {"ok": True, "status": 200, "text": "empty"}

    class _PostRecorder(_FakeBrowser):
        async def api_post(self, url, headers=None, body=None):
            posts.append(body)
            return await super().api_post(url, headers, body)

    browser = _PostRecorder(responder)
    await spa_api.attempt(browser, "https://app.x/login", "e@x", "p",
                          store=_FakeStore(), session=_FakeSession())
    first_body = _json.loads(posts[0])
    assert set(first_body.keys()) == {"username", "password"}

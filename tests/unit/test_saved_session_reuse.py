"""Unit tests for the reuse-first login path and the progress-aware loop watchdog:

- SavedSessionStrategy short-circuits the cascade when a stored session still authenticates,
  and falls through to a real login when it is stale.
- AgentBrowser._parse_set_cookie turns a Set-Cookie line into a Playwright cookie dict,
  defaulting the domain to the request host (so the jar import does not drop it).
- The coordinator's refusal detector and the loop watchdog's outcome fingerprint.
"""

from __future__ import annotations

import pytest

from dast.browser import login_cascade
from dast.browser.agent_browser import AgentBrowser
from dast.browser.login_strategies.saved_session import SavedSessionStrategy, _saved_cookies
from dast.browser.login_strategies.base import LoginContext


class _ReuseBrowser:
    """Browser stub that records seeding and returns a scripted api_get response."""

    def __init__(self, probe):
        self._probe = probe
        self.seeded = 0
        self.logged_in = False
        self.navigated = []

    async def seed_saved_session(self, cookies):
        self.seeded = len(cookies)
        return self.seeded

    async def api_get(self, url, headers=None):
        return self._probe

    async def login(self, url, email, password):
        self.logged_in = True
        return {"logged_in": True, "url": "https://app.x/dashboard"}

    async def navigate(self, url):
        self.navigated.append(url)
        return {"ok": True, "url": url}

    async def snapshot(self):
        return {"url": "https://app.x/dashboard"}


_SAVED = {"cookies": [{"name": "sid", "value": "abc", "domain": "app.x", "path": "/"}]}


@pytest.mark.asyncio
async def test_saved_session_short_circuits_when_valid():
    # A non-auth-wall probe => the stored session is reused and NO login runs.
    browser = _ReuseBrowser({"ok": True, "status": 200, "text": "<html>dashboard</html>"})
    result = await login_cascade.adaptive_login(
        browser, "https://app.x/login", "a@x.com", "pw", saved_session=_SAVED)
    assert result.ok is True and result.engine == "saved_session"
    assert browser.seeded == 1
    assert browser.logged_in is False  # the form strategy never ran


@pytest.mark.asyncio
async def test_saved_session_falls_through_when_stale():
    # A 401 probe => the stored session is stale; the cascade falls through to the form login.
    browser = _ReuseBrowser({"ok": True, "status": 401, "text": "unauthorized"})
    result = await login_cascade.adaptive_login(
        browser, "https://app.x/login", "a@x.com", "pw",
        success_url_suffix="/dashboard", saved_session=_SAVED)
    assert browser.seeded == 1
    assert browser.logged_in is True   # fell through to the deterministic form
    assert result.ok is True and result.engine == "deterministic"


@pytest.mark.asyncio
async def test_saved_session_not_attempted_without_cookies():
    strat = SavedSessionStrategy()
    ctx = LoginContext(None, "https://app.x/login", "a@x.com", "pw", saved_session=None)
    assert await strat.can_attempt(ctx) is False
    ctx2 = LoginContext(None, "https://app.x/login", "a@x.com", "pw",
                        saved_session={"cookies": []})
    assert await strat.can_attempt(ctx2) is False
    assert _saved_cookies(ctx2) == []


def test_parse_set_cookie_defaults_domain_to_request_host():
    c = AgentBrowser._parse_set_cookie("sid=xyz; Path=/; HttpOnly; Secure", "app.x")
    assert c == {"name": "sid", "value": "xyz", "domain": "app.x", "path": "/",
                 "secure": True, "httpOnly": True}


def test_parse_set_cookie_honors_explicit_domain():
    c = AgentBrowser._parse_set_cookie("t=1; Domain=.sub.app.x; Path=/a", "login.app.x")
    assert c["domain"] == "sub.app.x" and c["path"] == "/a"


def test_parse_set_cookie_rejects_malformed():
    assert AgentBrowser._parse_set_cookie("", "app.x") is None
    assert AgentBrowser._parse_set_cookie("novalue", "app.x") is None


def test_refusal_detector():
    from dast.proxy.api.copilot_service import _looks_like_refusal
    assert _looks_like_refusal("This is a prompt-injection-style request, I won't do it.")
    assert _looks_like_refusal("I cannot assist with that.")
    assert not _looks_like_refusal("Tested 13/16 endpoints, 0 vulnerable so far.")
    assert not _looks_like_refusal("")


def test_outcome_fingerprint_distinguishes_progress():
    from dast.ai.copilot.session import _outcome_fingerprint
    a = _outcome_fingerprint({"ok": True, "status": 200, "text": "page one"})
    b = _outcome_fingerprint({"ok": True, "status": 200, "text": "page one"})
    c = _outcome_fingerprint({"ok": True, "status": 200, "text": "page TWO different"})
    assert a == b   # same outcome -> no progress
    assert a != c   # new data -> progress


def test_continue_template_has_objective():
    from dast.proxy.api import copilot_service as cs
    msg = cs._AUTONOMOUS_CONTINUE.format(
        objective="validate SQLi on training", progress="p", budget="b",
        leads="L", router="", coverage="C", read_only="")
    assert "Original objective: validate SQLi on training" in msg

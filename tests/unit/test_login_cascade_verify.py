"""Unit tests for the cascade driver's verified journaling (round 2-B).

The form/llm strategies decide ``ok`` from URL heuristics — and the journal
PROMOTES a learned winner to the front of every future cascade, so a heuristic
win that the structural session probe contradicts must be journaled as an error,
never learned as a success (the poisoned-winner audit finding).
"""

from __future__ import annotations


import pytest

from dast.browser import login_cascade
from dast.session import login_journal

BASE = "https://app.example.com/login"


class _Browser:
    """Fake browser: deterministic login() succeeds on cue; api_get routes for the
    verification probe; export_cookies returns a session-looking jar."""

    def __init__(self, api_routes):
        self._routes = api_routes

    async def login(self, url, email, password, totp_secret=None):
        return {"logged_in": True, "url": "https://app.example.com/dashboard"}

    async def navigate(self, url):
        return {"ok": True, "url": url}

    async def snapshot(self):
        return {"url": "https://app.example.com/dashboard"}

    async def export_cookies(self):
        return {"sessionid": "s3ss10n"}

    async def api_get(self, url):
        return self._routes.get(url, {"ok": True, "status": 200, "text": "{}"})


def _ok_routes():
    return {
        "https://app.example.com/": {"ok": True, "status": 200, "text": "<html/>"},
        "https://app.example.com/spa/session": {
            "ok": True, "status": 200,
            "text": '{"account": {"id": 42}, "user": {"id": 5}}'},
    }


@pytest.mark.asyncio
async def test_verified_success_is_journaled_with_verified_flag():
    browser = _Browser(_ok_routes())
    result = await login_cascade.adaptive_login(
        browser, BASE, "a@x.com", "pw", success_url_suffix="/dashboard")
    assert result.ok is True

    records = login_journal.recent_records("app.example.com")
    success = [r for r in records if r.get("outcome") == "success"]
    assert len(success) == 1
    assert success[0].get("verified") is True
    assert success[0]["strategy"] == "deterministic"


@pytest.mark.asyncio
async def test_contradicted_heuristic_win_is_journaled_as_error():
    """URL heuristic says logged-in; the structural probe says auth wall. The
    driver must NOT journal a success the probe contradicted — a poisoned winner
    would be reordered to the front of every future cascade."""
    routes = {
        "https://app.example.com/": {"ok": False, "status": 401, "text": "unauthorized"},
    }
    browser = _Browser(routes)
    result = await login_cascade.adaptive_login(
        browser, BASE, "a@x.com", "pw", success_url_suffix="/dashboard")
    # The cascade still RETURNS the heuristic result (caller owns the decision) —
    # only the JOURNAL refuses to learn it.
    assert result.ok is True

    records = login_journal.recent_records("app.example.com")
    successes = [r for r in records if r.get("outcome") == "success"]
    errors = [r for r in records if r.get("outcome") == "error"]
    assert successes == []
    assert len(errors) == 1
    assert "contradicted" in errors[0].get("reason", "")


@pytest.mark.asyncio
async def test_inconclusive_probe_fails_open_and_journals_success():
    """Probe cannot decide (SPA shell at root, no session endpoint, no
    session-looking cookie) → legacy behavior: journal the success, without a
    verified claim."""

    class _AmbiguousBrowser(_Browser):
        async def export_cookies(self):
            # Only analytics cookies — the session-cookie heuristic cannot decide.
            return {"cf_bm": "x", "_ga": "y"}

    routes = {
        "https://app.example.com/": {"ok": True, "status": 200, "text": "<html>shell</html>"},
    }
    browser = _AmbiguousBrowser(routes)
    result = await login_cascade.adaptive_login(
        browser, BASE, "a@x.com", "pw", success_url_suffix="/dashboard")
    assert result.ok is True

    records = login_journal.recent_records("app.example.com")
    success = [r for r in records if r.get("outcome") == "success"]
    assert len(success) == 1
    assert "verified" not in success[0]

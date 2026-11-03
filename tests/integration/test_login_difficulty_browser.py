"""Login-difficulty harness - deterministic browser engine (T0-T4, T9-T11).

Drives the real ``AgentBrowser.login()`` heuristic (the LLM-free engine) against
the local fixture login pages and asserts, per tier, whether it can identify the
fields, submit, and land authenticated - the way an operator would expect.

Tiers it should solve today (asserted to pass):
    T0  trivial single-page form
    T1  two-step: email -> Continue -> password
    T2  non-standard identifiers + <div role=button> submit (newly solved: the
        engine now covers names like j_username and scores a role=button submit)
    T3  consent banner + honeypot + placeholder-only labels
    T9  SSO redirect to a second-origin IdP and back
    T10 MFA: detected and reported (graceful bail, not a false success)

Tiers that are known gaps in the heuristic engine (asserted xfail - they are the
spec for a future engine improvement, and the LLM-driven path is where they get
solved like a human):
    T4  credential fields inside an <iframe>
    T11 OAuth-style "Authorize" consent button (engine submits once, does not click
        the consent button; the LLM fallback completes it)

The browser is launched WITHOUT a proxy (fixtures are already on 127.0.0.1), by
pre-assigning a Playwright page to the AgentBrowser instance so ``login()`` runs
verbatim. Skipped entirely when Playwright/Chromium is unavailable.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Dict

import pytest
import pytest_asyncio

from dast.browser.agent_browser import AgentBrowser
from tests.fixtures.login_pages.browser_harness import (
    chromium_available,
    proxyless_agent_browser,
)
from tests.fixtures.login_pages.server import PASSWORD, USERNAME, login_fixture

# Hard ceiling per login attempt. login() has its own 60s internal timeout plus
# fixed waits; this bounds the worst case to a clean failure (there is no
# pytest-timeout plugin in the project to catch a true hang).
_LOGIN_TIMEOUT_SECONDS = 90

pytestmark = pytest.mark.skipif(not chromium_available(), reason="chromium not installed")


@pytest_asyncio.fixture
async def agent_browser() -> AsyncIterator[AgentBrowser]:
    """A proxy-less AgentBrowser so ``login()`` runs without routing through a proxy."""
    async with proxyless_agent_browser() as agent:
        yield agent


async def _login(ab: AgentBrowser, url: str) -> Dict[str, Any]:
    return await asyncio.wait_for(
        ab.login(url, USERNAME, PASSWORD), timeout=_LOGIN_TIMEOUT_SECONDS
    )


# ----------------------------------------------------------------- solvable tiers


@pytest.mark.asyncio
async def test_t0_trivial_single_page(agent_browser: AgentBrowser) -> None:
    with login_fixture() as server:
        result = await _login(agent_browser, f"{server.base_url}/t0/login")
    assert result.get("logged_in") is True, result
    assert result["url"].endswith("/dashboard")


@pytest.mark.asyncio
async def test_t1_two_step_email_then_password(agent_browser: AgentBrowser) -> None:
    with login_fixture() as server:
        result = await _login(agent_browser, f"{server.base_url}/t1/login")
    assert result.get("logged_in") is True, result
    assert result["url"].endswith("/dashboard")


@pytest.mark.asyncio
async def test_t3_consent_banner_and_honeypot(agent_browser: AgentBrowser) -> None:
    with login_fixture() as server:
        result = await _login(agent_browser, f"{server.base_url}/t3/login")
        # The honeypot field must never have been filled by the engine.
        honeypot_posts = [form for path, form in server.posts
                          if path == "/t3/submit" and form.get("website")]
    assert result.get("logged_in") is True, result
    assert result["url"].endswith("/dashboard")
    assert honeypot_posts == [], "engine filled the honeypot field"


@pytest.mark.asyncio
async def test_t9_sso_redirect_round_trip(agent_browser: AgentBrowser) -> None:
    with login_fixture(with_idp=True) as server:
        result = await _login(agent_browser, f"{server.base_url}/t9/login")
    assert result.get("logged_in") is True, result
    assert result["url"].endswith("/dashboard")


@pytest.mark.asyncio
async def test_t10_mfa_detected_and_reported(agent_browser: AgentBrowser) -> None:
    with login_fixture() as server:
        result = await _login(agent_browser, f"{server.base_url}/t10/login")
    # Graceful bail: MFA is detected, no false "logged in".
    assert result.get("mfa_required") is True, result
    assert result.get("logged_in") is not True


# ------------------------------------------------- known gaps (documented xfail)


@pytest.mark.asyncio
async def test_t2_nonstandard_identifiers(agent_browser: AgentBrowser) -> None:
    # Previously a gap: the engine now covers non-standard username names
    # (j_username) and scores a <div role=button> submit, so it logs in without
    # the LLM. Kept as a pass to lock in that improvement.
    with login_fixture() as server:
        result = await _login(agent_browser, f"{server.base_url}/t2/login")
    assert result.get("logged_in") is True, result
    assert result["url"].endswith("/dashboard")


@pytest.mark.asyncio
@pytest.mark.xfail(reason="login() queries the main frame only; credential fields "
                          "inside an iframe are not reached",
                   strict=True)
async def test_t4_fields_inside_iframe(agent_browser: AgentBrowser) -> None:
    with login_fixture() as server:
        result = await _login(agent_browser, f"{server.base_url}/t4/login")
    assert result.get("logged_in") is True, result


@pytest.mark.asyncio
@pytest.mark.xfail(reason="engine has no 'Authorize/Allow' consent step; it stops on "
                          "the consent screen and does not reach /dashboard",
                   strict=True)
async def test_t11_oauth_authorize_consent(agent_browser: AgentBrowser) -> None:
    with login_fixture() as server:
        result = await _login(agent_browser, f"{server.base_url}/t11/login")
    assert result["url"].endswith("/dashboard"), result

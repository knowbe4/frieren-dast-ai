"""Deterministic, token-free regression over the high-fidelity product-clone
environments (``environments.py``).

These lock in the engine improvements that let the deterministic path handle
real-world login pages without the LLM:
  - broadened username selectors (identifier/loginfmt/log/UserName/...),
  - scored submit control (prefers the login form's sign-in button over a header
    Search/Go, and reaches a <div role=button> / <span role=button>),
  - single-page early password fill + one-shot classification,
  - shadow-DOM piercing for the submit control.

The LLM-only environments (intl_ptbr non-English field names, azure_ad consent)
are covered by the opt-in real-model eval ``login_env_eval.py`` instead - here we
only assert the deterministic outcomes, so this runs in CI without tokens.
"""

from __future__ import annotations

from typing import Any, AsyncIterator

import pytest
import pytest_asyncio

from dast.browser.agent_browser import AgentBrowser
from dast.browser.login_cascade import adaptive_login
from tests.fixtures.login_pages.browser_harness import (
    chromium_available,
    proxyless_agent_browser,
)
from tests.fixtures.login_pages.environments import (
    PASSWORD,
    USERNAME,
    env_fixture,
    env_login_url,
)

pytestmark = pytest.mark.skipif(not chromium_available(), reason="chromium not installed")


@pytest_asyncio.fixture
async def agent_browser() -> AsyncIterator[AgentBrowser]:
    async with proxyless_agent_browser() as agent:
        yield agent


def _never_called_decider() -> Any:
    def decide(snapshot: dict, context: dict) -> None:
        raise AssertionError("LLM must not be used: this environment is solved "
                             "by the deterministic engine")
    return decide


# Environments the deterministic engine solves end to end (no LLM).
_DETERMINISTIC_ENVS = ["okta", "auth0", "keycloak", "wordpress", "django",
                       "adfs", "shadow_dom"]


@pytest.mark.asyncio
@pytest.mark.parametrize("env", _DETERMINISTIC_ENVS)
async def test_environment_solved_deterministically(agent_browser: AgentBrowser, env: str) -> None:
    with env_fixture() as server:
        result = await adaptive_login(
            agent_browser, env_login_url(server.base_url, env), USERNAME, PASSWORD,
            decide=_never_called_decider(), success_url_suffix="/dashboard",
        )
    assert result.ok is True, (env, result.to_dict())
    assert result.engine == "deterministic"
    assert result.url.endswith("/dashboard")


@pytest.mark.asyncio
async def test_sso_mfa_combo_bails_at_mfa(agent_browser: AgentBrowser) -> None:
    # SSO + MFA combo: credentials are accepted, then an OTP wall. The engine must
    # report MFA and NOT escalate to the LLM (a human wall, not a selector problem).
    with env_fixture() as server:
        result = await adaptive_login(
            agent_browser, env_login_url(server.base_url, "sso_mfa"), USERNAME, PASSWORD,
            decide=_never_called_decider(), success_url_suffix="/dashboard",
        )
    assert result.ok is False, result.to_dict()
    assert result.error == "mfa_required"
    assert result.engine == "deterministic"

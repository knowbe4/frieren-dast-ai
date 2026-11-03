"""Adaptive-login cascade: deterministic-first, LLM-on-failure (token-free).

Proves the cascade mechanics in ``dast.browser.login_cascade.adaptive_login``:

- tiers the heuristic already solves (T0) never invoke the LLM decider;
- tiers the heuristic cannot solve (T2 odd selectors, T11 consent button) ARE
  solved once the LLM drives the browser primitives - here a *scripted* decider
  stands in for the model (the real model path is the opt-in eval), so this runs
  in CI without spending tokens;
- MFA (T10) is not escalated to the LLM - it is a human wall, reported as such;
- an iframe form (T4) is a genuine limitation: the main-frame snapshot exposes no
  fields, so even the fallback cannot act on them.

The scripted deciders read the page snapshot (asserting the expected controls are
present) and use ``context['history']`` to know how far they have progressed -
exactly the information the real decider works from.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable, Dict, List, Optional

import pytest
import pytest_asyncio

from dast.browser.agent_browser import AgentBrowser
from dast.browser.login_cascade import adaptive_login
from tests.fixtures.login_pages.browser_harness import (
    chromium_available,
    proxyless_agent_browser,
)
from tests.fixtures.login_pages.server import PASSWORD, USERNAME, login_fixture

pytestmark = pytest.mark.skipif(not chromium_available(), reason="chromium not installed")


@pytest_asyncio.fixture
async def agent_browser() -> AsyncIterator[AgentBrowser]:
    async with proxyless_agent_browser() as agent:
        yield agent


def _scripted_decider(plan: List[Dict[str, Any]],
                      require_names: Optional[set] = None) -> Callable:
    """A decider that replays ``plan`` by step index (len of history), optionally
    asserting that the snapshot actually exposes ``require_names`` field names -
    tying each decision to the observed DOM."""
    def decide(snapshot: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if require_names:
            names = {f.get("name") for form in (snapshot.get("forms") or [])
                     for f in (form.get("fields") or [])}
            assert require_names.issubset(names), f"snapshot missing {require_names - names}"
        index = len(context.get("history") or [])
        if index >= len(plan):
            return {"action": "stop"}
        action = dict(plan[index])
        # Resolve credential placeholders from context.
        if action.get("value") == "$EMAIL":
            action["value"] = context["email"]
        elif action.get("value") == "$PASSWORD":
            action["value"] = context["password"]
        return action
    return decide


def _never_called_decider() -> Callable:
    def decide(snapshot: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise AssertionError("LLM decider must not be called when the deterministic "
                             "engine already logged in")
    return decide


# ---------------------------------------------------- deterministic wins (no LLM)


@pytest.mark.asyncio
async def test_t0_solved_deterministically_without_llm(agent_browser: AgentBrowser) -> None:
    with login_fixture() as server:
        result = await adaptive_login(
            agent_browser, f"{server.base_url}/t0/login", USERNAME, PASSWORD,
            decide=_never_called_decider(), success_url_suffix="/dashboard",
        )
    assert result.ok is True
    assert result.engine == "deterministic"
    assert result.llm_steps == 0


@pytest.mark.asyncio
async def test_t10_mfa_not_escalated_to_llm(agent_browser: AgentBrowser) -> None:
    with login_fixture() as server:
        result = await adaptive_login(
            agent_browser, f"{server.base_url}/t10/login", USERNAME, PASSWORD,
            decide=_never_called_decider(), success_url_suffix="/dashboard",
        )
    assert result.ok is False
    assert result.engine == "deterministic"
    assert result.error == "mfa_required"


# ------------------------------------------------- LLM fallback solves the gap


@pytest.mark.asyncio
async def test_t2_nonstandard_identifiers_now_deterministic(agent_browser: AgentBrowser) -> None:
    # After the engine improvements (j_username coverage + scored <div role=button>
    # submit), T2 is solved by the deterministic engine, so the LLM is never needed.
    with login_fixture() as server:
        result = await adaptive_login(
            agent_browser, f"{server.base_url}/t2/login", USERNAME, PASSWORD,
            decide=_never_called_decider(), success_url_suffix="/dashboard",
        )
    assert result.ok is True, result.to_dict()
    assert result.engine == "deterministic"
    assert result.llm_steps == 0
    assert result.url.endswith("/dashboard")


@pytest.mark.asyncio
async def test_t11_authorize_consent_solved_by_llm(agent_browser: AgentBrowser) -> None:
    plan = [
        {"action": "fill", "selector": "input[type=email]", "value": "$EMAIL"},
        {"action": "fill", "selector": "input[type=password]", "value": "$PASSWORD"},
        {"action": "click", "selector": "button[type=submit]", "expect_navigation": True},
        {"action": "click", "selector": "#authorize-btn", "expect_navigation": True},
    ]
    with login_fixture() as server:
        result = await adaptive_login(
            agent_browser, f"{server.base_url}/t11/login", USERNAME, PASSWORD,
            decide=_scripted_decider(plan),
            success_url_suffix="/dashboard",
        )
    assert result.ok is True, result.to_dict()
    assert result.engine == "llm"
    assert result.url.endswith("/dashboard")


# --------------------------------------------------------- genuine limitation


@pytest.mark.asyncio
async def test_t4_iframe_fields_unreachable_even_by_fallback(agent_browser: AgentBrowser) -> None:
    """Credential fields inside an iframe are not in the main-frame snapshot, so a
    snapshot-driven decider has nothing to act on and gives up. Documents the limit
    (fixing it needs frame-aware primitives, not a smarter prompt)."""
    def decide(snapshot: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        names = {f.get("name") for form in (snapshot.get("forms") or [])
                 for f in (form.get("fields") or [])}
        if "email" in names or "password" in names:
            return {"action": "fill", "selector": "input[type=email]", "value": context["email"]}
        return {"action": "stop"}  # nothing usable in the main-frame snapshot

    with login_fixture() as server:
        result = await adaptive_login(
            agent_browser, f"{server.base_url}/t4/login", USERNAME, PASSWORD,
            decide=decide, success_url_suffix="/dashboard",
        )
    assert result.ok is False, result.to_dict()
    assert not result.url.endswith("/dashboard")

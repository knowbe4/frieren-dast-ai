"""Unit tests for the login strategy registry (dast/browser/login_strategies/registry.py)
and the registry-driven adaptive_login loop: default ordering, the pure reorder rule, and the
driver's success / terminal short-circuit (so a later strategy is not run once one resolves)."""

from __future__ import annotations

import pytest

from dast.browser import login_cascade
from dast.browser.login_strategies import registry


def test_default_registry_has_the_three_strategies_in_order():
    names = [s.name for s in registry.ordered_strategies()]
    assert names == ["deterministic", "spa_api", "llm"]


def test_reorder_moves_winner_to_front():
    default = ("deterministic", "spa_api", "llm")
    assert registry.reorder(default, "spa_api") == ["spa_api", "deterministic", "llm"]
    assert registry.reorder(default, "llm") == ["llm", "deterministic", "spa_api"]
    # None or an unknown winner leaves the order unchanged, and never drops a strategy.
    assert registry.reorder(default, None) == list(default)
    assert registry.reorder(default, "nope") == list(default)


class _Browser:
    """Minimal browser whose login() returns a scripted dict; records whether the LLM-path
    primitives (navigate/snapshot) were touched, to prove short-circuiting."""

    def __init__(self, login_result):
        self._login_result = login_result
        self.snapshotted = False
        self.navigated = []

    async def login(self, url, email, password):
        return self._login_result

    async def navigate(self, url):
        self.navigated.append(url)
        return {"ok": True, "url": url}

    async def snapshot(self):
        self.snapshotted = True
        return {"url": "https://app.x/login"}


@pytest.mark.asyncio
async def test_driver_returns_on_deterministic_success_without_running_llm():
    browser = _Browser({"logged_in": True, "url": "https://app.x/dashboard"})
    result = await login_cascade.adaptive_login(
        browser, "https://app.x/login", "a@x.com", "pw", success_url_suffix="/dashboard")
    assert result.ok is True and result.engine == "deterministic"
    assert browser.snapshotted is False   # LLM strategy never ran


@pytest.mark.asyncio
async def test_driver_short_circuits_on_terminal_mfa():
    # A terminal MFA result stops the cascade: neither spa_api nor the LLM is attempted.
    browser = _Browser({"logged_in": False, "mfa_required": True, "url": "https://app.x/mfa"})
    result = await login_cascade.adaptive_login(
        browser, "https://app.x/login", "a@x.com", "pw", success_url_suffix="/dashboard")
    assert result.ok is False and result.engine == "deterministic"
    assert result.error == "mfa_required"
    assert browser.snapshotted is False   # did not escalate to the LLM


def test_ordered_strategies_learns_winner_from_journal():
    from dast.session import login_journal
    host = "learned.example.com"
    # No history -> default order.
    assert [s.name for s in registry.ordered_strategies(host)] == \
        ["deterministic", "spa_api", "llm"]
    # Record a spa_api win -> it is tried first next time, the rest keep default order.
    login_journal.record(f"https://{host}/login", "success", strategy="spa_api",
                         endpoint=f"https://{host}/spa/auth/login")
    assert [s.name for s in registry.ordered_strategies(host)] == \
        ["spa_api", "deterministic", "llm"]
    # An unknown host is unaffected (still default).
    assert [s.name for s in registry.ordered_strategies("other.example.com")] == \
        ["deterministic", "spa_api", "llm"]

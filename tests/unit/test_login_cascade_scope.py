"""Scope gate on adaptive-login decider actions (security fix).

The LLM decider reads untrusted target page content, so a prompt-injected
``navigate`` to an out-of-scope URL must be refused (credential/SSRF exfil).
Token-free: drives _apply_action against a fake browser.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from dast.browser.login_cascade import _apply_action


class _FakeBrowser:
    def __init__(self) -> None:
        self.navigated: List[str] = []
        self.filled: List[tuple] = []

    async def navigate(self, url: str) -> Dict[str, Any]:
        self.navigated.append(url)
        return {"ok": True, "url": url}

    async def fill(self, selector: str, value: str) -> Dict[str, Any]:
        self.filled.append((selector, value))
        return {"ok": True}

    async def click(self, selector: str, expect_nav: bool = False) -> Dict[str, Any]:
        return {"ok": True}


def _scope(*allowed: str):
    return lambda url: any(url.startswith(a) for a in allowed)


@pytest.mark.asyncio
async def test_navigate_out_of_scope_is_refused() -> None:
    browser = _FakeBrowser()
    in_scope = _scope("https://app.example.com")
    ok = await _apply_action(
        browser, {"action": "navigate", "selector": "https://evil.attacker.com/steal"},
        in_scope)
    assert ok is False
    assert browser.navigated == [], "out-of-scope navigate must not run"


@pytest.mark.asyncio
async def test_navigate_in_scope_is_allowed() -> None:
    browser = _FakeBrowser()
    in_scope = _scope("https://app.example.com")
    ok = await _apply_action(
        browser, {"action": "navigate", "selector": "https://app.example.com/login"},
        in_scope)
    assert ok is True
    assert browser.navigated == ["https://app.example.com/login"]


@pytest.mark.asyncio
async def test_fill_is_not_scope_gated() -> None:
    # fill/click act on the already-loaded in-scope page; only navigate is gated.
    browser = _FakeBrowser()
    ok = await _apply_action(
        browser, {"action": "fill", "selector": "#email", "value": "a@b.com"},
        _scope("https://app.example.com"))
    assert ok is True
    assert browser.filled == [("#email", "a@b.com")]

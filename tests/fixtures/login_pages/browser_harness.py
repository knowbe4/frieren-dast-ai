"""Shared Playwright helpers for the login-difficulty browser tiers.

Keeps the proxy-less AgentBrowser setup in one place so both the deterministic
suite and the cascade suite use the same launch path. The fixtures are local
127.0.0.1 pages, so the browser is launched WITHOUT a proxy by pre-assigning a
Playwright page to the AgentBrowser instance (login()/navigate() then run verbatim).
"""

from __future__ import annotations

import contextlib
from typing import AsyncIterator

from dast.browser.agent_browser import AgentBrowser


def chromium_available() -> bool:
    """True when Playwright + Chromium can actually launch (else tests skip)."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


@contextlib.asynccontextmanager
async def proxyless_agent_browser() -> AsyncIterator[AgentBrowser]:
    """Yield an AgentBrowser backed by a directly-launched (no-proxy) Chromium."""
    from playwright.async_api import async_playwright

    pw_ctx = async_playwright()
    pw = await pw_ctx.__aenter__()
    browser = await pw.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()
    agent = AgentBrowser(proxy_port=0, store=None, headless=True)
    agent._pw_ctx, agent._browser, agent._context, agent._page = pw_ctx, browser, context, page
    try:
        yield agent
    finally:
        await agent.close()

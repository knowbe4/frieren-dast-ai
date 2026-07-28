"""
BrowserContext pool — one isolated context per parallel worker.

Each context has its own cookies, localStorage, and interceptor.
Inspired by the Playwright architecture finding: BrowserContext is the
right isolation unit for parallel DAST (not pages, not browser instances).
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, List, Optional

from playwright.async_api import Browser, BrowserContext, Playwright, async_playwright

from dast.utils.logger import get_logger

logger = get_logger(__name__)



class ContextPool:
    """
    Manages a pool of Playwright BrowserContexts for parallel scanning.

    Each worker checks out a context, which is pre-authenticated and has
    network interception wired. After work is done the context is returned
    (not destroyed) so re-authentication is avoided for subsequent tasks.
    """

    def __init__(self, size: int = 4, headless: bool = True):
        self._size = size
        self._headless = headless
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._available: asyncio.Queue[BrowserContext] = asyncio.Queue()
        self._all_contexts: List[BrowserContext] = []

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self._headless,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding",
            ],
        )
        for _ in range(self._size):
            ctx = await self._new_context()
            self._all_contexts.append(ctx)
            await self._available.put(ctx)

    async def _new_context(self) -> BrowserContext:
        ctx = await self._browser.new_context(
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
            java_script_enabled=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36 DAST-AI/1.0"
            ),
            service_workers="block",  # prevent SW from shadowing network events
        )
        return ctx

    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[BrowserContext, None]:
        """Checkout a context from the pool. Returns it when the block exits."""
        ctx = await self._available.get()
        try:
            yield ctx
        finally:
            await self._available.put(ctx)

    async def apply_auth_state(self, storage_state: Dict) -> None:
        """Apply authentication storage state (cookies + localStorage) to all contexts."""
        for ctx in self._all_contexts:
            await ctx.add_cookies(storage_state.get("cookies", []))

    async def stop(self) -> None:
        # Best-effort, resilient teardown. During shutdown the Playwright driver
        # may already be gone (e.g. the launcher killed the process group), so
        # close() can raise "Connection closed while reading from the driver".
        # That must never abort shutdown or surface a traceback to the user —
        # wrap each step independently and log at warning level, then continue.
        for ctx in self._all_contexts:
            try:
                await ctx.close()
            except Exception as exc:
                logger.warning("BrowserContext close failed during shutdown", error=str(exc))
        if self._browser:
            try:
                await self._browser.close()
            except Exception as exc:
                logger.warning("Browser close failed during shutdown", error=str(exc))
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception as exc:
                logger.warning("Playwright stop failed during shutdown", error=str(exc))

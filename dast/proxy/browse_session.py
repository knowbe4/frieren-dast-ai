"""
Browse session — launches a Chromium browser routed through the local proxy.

All traffic the user generates flows through 127.0.0.1:8080, gets recorded
in the SessionStore, and is tagged with the active browse_session_id so the
dashboard can filter and scan only that session's requests.

Each named session gets its own isolated Playwright context so multiple users
can be logged in simultaneously without cookie interference.
"""

from __future__ import annotations

import uuid
from typing import Callable, Dict, List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)


class BrowseSession:
    def __init__(
        self,
        proxy_port: int,
        on_stop: Callable[[], None],
        name: Optional[str] = None,
    ) -> None:
        self._proxy_port = proxy_port
        self._on_stop    = on_stop
        self._browser    = None
        self._context    = None
        self._pw         = None
        self._pw_ctx     = None
        self.name: Optional[str] = name
        self.session_id: str = str(uuid.uuid4())[:8]
        self.running: bool   = False

    async def start(self, start_url: Optional[str] = None, headless: bool = False) -> None:
        from playwright.async_api import async_playwright

        self._pw_ctx = async_playwright()
        pw = await self._pw_ctx.__aenter__()
        self._pw = pw

        proxy_url = f"http://127.0.0.1:{self._proxy_port}"

        self._browser = await pw.chromium.launch(
            headless=headless,
            proxy={"server": proxy_url},
            args=[
                "--ignore-certificate-errors",
                "--window-size=1440,900",
                "--start-maximized",
            ],
        )
        self._context = await self._browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1440, "height": 900},
            no_viewport=not headless,
        )
        page = await self._context.new_page()

        if start_url:
            try:
                await page.goto(start_url, timeout=15000)
            except Exception as e:
                logger.debug("Browse session initial navigation error", error=str(e))

        self.running = True
        label = f'"{self.name}" ' if self.name else ""
        logger.info(f"Browse session {label}started", session_id=self.session_id, proxy=proxy_url)

        self._browser.on("disconnected", self._handle_close)

    async def get_playwright_cookies(self) -> List[dict]:
        """Return cookies directly from the Playwright context (isolated, not the proxy jar)."""
        if not self._context:
            return []
        try:
            return await self._context.cookies()
        except Exception:
            return []

    def _handle_close(self, *_) -> None:
        self.running = False
        label = f'"{self.name}" ' if self.name else ""
        logger.info(f"Browse session {label}closed", session_id=self.session_id)
        self._on_stop()

    async def stop(self) -> None:
        self.running = False
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._pw_ctx:
            try:
                await self._pw_ctx.__aexit__(None, None, None)
            except Exception:
                pass
        self._on_stop()
        label = f'"{self.name}" ' if self.name else ""
        logger.info(f"Browse session {label}stopped", session_id=self.session_id)


async def login_with_credentials(
    proxy_port: int,
    login_url: str,
    username: str,
    password: str,
    username_selector: str = "input[type=email],input[type=text],input[name*=user],input[name*=email],input[id*=user],input[id*=email]",
    password_selector: str = "input[type=password]",
    submit_selector: str = "button[type=submit],input[type=submit]",
) -> Dict[str, object]:
    """
    Headless login: navigates to login_url, fills credentials, submits, waits for
    navigation. Returns {"cookies": [...], "auth_headers": {}, "success": bool, "error": str}.

    Cookies are captured from the Playwright context after login — isolated from the
    proxy cookie jar so they don't overwrite any existing named sessions.
    """
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout

    proxy_url = f"http://127.0.0.1:{proxy_port}"

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            proxy={"server": proxy_url},
            args=["--ignore-certificate-errors"],
        )
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        # Capture Authorization / token headers seen after login
        auth_headers: Dict[str, str] = {}

        def _on_request(request) -> None:
            for k, v in (request.headers or {}).items():
                if k.lower() in ("authorization", "x-auth-token", "x-api-key"):
                    auth_headers[k] = v

        page.on("request", _on_request)

        try:
            await page.goto(login_url, timeout=20000, wait_until="domcontentloaded")

            # Fill username
            user_field = page.locator(username_selector).first
            await user_field.wait_for(state="visible", timeout=8000)
            await user_field.fill(username)

            # Fill password
            pass_field = page.locator(password_selector).first
            await pass_field.wait_for(state="visible", timeout=5000)
            await pass_field.fill(password)

            # Submit and wait for navigation
            await page.locator(submit_selector).first.click()
            try:
                await page.wait_for_url(lambda url: url != login_url, timeout=10000)
            except PWTimeout:
                # Some apps don't change URL — just wait for network idle
                await page.wait_for_load_state("networkidle", timeout=8000)

            cookies = await context.cookies()
            await browser.close()
            return {"cookies": cookies, "auth_headers": auth_headers, "success": True, "error": ""}

        except Exception as exc:
            try:
                await browser.close()
            except Exception:
                pass
            return {"cookies": [], "auth_headers": {}, "success": False, "error": str(exc)}

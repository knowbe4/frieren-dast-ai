"""
AgentBrowser — a headless, proxy-routed Playwright page the copilot drives.

Some workflows cannot be reproduced with raw ``send_request``: forms protected by
single-use CSRF tokens (ComposeToken, ASP.NET __VIEWSTATE, draftId) need a real
browser to fetch a fresh token and submit the form. This gives the agent a
persistent browser it can navigate / fill / click / read across tool calls.

The browser routes through the local proxy (so every request is captured in
history and in-scope) and is seeded with the proxy cookie jar (so it starts
authenticated, mirroring AuthAgent's login). One page per session, created lazily
and reused so multi-step form state persists between tool calls.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Compact page view for the model: forms (with fields), buttons, and links.
_SNAPSHOT_JS = r"""
() => {
  const vis = el => { const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden'; };
  const forms = [...document.querySelectorAll('form')].slice(0, 10).map(f => ({
    action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'get').toUpperCase(),
    fields: [...f.querySelectorAll('input,select,textarea')].slice(0, 40).map(i => ({
      tag: i.tagName.toLowerCase(), type: (i.getAttribute('type') || '').toLowerCase(),
      name: i.getAttribute('name') || '', id: i.id || '',
      hidden: (i.getAttribute('type') || '').toLowerCase() === 'hidden' || !vis(i),
    })),
  }));
  const buttons = [...document.querySelectorAll('button,input[type=submit],a[role=button]')]
    .filter(vis).slice(0, 25).map(b => ({
      text: (b.innerText || b.value || '').trim().slice(0, 40), id: b.id || '',
      type: (b.getAttribute('type') || '').toLowerCase(),
    }));
  const links = [...document.querySelectorAll('a[href]')].filter(vis).slice(0, 25).map(a => ({
    text: (a.innerText || '').trim().slice(0, 40), href: a.getAttribute('href') || '', id: a.id || '',
  }));
  return { forms, buttons, links };
}
"""


class AgentBrowser:
    """One lazily-launched headless browser page, driven by the browser_* tools."""

    def __init__(self, proxy_port: int = 8080, store: Optional[Any] = None,
                 read_only: bool = False) -> None:
        self._proxy_port = proxy_port
        self._store = store
        self._read_only = read_only
        self._pw_ctx: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._lock = asyncio.Lock()

    async def _ensure_page(self) -> Any:
        if self._page is not None:
            return self._page
        async with self._lock:
            if self._page is not None:
                return self._page
            from playwright.async_api import async_playwright

            self._pw_ctx = async_playwright()
            pw = await self._pw_ctx.__aenter__()
            self._browser = await pw.chromium.launch(
                headless=True,
                proxy={"server": f"http://127.0.0.1:{self._proxy_port}"},
                args=["--ignore-certificate-errors"],
            )
            self._context = await self._browser.new_context(ignore_https_errors=True)
            if self._read_only:
                from dast.utils.read_only import make_route_guard
                await self._context.route("**/*", make_route_guard("agent-browser"))
            await self._seed_cookies()
            self._page = await self._context.new_page()
            logger.info("AgentBrowser launched", proxy_port=self._proxy_port)
            return self._page

    async def _seed_cookies(self) -> None:
        """Seed the context with the proxy jar so it starts authenticated."""
        if self._store is None:
            return
        try:
            jar = self._store.get_all_cookies() or []
        except Exception as exc:
            logger.warning("AgentBrowser: cookie seed read failed", error=str(exc))
            return
        pw_cookies: List[dict] = []
        for c in jar:
            name, domain = c.get("name"), (c.get("domain") or "").lstrip(".")
            if not name or not domain:
                continue
            pw_cookies.append({
                "name": name, "value": c.get("value", ""), "domain": domain,
                "path": c.get("path", "/"), "secure": bool(c.get("secure", True)),
                "httpOnly": bool(c.get("httpOnly", False)),
            })
        if pw_cookies:
            try:
                await self._context.add_cookies(pw_cookies)
                logger.info("AgentBrowser seeded cookies from jar", count=len(pw_cookies))
            except Exception as exc:
                logger.warning("AgentBrowser: add_cookies failed", error=str(exc))

    async def export_cookies(self) -> Dict[str, str]:
        """Export all browser cookies as a {name: value} dict for send_request fallback."""
        if self._context is None:
            return {}
        try:
            cookies = await self._context.cookies()
            return {c["name"]: c["value"] for c in cookies if c.get("name")}
        except Exception as exc:
            logger.debug("AgentBrowser: export_cookies failed", error=str(exc))
            return {}

    async def clear_cookies(self) -> None:
        """Clear all browser cookies so stale sessions don't interfere with login."""
        if self._context is not None:
            try:
                await self._context.clear_cookies()
                logger.info("AgentBrowser cookies cleared")
            except Exception as exc:
                logger.debug("AgentBrowser: clear_cookies failed", error=str(exc))

    async def navigate(self, url: str, timeout_ms: int = 20000) -> Dict[str, Any]:
        page = await self._ensure_page()
        if any(kw in url.lower() for kw in ("/login", "/sign_in", "/signin", "/auth/sign")):
            await self.clear_cookies()
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        return {"ok": True, "url": page.url, "status": (resp.status if resp else None),
                "title": await page.title()}

    async def fill(self, selector: str, value: str, timeout_ms: int = 10000) -> Dict[str, Any]:
        page = await self._ensure_page()
        await page.fill(selector, value, timeout=timeout_ms)
        return {"ok": True, "selector": selector}

    async def click(self, selector: str, timeout_ms: int = 10000,
                    expect_nav: bool = False) -> Dict[str, Any]:
        page = await self._ensure_page()
        if expect_nav:
            try:
                async with page.expect_navigation(wait_until="domcontentloaded", timeout=timeout_ms):
                    await page.click(selector, timeout=timeout_ms)
            except Exception as exc:
                logger.debug("AgentBrowser click nav wait ended", error=str(exc))
        else:
            await page.click(selector, timeout=timeout_ms)
        return {"ok": True, "selector": selector, "url": page.url}

    async def wait_for(self, selector: str, timeout_ms: int = 10000,
                       state: str = "visible") -> Dict[str, Any]:
        page = await self._ensure_page()
        await page.wait_for_selector(selector, timeout=timeout_ms, state=state)
        return {"ok": True, "selector": selector}

    async def extract(self, selector: str, attribute: str = "value") -> Dict[str, Any]:
        page = await self._ensure_page()
        loc = page.locator(selector).first
        if attribute == "text":
            val = await loc.inner_text(timeout=5000)
        elif attribute == "value":
            val = await loc.input_value(timeout=5000)
        else:
            val = await loc.get_attribute(attribute, timeout=5000)
        return {"ok": True, "selector": selector, "attribute": attribute, "value": val}

    async def snapshot(self) -> Dict[str, Any]:
        page = await self._ensure_page()
        view = await page.evaluate(_SNAPSHOT_JS)
        return {"ok": True, "url": page.url, "title": await page.title(), **view}

    _EMAIL_SELECTORS = [
        "#REGISTRATION-EMAIL", "#LOGIN-EMAIL", "#email",
        "input[type=email]", "input[name=email]",
    ]
    _SUBMIT_SELECTORS = [
        "#LOGIN-SUBMIT-BTN", "button[type=submit]",
        "button:has-text('Continue')", "button:has-text('Next')",
        "button:has-text('Log In')", "button:has-text('Sign In')",
        "input[type=submit]",
    ]
    _PASSWORD_SELECTORS = ["#LOGIN-PASSWORD", "input[type=password]"]

    async def login(self, url: str, email: str, password: str,
                    timeout_ms: int = 30000) -> Dict[str, Any]:
        """Autonomous multi-step login: email -> [Continue] -> password -> submit.

        Handles both single-page and two-step login flows (e.g. KMSAT where
        the password field only appears after submitting the email).
        """
        page = await self._ensure_page()
        await self.clear_cookies()

        try:
            await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        except Exception as exc:
            return {"ok": False, "error": f"navigate failed: {str(exc)[:200]}"}

        async def _find_visible(selectors: List[str]) -> Any:
            for sel in selectors:
                try:
                    loc = page.locator(sel)
                    if await loc.count() > 0 and await loc.first.is_visible():
                        return loc.first
                except Exception:
                    continue
            return None

        email_field = await _find_visible(self._EMAIL_SELECTORS)
        if email_field is None:
            return {"ok": False, "error": "no email field found on the page",
                    "url": page.url}

        await email_field.fill(email)
        logger.info("browser_login: filled email", url=page.url)

        submit_btn = await _find_visible(self._SUBMIT_SELECTORS)
        if submit_btn is None:
            return {"ok": False, "error": "no submit button found after email",
                    "url": page.url}
        await submit_btn.click()
        await page.wait_for_timeout(3000)
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        password_field = None
        for _attempt in range(3):
            for sel in self._PASSWORD_SELECTORS:
                try:
                    loc = page.locator(sel)
                    if await loc.count() > 0:
                        await loc.first.wait_for(state="visible", timeout=5000)
                        password_field = loc.first
                        break
                except Exception:
                    continue
            if password_field is not None:
                break
            await page.wait_for_timeout(2000)

        if password_field is not None:
            logger.info("browser_login: two-step flow, filling password")
            for sel in self._EMAIL_SELECTORS:
                try:
                    loc = page.locator(sel)
                    if await loc.count() > 0 and await loc.first.is_visible():
                        current_val = await loc.first.input_value()
                        if not current_val or current_val != email:
                            await loc.first.fill(email)
                        break
                except Exception:
                    continue

            await password_field.fill(password)

            submit_btn2 = await _find_visible(self._SUBMIT_SELECTORS)
            if submit_btn2 is not None:
                try:
                    async with page.expect_navigation(
                        wait_until="networkidle", timeout=15000
                    ):
                        await submit_btn2.click()
                except Exception as exc:
                    logger.debug("browser_login: nav wait ended", error=str(exc)[:100])

        await page.wait_for_timeout(3000)

        final_path = page.url.lower().split("?")[0]
        login_paths = ("/login", "/signin", "/sign_in", "/sign-in", "/auth/login")
        logged_in = not any(final_path.endswith(p) or f"{p}/" in final_path for p in login_paths)
        cookies = await self.export_cookies()
        csrf_token = cookies.get("CSRF-TOKEN")

        logger.info("browser_login: complete",
                     logged_in=logged_in, url=page.url, cookies=len(cookies))

        return {
            "ok": logged_in,
            "url": page.url,
            "logged_in": logged_in,
            "cookies_count": len(cookies),
            "csrf_token": csrf_token[:20] + "..." if csrf_token and len(csrf_token) > 20 else csrf_token,
            "cookies": cookies,
        }

    async def close(self) -> None:
        try:
            if self._browser is not None:
                await self._browser.close()
        except Exception as exc:
            logger.debug("AgentBrowser close error", error=str(exc))
        finally:
            try:
                if self._pw_ctx is not None:
                    await self._pw_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            self._page = self._context = self._browser = self._pw_ctx = None

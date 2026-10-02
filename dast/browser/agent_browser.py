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

    def __init__(self, proxy_port: int = 8080, store: Optional[Any] = None) -> None:
        self._proxy_port = proxy_port
        self._store = store
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

    async def navigate(self, url: str, timeout_ms: int = 20000) -> Dict[str, Any]:
        page = await self._ensure_page()
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

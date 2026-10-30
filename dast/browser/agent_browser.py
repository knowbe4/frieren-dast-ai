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
    """Browser page driven by the browser_* tools.

    Headed (visible) by default so the operator can complete MFA prompts,
    captchas, and other interactive challenges that automation cannot handle.
    Set ``headless=True`` via the constructor or the ``BROWSER_HEADLESS=true``
    env var for CI/unattended runs — note that any login flow requiring manual
    interaction (MFA, captcha) will fail in headless mode.
    """

    def __init__(self, proxy_port: int = 8080, store: Optional[Any] = None,
                 read_only: bool = False, headless: Optional[bool] = None) -> None:
        self._proxy_port = proxy_port
        self._store = store
        self._read_only = read_only
        if headless is not None:
            self._headless = headless
        else:
            import os
            self._headless = os.environ.get("BROWSER_HEADLESS", "").lower() in ("true", "1", "yes")
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
                headless=self._headless,
                proxy={"server": f"http://127.0.0.1:{self._proxy_port}"},
                args=["--ignore-certificate-errors"],
            )
            if not self._headless:
                logger.info("AgentBrowser launched in headed mode (visible window)")

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
        "input[name=username]", "input[name=login]",
    ]
    _SUBMIT_SELECTORS = [
        "#LOGIN-SUBMIT-BTN", "button[type=submit]",
        "button[data-action-button-primary=true]",
        "button:has-text('Continue')", "button:has-text('Next')",
        "button:has-text('Log In')", "button:has-text('Sign In')",
        "input[type=submit]",
    ]
    _PASSWORD_SELECTORS = [
        "#LOGIN-PASSWORD", "input[type=password]",
        "#password", "input[name=password]",
    ]
    _SSO_DOMAINS = ("auth0", "okta", "login.microsoftonline",
                    "accounts.google", "hrmauth", "cognito")
    _MFA_INDICATORS = ("/mfa", "/otp", "/challenge", "/two-factor",
                       "/u/mfa-otp-challenge", "/u/mfa-detect-browser")

    async def login(self, url: str, email: str, password: str,
                    timeout_ms: int = 30000) -> Dict[str, Any]:
        """Autonomous multi-step login: email -> [Continue] -> password -> submit.

        Handles single-page, two-step, and SSO/Auth0 cross-domain flows:
        - Single-page: email + password on one page, click submit.
        - Two-step (KMSAT): email -> Continue -> password appears on same domain.
        - SSO (Auth0/Okta): email -> Continue -> redirect to IdP domain ->
          password on IdP -> MFA prompt -> redirect back to app.
        If MFA is required, returns mfa_required=True so the operator can
        complete the challenge manually.
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
        pre_submit_url = page.url
        await submit_btn.click()
        await page.wait_for_timeout(3000)
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        # Detect SSO redirect: the page may have navigated to an IdP domain
        if page.url != pre_submit_url:
            logger.info("browser_login: page navigated after email submit",
                        from_url=pre_submit_url[:60], to_url=page.url[:60])

        password_field = None
        for _attempt in range(3):
            logger.debug("browser_login: password field attempt",
                         attempt=_attempt + 1, url=page.url)
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
            if _attempt == 1:
                retry_btn = await _find_visible(self._SUBMIT_SELECTORS)
                if retry_btn is not None:
                    logger.info("browser_login: re-clicking submit (SPA may not have registered first click)")
                    await retry_btn.click()
                    await page.wait_for_timeout(3000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=8000)
                    except Exception:
                        pass
                    continue
            await page.wait_for_timeout(2000)

        if password_field is None:
            snapshot = None
            try:
                snapshot = await self.snapshot()
            except Exception:
                pass
            logger.warning("browser_login: no password field after retries",
                           url=page.url, snapshot_buttons=len(
                               (snapshot or {}).get("buttons", [])))
            return {
                "ok": False,
                "error": "no password field found after email submission",
                "url": page.url,
                "snapshot": snapshot,
                "cookies": await self.export_cookies(),
            }

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
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass

        await page.wait_for_timeout(3000)

        # Detect MFA prompt: still on IdP with a challenge path
        final_url_lower = page.url.lower()
        mfa_required = any(ind in final_url_lower for ind in self._MFA_INDICATORS)
        if not mfa_required:
            # Also check for OTP/code input fields on the page
            try:
                otp_loc = page.locator("input[name=code], input[name=otp], input[type=tel][maxlength='6']")
                if await otp_loc.count() > 0:
                    mfa_required = True
            except Exception:
                pass

        if mfa_required:
            cookies = await self.export_cookies()
            logger.info("browser_login: MFA required, returning for manual completion",
                        url=page.url)
            return {
                "ok": False,
                "url": page.url,
                "logged_in": False,
                "mfa_required": True,
                "cookies_count": len(cookies),
                "cookies": cookies,
            }

        # Determine if login succeeded: not on a login page and not on an IdP domain
        final_path = final_url_lower.split("?")[0]
        login_paths = ("/login", "/signin", "/sign_in", "/sign-in",
                        "/auth/login", "/u/login", "/authorize")
        on_login_page = any(final_path.endswith(p) or f"{p}/" in final_path
                           for p in login_paths)
        on_sso_domain = any(d in final_url_lower for d in self._SSO_DOMAINS)
        logged_in = not on_login_page and not on_sso_domain

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

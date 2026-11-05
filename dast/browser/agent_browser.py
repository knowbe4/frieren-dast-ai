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
import time as _time
from typing import Any, Dict, List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Compact page view for the model: forms (with fields), buttons, and links.
_SNAPSHOT_JS = r"""
() => {
  const vis = el => { const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden'; };
  // Traverse OPEN shadow roots too: modern SPAs (SvelteKit, web components, the target's
  // login) render the form inside shadow DOM, which document.querySelectorAll does NOT
  // pierce — so a plain snapshot reported 0 inputs/buttons on a form that is clearly
  // there. deepQA walks every shadowRoot so the copilot can see (and then fill/click,
  // since Playwright CSS selectors pierce open shadow DOM) the real fields.
  const deepQA = (root, sel, out) => {
    try { out.push(...root.querySelectorAll(sel)); } catch (e) {}
    root.querySelectorAll('*').forEach(el => { if (el.shadowRoot) deepQA(el.shadowRoot, sel, out); });
    return out;
  };
  const field = i => ({
    tag: i.tagName.toLowerCase(), type: (i.getAttribute('type') || '').toLowerCase(),
    name: i.getAttribute('name') || '', id: i.id || '',
    placeholder: i.getAttribute('placeholder') || '',
    label: i.getAttribute('aria-label') || '',
    autocomplete: i.getAttribute('autocomplete') || '',
    hidden: (i.getAttribute('type') || '').toLowerCase() === 'hidden' || !vis(i),
  });
  const forms = deepQA(document, 'form', []).slice(0, 10).map(f => ({
    id: f.id || '', name: f.getAttribute('name') || '',
    action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'get').toUpperCase(),
    fields: deepQA(f, 'input,select,textarea', []).slice(0, 40).map(field),
  }));
  // All interactive fields across the page (incl. shadow DOM), even when they are NOT
  // wrapped in a <form> element — SPA login forms frequently are not.
  const fields = deepQA(document, 'input,select,textarea', []).slice(0, 40).map(field);
  const buttons = deepQA(document,
      'button,input[type=submit],input[type=button],[role=button]', [])
    .filter(vis).slice(0, 25).map(b => ({
      text: (b.innerText || b.value || '').trim().slice(0, 40), id: b.id || '',
      name: b.getAttribute('name') || '',
      type: (b.getAttribute('type') || '').toLowerCase(),
    }));
  const links = deepQA(document, 'a[href]', []).filter(vis).slice(0, 25).map(a => ({
    text: (a.innerText || '').trim().slice(0, 40), href: a.getAttribute('href') || '', id: a.id || '',
  }));
  return { forms, fields, buttons, links };
}
"""

# True once the page has mounted at least `min` interactive elements, counted across
# the document, open shadow roots, and same-origin iframes. Used to tell a hydrated SPA
# from its pre-render shell: a single "Home" link (count 1) must NOT pass, so the wait
# requires a real threshold rather than "any element".
_HYDRATION_JS = r"""
(min) => {
  const SEL = 'input,button,a,form,select,textarea,[role=button]';
  const count = (root) => {
    let n = 0;
    try { n += root.querySelectorAll(SEL).length; } catch (e) {}
    try { root.querySelectorAll('*').forEach(el => {
      if (el.shadowRoot) n += count(el.shadowRoot); }); } catch (e) {}
    try { root.querySelectorAll('iframe,frame').forEach(f => {
      try { if (f.contentDocument) n += count(f.contentDocument); } catch (e) {} }); } catch (e) {}
    return n;
  };
  return count(document) >= min;
}
"""

# Pick the best submit control for a login form and tag it with data-dast-submit.
# Scores candidates: sign-in text wins, search/nav/secondary text loses, and being
# in the same form as the password/email field is a strong boost. This stops the
# deterministic engine from clicking a header "Search" button on a noisy page.
_PICK_SUBMIT_JS = r"""
() => {
  // Traverse open shadow roots too (web components): querySelectorAll alone does
  // not pierce them, so a shadow-DOM login form's submit would be missed.
  const deepQA = (root, sel, out) => {
    out.push(...root.querySelectorAll(sel));
    root.querySelectorAll('*').forEach(el => { if (el.shadowRoot) deepQA(el.shadowRoot, sel, out); });
    return out;
  };
  const deepFirst = (sel) => deepQA(document, sel, [])[0] || null;
  deepQA(document, '[data-dast-submit]', []).forEach(e => e.removeAttribute('data-dast-submit'));
  const POS = ['continue','next','sign in','log in','login','log on','sign on','submit','yes','authorize','allow','proceed','done','entrar','acessar','conectar'];
  const NEG = ['search','buscar','go','subscribe','cancel','back','forgot','reset','create account','sign up','register','skip','no'];
  const vis = el => { const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden' && !el.disabled; };
  const cands = deepQA(document,
      'button,input[type=submit],input[type=button],[role=button]', []).filter(vis);
  if (!cands.length) return null;
  const pwField = deepFirst('input[type=password]');
  const emField = deepFirst(
      'input[type=email],input[name=email],input[name=username],input[name=user],'
      + 'input[name=identifier],input[name=loginfmt],input[name=login],input[name=log]');
  const pwForm = pwField && pwField.form, emForm = emField && emField.form;
  const score = el => {
    const t = (el.innerText || el.value || '').trim().toLowerCase();
    let s = 0;
    if (POS.some(p => t.includes(p))) s += 5;
    if (NEG.some(n => t === n || t.includes(n))) s -= 8;
    if (pwForm && el.form === pwForm) s += 4;
    else if (emForm && el.form === emForm) s += 3;
    if ((el.getAttribute('type') || '').toLowerCase() === 'submit') s += 1;
    return s;
  };
  let best = null, bestScore = -1e9;
  for (const el of cands) { const s = score(el); if (s > bestScore) { bestScore = s; best = el; } }
  if (!best || bestScore <= -8) return null;
  best.setAttribute('data-dast-submit', '1');
  return { score: bestScore, text: (best.innerText || best.value || '').trim().slice(0, 40) };
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
                 read_only: bool = False, headless: Optional[bool] = None,
                 session_name: Optional[str] = None) -> None:
        self._proxy_port = proxy_port
        self._store = store
        self._read_only = read_only
        # When set, seed/resync cookies from this named session's isolated jar instead
        # of the shared global jar, so a per-session browser stays isolated from other
        # concurrent copilot runs. Settable after construction (the session name is
        # known only once a login profile is activated).
        self.session_name = session_name
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
        self._last_cookie_sync: float = 0.0

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
        """Seed the context so it starts authenticated. For a session-scoped browser,
        seed ONLY this run's named-session cookies (isolated); otherwise the global jar."""
        if self._store is None:
            return
        try:
            if self.session_name is not None:
                jar = self._store.get_named_session_cookies(self.session_name) or []
            else:
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
                self._last_cookie_sync = _time.time()
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

    async def resync_cookies(self) -> int:
        """Re-read cookies from the proxy jar into the browser context.

        Replaces all browser cookies with current jar contents so that tokens
        refreshed by operator browsing (or by a login flow) are picked up by
        subsequent ``browser_fetch`` / ``browser_navigate`` calls.
        """
        if self._context is None or self._store is None:
            return 0
        try:
            # Unscoped: replace all context cookies with the current global jar.
            # Scoped: do NOT clear — the context already holds THIS session's own login;
            # only (re)layer the saved named-session cookies so we never wipe the fresh
            # login of a credential-only profile whose named jar is still empty.
            if self.session_name is None:
                await self._context.clear_cookies()
            await self._seed_cookies()
            cookies = await self._context.cookies()
            logger.info("AgentBrowser cookies re-synced from jar", count=len(cookies))
            return len(cookies)
        except Exception as exc:
            logger.debug("AgentBrowser: resync_cookies failed", error=str(exc))
            return 0

    async def ensure_fresh_cookies(self) -> None:
        """Re-sync cookies if the last sync was more than 30 seconds ago."""
        if _time.time() - self._last_cookie_sync > 30:
            await self.resync_cookies()

    async def export_cookies_full(self) -> List[dict]:
        """Export the browser's cookies as Playwright dicts (name/value/domain/path/...),
        for importing into the proxy jar (which keys by domain). Unlike export_cookies,
        this preserves the domain so get_cookies_for_host can match."""
        if self._context is None:
            return []
        try:
            return list(await self._context.cookies())
        except Exception as exc:
            logger.debug("AgentBrowser: export_cookies_full failed", error=str(exc))
            return []

    async def api_post(self, url: str, headers: Optional[Dict[str, str]] = None,
                       body: Optional[str] = None) -> Dict[str, Any]:
        """Network-level POST through the browser context (carries its cookies, bypasses
        CORS). Used by the SPA JSON-API login strategy: it hits the app's JSON auth
        endpoint without touching the form DOM, so it works regardless of shadow DOM /
        iframes. Returns {ok, status, text, headers}."""
        page = await self._ensure_page()
        fetch_kwargs: Dict[str, Any] = {"method": "POST", "headers": headers or {}}
        if body is not None:
            fetch_kwargs["data"] = body
        try:
            resp = await page.request.fetch(url, **fetch_kwargs)
            text = await resp.text()
            return {"ok": True, "status": resp.status, "text": text[:20000],
                    "headers": {k: v for k, v in resp.headers.items()}}
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:200], "status": None, "text": ""}

    async def _wait_for_hydration(self, page: Any, timeout_ms: int = 6000,
                                  min_elements: int = 3) -> bool:
        """Wait for the SPA to mount real interactive content (``>= min_elements`` across
        the document + open shadow roots + same-origin iframes). Returns True when content
        appeared, False on timeout. Best-effort: a genuinely sparse page returns False
        without raising, so callers never block on it."""
        try:
            await page.wait_for_function(_HYDRATION_JS, arg=min_elements, timeout=timeout_ms)
            return True
        except Exception as exc:
            logger.debug("AgentBrowser hydration wait ended", error=str(exc)[:120])
            return False

    async def navigate(self, url: str, timeout_ms: int = 20000,
                       wait_selector: Optional[str] = None) -> Dict[str, Any]:
        page = await self._ensure_page()
        if any(kw in url.lower() for kw in ("/login", "/sign_in", "/signin", "/auth/sign")):
            await self.clear_cookies()
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        # domcontentloaded fires BEFORE the JS framework mounts, so a single-page app
        # returns an empty shell — snapshot/fill/click would all act on an unrendered
        # page. networkidle is intentionally NOT used: a continuous WebSocket/polling SPA
        # (e.g. modstore3) never reaches it, so it only burns the whole timeout budget.
        # Instead wait for real interactive content (a one-link shell does not count), or
        # for an explicit caller-supplied selector when the target control is known.
        if wait_selector:
            try:
                await page.wait_for_selector(wait_selector, timeout=min(timeout_ms, 10000))
            except Exception as exc:
                logger.debug("AgentBrowser navigate: wait_selector ended", error=str(exc)[:120])
        else:
            await self._wait_for_hydration(page, timeout_ms=min(timeout_ms, 6000))
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

    async def wait_for_text(self, text: str, timeout_ms: int = 10000) -> Dict[str, Any]:
        """Wait until *text* appears anywhere in the page body — for client-rendered SPAs
        where content arrives without a stable selector to target."""
        page = await self._ensure_page()
        await page.wait_for_function(
            "(t) => ((document.body && document.body.innerText) || '').includes(t)",
            arg=text, timeout=timeout_ms,
        )
        return {"ok": True, "text": text}

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
        # A snapshot taken right after navigate can catch the pre-hydration shell. Settle
        # for real content first (best-effort; a sparse page still snapshots promptly).
        await self._wait_for_hydration(page, timeout_ms=3000)
        view = await page.evaluate(_SNAPSHOT_JS)
        return {"ok": True, "url": page.url, "title": await page.title(), **view}

    async def _find_submit(self, page: Any) -> Any:
        """Best submit control for the login form: scored to prefer the sign-in
        button in the password/email form over a header Search/Go button. Falls
        back to the static selector list (text-filtered) when scoring finds none."""
        try:
            picked = await page.evaluate(_PICK_SUBMIT_JS)
        except Exception as exc:
            logger.debug("_find_submit: scoring failed", error=str(exc)[:120])
            picked = None
        if picked:
            loc = page.locator('[data-dast-submit="1"]')
            try:
                if await loc.count() > 0 and await loc.first.is_visible():
                    logger.debug("_find_submit: scored submit",
                                 text=picked.get("text"), score=picked.get("score"))
                    return loc.first
            except Exception:
                pass
        for sel in self._SUBMIT_SELECTORS:
            try:
                loc = page.locator(sel)
                if await loc.count() > 0 and await loc.first.is_visible():
                    return loc.first
            except Exception:
                continue
        return None

    _LOGIN_PATHS = ("/login", "/signin", "/sign_in", "/sign-in",
                    "/auth/login", "/u/login", "/authorize")

    async def _login_success_result(self, page: Any) -> Dict[str, Any]:
        """Build the login result dict from the current page: logged_in is true when
        the URL is no longer a login/SSO page. Shared by the single-page short-circuit
        and the end of login()."""
        current_url = page.url.lower()
        final_path = current_url.split("?")[0]
        on_login_page = any(final_path.endswith(p) or f"{p}/" in final_path
                            for p in self._LOGIN_PATHS)
        on_sso_domain = any(d in current_url for d in self._SSO_DOMAINS)
        logged_in = not on_login_page and not on_sso_domain
        cookies = await self.export_cookies()
        csrf_token = cookies.get("CSRF-TOKEN")
        return {
            "ok": logged_in,
            "url": page.url,
            "logged_in": logged_in,
            "cookies_count": len(cookies),
            "csrf_token": csrf_token[:20] + "..." if csrf_token and len(csrf_token) > 20 else csrf_token,
            "cookies": cookies,
        }

    _EMAIL_SELECTORS = [
        "#REGISTRATION-EMAIL", "#LOGIN-EMAIL", "#email",
        "input[type=email]", "input[name=email]",
        # Real-world username field names across common products:
        # username (generic), identifier (Okta), loginfmt (Azure AD),
        # log (WordPress), UserName (ADFS), user/userid, j_username (JEE), login.
        "input[name=username i]", "input[name=identifier i]",
        "input[name=loginfmt i]", "input[name=log i]",
        "input[name=user i]", "input[name=userid i]",
        "input[name=j_username i]", "input[name=login i]",
        "input[autocomplete=username]", "input[autocomplete=email]",
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
                    timeout_ms: int = 60000) -> Dict[str, Any]:
        """Autonomous multi-step login: email -> [Continue] -> password -> submit.

        Handles single-page, two-step, and SSO/Auth0 cross-domain flows:
        - Single-page: email + password on one page, click submit.
        - Two-step (SSO): email -> Continue -> password appears on same domain.
        - SSO (Auth0/Okta): email -> Continue -> redirect to IdP domain ->
          password on IdP -> MFA prompt -> redirect back to app.
        If MFA is required, returns mfa_required=True so the operator can
        complete the challenge manually.
        """
        page = await self._ensure_page()
        await self.clear_cookies()

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:
            return {"ok": False, "error": f"navigate failed: {str(exc)[:200]}"}
        try:
            await page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass

        async def _find_visible(selectors: List[str]) -> Any:
            for sel in selectors:
                try:
                    loc = page.locator(sel)
                    if await loc.count() > 0 and await loc.first.is_visible():
                        return loc.first
                except Exception:
                    continue
            return None

        email_field = None
        for _email_attempt in range(3):
            email_field = await _find_visible(self._EMAIL_SELECTORS)
            if email_field is not None:
                break
            logger.debug("browser_login: email field not visible yet",
                         attempt=_email_attempt + 1, url=page.url)
            await page.wait_for_timeout(2000)
        if email_field is None:
            return {"ok": False, "error": "no email field found on the page",
                    "url": page.url}

        await email_field.fill(email)
        logger.info("browser_login: filled email", url=page.url)

        # Single-page forms: if the password field is already visible, fill it
        # BEFORE submitting. Otherwise a form without HTML5 `required` posts with
        # an empty password on the first submit and fails. (Two-step forms hide
        # the password until a Continue/Next click, so this is a no-op there.)
        early_password = await _find_visible(self._PASSWORD_SELECTORS)
        if early_password is not None:
            try:
                await early_password.fill(password)
                logger.info("browser_login: single-page form, filled password early",
                            url=page.url)
            except Exception as exc:
                logger.debug("browser_login: early password fill failed",
                             error=str(exc)[:120])

        submit_btn = await self._find_submit(page)
        if submit_btn is None:
            return {"ok": False, "error": "no submit button found after email",
                    "url": page.url}
        pre_submit_url = page.url
        await submit_btn.click()
        await page.wait_for_timeout(3000)
        try:
            await page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass

        # Single-page forms are a one-shot: having filled both fields and clicked
        # submit, the outcome is settled. Classify it and return — do NOT fall into
        # the two-step password search, which can mis-click interstitials (consent
        # pages, MFA "Verify") and muddle the result.
        if early_password is not None:
            low = page.url.lower()
            on_mfa = any(ind in low for ind in self._MFA_INDICATORS)
            if not on_mfa:
                try:
                    otp = page.locator(
                        "input[name=code], input[name=otp], input[type=tel][maxlength='6']")
                    on_mfa = await otp.count() > 0
                except Exception:
                    on_mfa = False
            if on_mfa:
                cookies = await self.export_cookies()
                logger.info("browser_login: single-page submit hit an MFA wall",
                            url=page.url)
                return {"ok": False, "url": page.url, "logged_in": False,
                        "mfa_required": True, "cookies_count": len(cookies),
                        "cookies": cookies}
            result = await self._login_success_result(page)
            if result["logged_in"]:
                logger.info("browser_login: single-page login succeeded", url=page.url)
            else:
                logger.info("browser_login: single-page submit did not authenticate "
                            "(invalid creds, or a consent/Authorize step the "
                            "deterministic engine does not handle)", url=page.url)
                result.setdefault("error", "submitted but not authenticated")
            return result

        # Detect SSO redirect: the page may have navigated to an IdP domain.
        # Federated login often lands on a new email-first form on the IdP
        # (e.g. app → SSO → email → Continue → password).
        # If we detect an email field but no password, fill + submit again.
        sso_redirected = page.url != pre_submit_url
        if sso_redirected:
            logger.info("browser_login: SSO redirect detected",
                        from_url=pre_submit_url[:60], to_url=page.url[:60])
            await page.wait_for_timeout(3000)
            idp_email = await _find_visible(self._EMAIL_SELECTORS)
            idp_password = await _find_visible(self._PASSWORD_SELECTORS)
            if idp_email is not None and idp_password is None:
                logger.info("browser_login: IdP has email-first form, filling + submitting")
                try:
                    current_val = await idp_email.input_value()
                    if not current_val or current_val != email:
                        await idp_email.fill(email)
                except Exception:
                    await idp_email.fill(email)
                idp_submit = await self._find_submit(page)
                if idp_submit is not None:
                    await idp_submit.click()
                    await page.wait_for_timeout(3000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass

        password_field = None
        for _attempt in range(5):
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
            if _attempt == 2:
                retry_btn = await self._find_submit(page)
                if retry_btn is not None:
                    logger.info("browser_login: re-clicking submit (SPA may not have registered first click)")
                    await retry_btn.click()
                    await page.wait_for_timeout(3000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass
                    continue
            await page.wait_for_timeout(3000)

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

        submit_btn2 = await self._find_submit(page)
        if submit_btn2 is not None:
            try:
                async with page.expect_navigation(
                    wait_until="domcontentloaded", timeout=15000
                ):
                    await submit_btn2.click()
            except Exception as exc:
                logger.debug("browser_login: nav wait ended", error=str(exc)[:100])
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
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
            if not self._headless:
                logger.info("browser_login: MFA detected, waiting for operator "
                            "to complete in visible browser", url=page.url)
                for _poll in range(24):
                    await page.wait_for_timeout(5000)
                    poll_url = page.url.lower()
                    still_mfa = any(ind in poll_url for ind in self._MFA_INDICATORS)
                    on_sso = any(d in poll_url for d in self._SSO_DOMAINS)
                    if not still_mfa and not on_sso:
                        logger.info("browser_login: MFA completed by operator",
                                    url=page.url)
                        mfa_required = False
                        break
                    if _poll % 6 == 0:
                        logger.debug("browser_login: waiting for MFA completion",
                                     attempt=_poll, url=page.url[:60])

            if mfa_required:
                cookies = await self.export_cookies()
                logger.info("browser_login: MFA not completed within timeout",
                            url=page.url)
                return {
                    "ok": False,
                    "url": page.url,
                    "logged_in": False,
                    "mfa_required": True,
                    "cookies_count": len(cookies),
                    "cookies": cookies,
                }

        # Re-read the current URL (may have changed during MFA polling)
        current_url = page.url.lower()
        final_path = current_url.split("?")[0]
        login_paths = ("/login", "/signin", "/sign_in", "/sign-in",
                        "/auth/login", "/u/login", "/authorize")
        on_login_page = any(final_path.endswith(p) or f"{p}/" in final_path
                           for p in login_paths)
        on_sso_domain = any(d in current_url for d in self._SSO_DOMAINS)
        logged_in = not on_login_page and not on_sso_domain

        # SSO flows may land back on /login even when authenticated (SPA
        # hasn't checked session yet). If we have cookies but are still on
        # a login page, navigate to the app root to trigger a client-side
        # redirect to the dashboard.
        if on_login_page and not on_sso_domain:
            cookies_check = await self.export_cookies()
            if len(cookies_check) >= 3:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                root_url = f"{parsed.scheme}://{parsed.netloc}/"
                logger.info("browser_login: on login page with cookies, "
                            "navigating to root to verify auth", root=root_url)
                try:
                    await page.goto(root_url, wait_until="domcontentloaded",
                                    timeout=15000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass
                    current_url = page.url.lower()
                    final_path = current_url.split("?")[0]
                    on_login_page = any(
                        final_path.endswith(p) or f"{p}/" in final_path
                        for p in login_paths)
                    logged_in = not on_login_page
                except Exception as exc:
                    logger.debug("browser_login: root navigation failed",
                                 error=str(exc)[:100])

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

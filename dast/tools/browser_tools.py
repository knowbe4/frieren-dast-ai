"""
browser_* tools — let the copilot drive a real browser for workflows raw
send_request cannot reproduce (forms with single-use CSRF tokens: ComposeToken,
ASP.NET __VIEWSTATE, draftId). The agent navigates, snapshots the page to see
its forms/buttons, fills fields, clicks, waits, and extracts values (e.g. a fresh
hidden token). Backed by ``ctx.browser`` (an AgentBrowser), present only for the
in-process copilot; the MCP/triage callers get a clear "not available".

The browser routes through the proxy (traffic recorded in-scope) and is seeded
with the proxy cookie jar (starts authenticated).
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def _browser(ctx: ToolContext) -> Any:
    return getattr(ctx, "browser", None)


def _unavailable() -> Dict[str, Any]:
    return {"ok": False, "error": "browser driving is not available in this context"}


async def _navigate(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = _browser(ctx)
    if browser is None:
        return _unavailable()
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}
    try:
        return await browser.navigate(url)
    except Exception as exc:
        return {"ok": False, "error": f"navigate failed: {str(exc)[:200]}", "url": url}


async def _snapshot(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = _browser(ctx)
    if browser is None:
        return _unavailable()
    try:
        return await browser.snapshot()
    except Exception as exc:
        return {"ok": False, "error": f"snapshot failed: {str(exc)[:200]}"}


async def _fill(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = _browser(ctx)
    if browser is None:
        return _unavailable()
    selector = str(args.get("selector", "")).strip()
    if not selector:
        return {"ok": False, "error": "selector is required"}
    value = str(args.get("value", ""))
    try:
        return await browser.fill(selector, value)
    except Exception as exc:
        return {"ok": False, "error": f"fill failed: {str(exc)[:200]}", "selector": selector}


async def _click(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = _browser(ctx)
    if browser is None:
        return _unavailable()
    selector = str(args.get("selector", "")).strip()
    if not selector:
        return {"ok": False, "error": "selector is required"}
    expect_nav = bool(args.get("expect_navigation", False))
    try:
        return await browser.click(selector, expect_nav=expect_nav)
    except Exception as exc:
        return {"ok": False, "error": f"click failed: {str(exc)[:200]}", "selector": selector}


async def _wait_for(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = _browser(ctx)
    if browser is None:
        return _unavailable()
    selector = str(args.get("selector", "")).strip()
    if not selector:
        return {"ok": False, "error": "selector is required"}
    state = str(args.get("state", "visible")).strip() or "visible"
    try:
        return await browser.wait_for(selector, state=state)
    except Exception as exc:
        return {"ok": False, "error": f"wait_for failed: {str(exc)[:200]}", "selector": selector}


async def _extract(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = _browser(ctx)
    if browser is None:
        return _unavailable()
    selector = str(args.get("selector", "")).strip()
    if not selector:
        return {"ok": False, "error": "selector is required"}
    attribute = str(args.get("attribute", "value")).strip() or "value"
    try:
        return await browser.extract(selector, attribute)
    except Exception as exc:
        return {"ok": False, "error": f"extract failed: {str(exc)[:200]}", "selector": selector}


_URL_SCHEMA = {"type": "object", "properties": {
    "url": {"type": "string", "description": "In-scope URL to navigate the browser to."}}, "required": ["url"]}
_SEL_SCHEMA = {"type": "object", "properties": {
    "selector": {"type": "string", "description": "CSS selector of the target element."},
    "value": {"type": "string", "description": "Value to fill (fill only)."},
    "attribute": {"type": "string", "description": "Attribute to read: 'value' (default), 'text', or any HTML attribute (extract only)."},
    "state": {"type": "string", "description": "Wait state: visible (default), attached, hidden (wait_for only)."},
    "expect_navigation": {"type": "boolean", "description": "Set true if the click triggers a page navigation (click only)."},
}, "required": ["selector"]}
_EMPTY_SCHEMA = {"type": "object", "properties": {}}

register(Tool(name="browser_navigate", input_schema=_URL_SCHEMA, handler=_navigate, tags=["browser", "active"],
    description="Navigate the agent browser to an in-scope URL. Returns the final url, status, and page title. "
                "Use before snapshot/fill/click to load a page (e.g. a form you must submit with a fresh CSRF token)."))
register(Tool(name="browser_snapshot", input_schema=_EMPTY_SCHEMA, handler=_snapshot, tags=["browser", "read"],
    description="Read the current page: its url, title, forms (with field name/type/hidden), visible buttons, and links. "
                "Use this to discover what selectors to fill/click — do not guess the DOM."))
register(Tool(name="browser_fill", input_schema=_SEL_SCHEMA, handler=_fill, tags=["browser", "active"],
    description="Fill a form field in the agent browser (selector + value). Use for inputs/textareas before submitting a form."))
register(Tool(name="browser_click", input_schema=_SEL_SCHEMA, handler=_click, tags=["browser", "active"],
    description="Click an element in the agent browser (e.g. a submit button). Set expect_navigation=true when the click loads a new page."))
register(Tool(name="browser_wait_for", input_schema=_SEL_SCHEMA, handler=_wait_for, tags=["browser", "read"],
    description="Wait for an element to reach a state (visible/attached/hidden) in the agent browser — e.g. a password field revealed after a Continue click."))
register(Tool(name="browser_extract", input_schema=_SEL_SCHEMA, handler=_extract, tags=["browser", "read"],
    description="Read a value from the current page: an input's value (default), an element's text, or any HTML attribute. "
                "Use to pull a fresh CSRF/hidden token out of a form before building a request."))


_LOGIN_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Login page URL (e.g. https://app.example.com/login)."},
        "email": {"type": "string", "description": "Email / username to log in with."},
        "password": {"type": "string", "description": "Password for the account."},
    },
    "required": ["url", "email", "password"],
}


async def _login(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = _browser(ctx)
    if browser is None:
        return _unavailable()
    url = str(args.get("url", "")).strip()
    email = str(args.get("email", "")).strip()
    password = str(args.get("password", ""))
    if not url:
        return {"ok": False, "error": "url is required"}
    if not email:
        return {"ok": False, "error": "email is required"}
    if not password:
        return {"ok": False, "error": "password is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}
    try:
        result = await browser.login(url, email, password)
        if result.get("ok") and result.get("cookies"):
            session = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
            if session is not None and hasattr(session, "_session_cookies"):
                session._session_cookies.update(result["cookies"])
                logger.info("browser_login: synced cookies to copilot session",
                            count=len(result["cookies"]))
        safe_result = {k: v for k, v in result.items() if k != "cookies"}
        return safe_result
    except Exception as exc:
        return {"ok": False, "error": f"login failed: {str(exc)[:200]}", "url": url}


register(Tool(name="browser_login", input_schema=_LOGIN_SCHEMA, handler=_login,
    tags=["browser", "active"],
    description="Autonomous login via the agent browser. Handles multi-step flows "
                "(email-first, then password on a second page) like KMSAT, Okta, and "
                "other SSO-style login pages. Clears stale cookies, discovers form "
                "fields automatically, fills credentials, clicks submit, waits for "
                "redirect, and exports the resulting session cookies (including CSRF "
                "tokens set on page load). Use this as step 0 before any authenticated "
                "testing. Returns logged_in status, final URL, and cookie count."))


_FETCH_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "URL to fetch (absolute or relative to current page origin)."},
        "method": {"type": "string", "description": "HTTP method (default POST).", "default": "POST"},
        "headers": {"type": "object", "description": "Request headers (Content-Type defaults to application/json)."},
        "body": {"type": "string", "description": "Request body (JSON string for POST/PUT)."},
    },
    "required": ["url"],
}


async def _fetch(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = _browser(ctx)
    if browser is None:
        return {"ok": False, "error": "browser driving is not available in this context"}
    page = await browser._ensure_page()
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    method = str(args.get("method", "POST")).upper()
    headers = args.get("headers") or {"Content-Type": "application/json"}
    body = args.get("body")
    result = await page.evaluate("""async (args) => {
        try {
            const opts = {
                method: args.method,
                headers: args.headers,
                credentials: 'include',
            };
            if (args.body && ['POST','PUT','PATCH','DELETE'].includes(args.method)) {
                opts.body = args.body;
            }
            const resp = await fetch(args.url, opts);
            const text = await resp.text();
            const hdrs = {};
            resp.headers.forEach((v, k) => { hdrs[k] = v; });
            return { ok: true, status: resp.status, headers: hdrs,
                     body: text.substring(0, 8000), length: text.length };
        } catch (e) {
            return { ok: false, error: e.message };
        }
    }""", {"url": url, "method": method, "headers": headers, "body": body})
    return result


register(Tool(name="browser_fetch", input_schema=_FETCH_SCHEMA, handler=_fetch, tags=["browser", "active"],
    description="Make an HTTP request from inside the browser using fetch(). Uses the browser's own cookies "
                "(session, CSRF) automatically — no proxy, no cookie jar issues. Use this for authenticated "
                "API calls after logging in via browser_navigate/browser_fill/browser_click. More reliable "
                "than send_request for SPAs that manage cookies client-side (e.g. CSRF tokens set on page "
                "load). The request does NOT appear in proxy history."))

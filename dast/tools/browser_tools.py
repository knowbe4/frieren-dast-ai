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

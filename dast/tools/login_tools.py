"""login_* tools — adaptive login that tries the deterministic engine first and
escalates to the LLM only on failure.

This is the agent/MCP front door for ``dast.browser.login_cascade.adaptive_login``:
a single "log me in" capability that first runs the token-free heuristic
(``AgentBrowser.login()``) and, only if that cannot authenticate, lets the model
drive the browser primitives to adapt to an unusual form (odd field names, a
custom submit control, an extra consent click). Backed by ``ctx.browser`` (present
only for the in-process copilot); other callers get a clear "not available".
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


_ADAPTIVE_LOGIN_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Login page URL (e.g. https://app.example.com/login)."},
        "email": {"type": "string", "description": "Email / username to log in with."},
        "password": {"type": "string", "description": "Password for the account."},
        "success_url_suffix": {
            "type": "string",
            "description": "Optional known post-login path (e.g. /dashboard). When set it is "
                           "the authoritative success signal; otherwise a heuristic (no longer "
                           "on a login/SSO page) is used.",
        },
    },
    "required": ["url", "email", "password"],
}


async def _adaptive_login(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    browser = getattr(ctx, "browser", None)
    if browser is None:
        return {"ok": False, "error": "browser driving is not available in this context"}
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
    success_url_suffix = str(args.get("success_url_suffix", "")).strip() or None
    try:
        from dast.browser.login_cascade import adaptive_login

        result = await adaptive_login(
            browser, url, email, password, success_url_suffix=success_url_suffix,
        )
        # On success, sync the browser's session cookies into the copilot session
        # so subsequent authenticated calls carry them (parity with browser_login).
        if result.ok:
            try:
                cookies = await browser.export_cookies()
            except Exception:
                cookies = {}
            session = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
            if session is not None and cookies and hasattr(session, "_session_cookies"):
                session._session_cookies.update(cookies)
                logger.info("adaptive_login tool: synced cookies to copilot session",
                            count=len(cookies))
            if session is not None:
                session._last_login = {"url": url, "email": email, "password": password}
        return result.to_dict()
    except Exception as exc:
        return {"ok": False, "error": f"adaptive login failed: {str(exc)[:200]}", "url": url}


register(Tool(
    name="browser_login_adaptive",
    input_schema=_ADAPTIVE_LOGIN_SCHEMA,
    handler=_adaptive_login,
    tags=["browser", "active"],
    description="Log in, trying the deterministic auto-login first and escalating to the LLM "
                "only if it fails. Use this instead of browser_login when a form may be "
                "unusual (non-standard field names, a custom submit control, a consent/Authorize "
                "step): the cheap heuristic runs first, and only on failure does the model drive "
                "navigate/snapshot/fill/click to adapt like a human. Does NOT attempt CAPTCHAs or "
                "MFA/OTP (those are reported, not brute-forced). Returns which engine succeeded "
                "(deterministic|llm), the final URL, and the LLM actions taken.",
))

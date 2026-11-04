"""SPA JSON-API login strategy.

Modern SPAs (SvelteKit, React, the the target apps) log in by POSTing JSON credentials to an
auth endpoint (e.g. ``/spa/auth/login``), not by a classic form submit. This strategy hits
that endpoint directly through the browser context — it NEVER touches the form DOM, so it
works regardless of how the form is rendered (open/closed shadow DOM, iframe) where the
deterministic form-fill strategy fails with "no email field found".

On success it SYNCS the resulting session cookies into the proxy jar and the copilot session
and arms ``_last_login`` for auto-relogin, so the authenticated session is usable by scans
and recovers on expiry — not stranded in the browser context.
"""

from __future__ import annotations

import json as _json
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import unquote, urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Known JSON auth endpoints, tried relative to the login page's origin (most specific first).
_DEFAULT_ENDPOINTS = (
    "/spa/auth/login", "/api/auth/login", "/auth/login", "/api/login", "/api/session",
)
_CSRF_COOKIE_NAMES = ("CSRF-TOKEN", "csrf-token", "csrf_token", "XSRF-TOKEN", "xsrf-token")
# Markers that a JSON login response indicates success vs. an error page/body.
_SUCCESS_MARKERS = ("redirectto", "redirect_to", "access_token", '"token"', '"ok":true',
                    "dashboard", "authenticated")
_ERROR_MARKERS = ("error", "invalid", "denied", "unauthor", "incorrect", "nosuchkey",
                  "forbidden", "not found", "nosuchbucket")


def _body_variants(email: str, password: str, timezone: str) -> List[dict]:
    """Common SPA login body shapes, in order of likelihood."""
    return [
        {"resource_type": "user", "browser_timezone": timezone, "email": email, "password": password},
        {"email": email, "password": password},
        {"username": email, "password": password},
        {"user": {"email": email, "password": password}},
        {"identifier": email, "password": password},
    ]


def _looks_success(status: Optional[int], text: str) -> bool:
    """True when a JSON auth response looks like a successful login (not an error body)."""
    if status not in (200, 201, 204):
        return False
    low = (text or "").lower()
    if any(m in low for m in _ERROR_MARKERS):
        return False
    if any(m in low for m in _SUCCESS_MARKERS):
        return True
    # A clean 200/201 with no error markers (e.g. empty/204 body) is treated as success.
    return status in (200, 201, 204)


async def _csrf_headers(browser: Any) -> Dict[str, str]:
    headers = {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
    try:
        cookies = await browser.export_cookies()
        token = next((cookies[name] for name in _CSRF_COOKIE_NAMES if cookies.get(name)), "")
        if token:
            headers["X-CSRF-Token"] = unquote(token)
    except Exception as exc:
        logger.debug("spa_api: CSRF lookup failed", error=str(exc)[:120])
    return headers


async def attempt(
    browser: Any,
    url: str,
    email: str,
    password: str,
    *,
    store: Optional[Any] = None,
    session: Optional[Any] = None,
    endpoints: Optional[List[str]] = None,
    in_scope: Optional[Callable[[str], bool]] = None,
    timezone: str = "America/Fortaleza",
) -> Dict[str, Any]:
    """Try to log in via the SPA JSON auth endpoint. Returns a result dict with
    ``ok``/``logged_in``/``engine='spa_api'``/``endpoint``; syncs cookies on success."""
    # Load the login page first so the CSRF cookie (double-submit) is set in the context.
    try:
        await browser.navigate(url)
    except Exception as exc:
        logger.debug("spa_api: navigate to login page failed", error=str(exc)[:120])

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    candidates = endpoints or [origin + path for path in _DEFAULT_ENDPOINTS]

    headers = await _csrf_headers(browser)
    for endpoint in candidates:
        if in_scope is not None and not in_scope(endpoint):
            continue
        for body in _body_variants(email, password, timezone):
            resp = await browser.api_post(endpoint, headers, _json.dumps(body))
            if not resp.get("ok"):
                continue
            if _looks_success(resp.get("status"), resp.get("text", "")):
                synced = await _sync_session(browser, store, session, url, email, password)
                logger.info("spa_api: login succeeded", endpoint=endpoint,
                            status=resp.get("status"), cookies=synced)
                return {
                    "ok": True, "logged_in": True, "engine": "spa_api",
                    "endpoint": endpoint, "url": url, "cookies": synced,
                    "status": resp.get("status"),
                }
    logger.info("spa_api: no JSON auth endpoint accepted the credentials",
                tried=len(candidates))
    return {"ok": False, "logged_in": False, "engine": "spa_api",
            "error": "no SPA JSON auth endpoint accepted the credentials"}


async def _sync_session(browser: Any, store: Any, session: Any,
                        url: str, email: str, password: str) -> int:
    """Push the browser's post-login cookies into the proxy jar + copilot session and arm
    auto-relogin. Returns the number of cookies synced to the jar."""
    synced = 0
    try:
        full = await browser.export_cookies_full()
        if store is not None and full:
            synced = store.import_playwright_cookies(full)
    except Exception as exc:
        logger.warning("spa_api: jar cookie sync failed", error=str(exc)[:120])
    try:
        flat = await browser.export_cookies()
        if session is not None:
            if hasattr(session, "_session_cookies"):
                session._session_cookies.update(flat)
            # Arm the engine's auto-relogin with these credentials.
            session._last_login = {"url": url, "email": email, "password": password}
    except Exception as exc:
        logger.debug("spa_api: session handoff sync failed", error=str(exc)[:120])
    return synced

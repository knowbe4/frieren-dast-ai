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
import re
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import unquote, urlparse

from dast.browser.login_strategies.base import LoginContext, LoginResult
from dast.session.account_state import AuthProbeConfig, api_get_fetch, verify_authenticated
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Known JSON auth endpoints, tried relative to the login page's origin (most specific first).
_DEFAULT_ENDPOINTS = (
    "/spa/auth/login", "/api/auth/login", "/auth/login", "/api/login", "/api/session",
)
# CSRF cookie conventions, most common first. Cookie names were historically the only
# thing scanned; the matching request headers now cover the three framework defaults.
_CSRF_COOKIE_NAMES = ("CSRF-TOKEN", "csrf-token", "csrf_token", "XSRF-TOKEN", "xsrf-token",
                      "csrftoken", "CSRFToken", "CSRF_TOKEN")
# Markers that a JSON login response indicates success vs. an error page/body.
_SUCCESS_MARKERS = ("redirectto", "redirect_to", "access_token", '"token"', '"ok":true',
                    "dashboard", "authenticated")
_ERROR_MARKERS = ("error", "invalid", "denied", "unauthor", "incorrect", "nosuchkey",
                  "forbidden", "not found", "nosuchbucket")

# ── anti-spray tuning ──────────────────────────────────────────────────────────
# A failed SPA login used to spray up to 5 endpoints × 5 body shapes = 25 credential
# POSTs per attempt — exactly what account-lockout / anti-brute-force controls punish.
_MAX_LOGIN_POSTS = 10
_LOGINISH_PATH_RE = re.compile(r"login|signin|sign-in|sign_in|auth", re.IGNORECASE)


def _local_timezone() -> str:
    """The operator machine's local TZ name (the old default claimed the browser was
    always in America/Fortaleza — a fingerprint anomaly on every SPA login)."""
    try:
        return time.tzname[time.daylight] or "UTC"
    except Exception:  # noqa: BLE001 — cosmetic field, never break the login
        return "UTC"


def _body_variants(email: str, password: str, timezone: str,
                   preferred_shape: Optional[str] = None) -> List[dict]:
    """Common SPA login body shapes, in order of likelihood. When the journal learned
    a ``body_shape`` (comma-joined keys) for this host, the matching shape is tried
    first so a learned login is both fast and low-spray."""
    variants = [
        {"resource_type": "user", "browser_timezone": timezone, "email": email, "password": password},
        {"email": email, "password": password},
        {"username": email, "password": password},
        {"user": {"email": email, "password": password}},
        {"identifier": email, "password": password},
    ]
    if preferred_shape:
        for i, v in enumerate(variants):
            if ",".join(sorted(v.keys())) == preferred_shape:
                return [variants[i], *variants[:i], *variants[i + 1:]]
    return variants


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
    """Build CSRF headers for the three framework conventions at once — Spring/KnowBe4
    style ``X-CSRF-Token`` (CSRF-TOKEN cookie), Angular/Laravel ``X-XSRF-TOKEN``
    (XSRF-TOKEN cookie), and Django ``X-CSRFToken`` (csrftoken cookie). Servers ignore
    the conventions they don't use, so emitting all three is safe and removes the
    single-convention 403-forever failure mode. (Meta-tag conventions need DOM access
    and are covered by the deterministic form-fill strategy instead.)"""
    headers = {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
    _CSRF_HEADER_BY_COOKIE = {
        "csrf-token": "X-CSRF-Token",
        "xsrf-token": "X-XSRF-TOKEN",
        "csrftoken": "X-CSRFToken",
    }
    try:
        cookies = await browser.export_cookies()
        for name, value in cookies.items():
            header = _CSRF_HEADER_BY_COOKIE.get(name.lower())
            if header and value and header not in headers:
                headers[header] = unquote(value)
    except Exception as exc:
        logger.debug("spa_api: CSRF lookup failed", error=str(exc)[:120])
    return headers


async def _confirm_session(
    browser: Any, url: str, probe: Optional[AuthProbeConfig],
) -> Optional[bool]:
    """Structural confirm that the context now holds a real session (tri-state).
    Never raises — a probe transport error returns None (fail-open to legacy behavior)."""
    try:
        cookies = await browser.export_cookies()
        verdict = await verify_authenticated(
            api_get_fetch(browser), base_url=url, probe=probe, session_cookies=cookies)
        return verdict.authenticated
    except Exception as exc:  # noqa: BLE001 — the probe is a guard, not a requirement
        logger.debug("spa_api: probe-confirm skipped", error=str(exc)[:120])
        return None


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
    timezone: Optional[str] = None,
    probe: Optional[AuthProbeConfig] = None,
    totp_secret: Optional[str] = None,
) -> Dict[str, Any]:
    """Try to log in via the SPA JSON auth endpoint. Returns a result dict with
    ``ok``/``logged_in``/``engine='spa_api'``/``endpoint``; syncs cookies on success."""
    tz = timezone or _local_timezone()
    # Load the login page first so the CSRF cookie (double-submit) is set in the context.
    try:
        await browser.navigate(url)
    except Exception as exc:
        logger.debug("spa_api: navigate to login page failed", error=str(exc)[:120])

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    candidates = endpoints or [origin + path for path in _DEFAULT_ENDPOINTS]

    # Reuse what worked last time: if the login journal has a known-good endpoint for this
    # host (same origin), try it FIRST so a learned login is fast and deterministic — and
    # replay its learned body shape so the first POST is the one that worked before.
    from dast.session import login_journal
    known = login_journal.last_success(url)
    preferred_shape: Optional[str] = None
    if known and known.get("endpoint", "").startswith(origin):
        candidates = [known["endpoint"]] + [c for c in candidates if c != known["endpoint"]]
        preferred_shape = known.get("body_shape") or None

    headers = await _csrf_headers(browser)
    posts_made = 0
    stop_reason = ""
    for endpoint in candidates:
        if in_scope is not None and not in_scope(endpoint):
            continue
        # ANTI-SPRAY: 401/403 from a REAL login endpoint (journal-known or
        # login/auth-shaped path) means the credentials themselves were rejected —
        # spraying the same credentials at more endpoints adds zero information and
        # only feeds account-lockout counters. 404 just means "not this endpoint" —
        # skip its remaining shapes and try the next. 429 means lockout is imminent:
        # stop everything.
        endpoint_known = known is not None and endpoint == known.get("endpoint")
        endpoint_loginish = endpoint_known or bool(_LOGINISH_PATH_RE.search(endpoint))
        variants = _body_variants(email, password, tz, preferred_shape=preferred_shape)
        for body in variants:
            if posts_made >= _MAX_LOGIN_POSTS:
                stop_reason = f"POST budget exhausted ({_MAX_LOGIN_POSTS})"
                break
            posts_made += 1
            resp = await browser.api_post(endpoint, headers, _json.dumps(body))
            status = resp.get("status")
            if not resp.get("ok"):
                continue
            if status in (404, 405, 410):
                logger.debug("spa_api: endpoint does not exist — skipping remaining shapes",
                             endpoint=endpoint, status=status)
                break
            if status == 429:
                stop_reason = "rate-limited (429) — stopping to avoid account lockout"
                break
            if status in (401, 403) and endpoint_loginish:
                stop_reason = (f"credentials rejected by login endpoint {endpoint} "
                               f"({status}) — not spraying further")
                break
            if _looks_success(status, resp.get("text", "")):
                # PROBE-CONFIRM before declaring victory: a success-shaped 2xx is not a
                # session — "MFA pending" 200s and empty-204 bodies read as success here
                # (and a false success is WORSE than a failure: the journal promotes it
                # to the front of the next cascade). A positively-contradicted verdict
                # (auth wall / guest / no session) skips this candidate and keeps trying;
                # an inconclusive probe falls back to the legacy behavior.
                confirmed = await _confirm_session(browser, url, probe)
                if confirmed is False:
                    logger.info("spa_api: endpoint looked successful but the session "
                                "probes as unauthenticated — trying next candidate",
                                endpoint=endpoint)
                    continue
                synced = await _sync_session(browser, store, session, url, email,
                                             password, totp_secret)
                logger.info("spa_api: login succeeded", endpoint=endpoint,
                            status=status, cookies=synced, verified=confirmed,
                            posts=posts_made)
                # Journal the reproducible shape (endpoint + body keys), never secrets.
                login_journal.record(url, "success", strategy="spa_api", endpoint=endpoint,
                                     body_shape=",".join(sorted(body.keys())), success_url=url)
                return {
                    "ok": True, "logged_in": True, "engine": "spa_api",
                    "endpoint": endpoint, "url": url, "cookies": synced,
                    "status": status, "verified": confirmed,
                }
        if stop_reason:
            break
    logger.info("spa_api: no JSON auth endpoint accepted the credentials",
                tried=len(candidates), posts=posts_made, stop_reason=stop_reason or None)
    login_journal.record(url, "error", strategy="spa_api",
                         reason=stop_reason or "no SPA JSON auth endpoint accepted the credentials")
    return {"ok": False, "logged_in": False, "engine": "spa_api",
            "error": stop_reason or "no SPA JSON auth endpoint accepted the credentials"}


async def _sync_session(browser: Any, store: Any, session: Any,
                        url: str, email: str, password: str,
                        totp_secret: Optional[str] = None) -> int:
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
            # Arm the engine's auto-relogin with these credentials — TOTP included so an
            # MFA account's auto-relogin doesn't die at the OTP step (the seed only
            # reaches here when may_use_totp allowed it upstream).
            armed = {"url": url, "email": email, "password": password}
            if totp_secret:
                armed["totp_secret"] = totp_secret
            session._last_login = armed
    except Exception as exc:
        logger.debug("spa_api: session handoff sync failed", error=str(exc)[:120])
    return synced


class SpaApiStrategy:
    """The SPA JSON-API login as a LoginStrategy. Thin adapter over the module-level
    ``attempt`` (kept as-is for its callers and tests); the registry drives this class."""

    name = "spa_api"

    async def can_attempt(self, ctx: LoginContext) -> bool:
        """Applicable when ordered first (a learned win — nothing tried yet) OR when the
        preceding strategy could not REACH a form: the DOM-independent JSON path is the
        fallback for an iframe/closed-shadow form. A form that WAS reached but failed
        (invalid creds / extra step) is left to the LLM, so this does not fire there."""
        if not ctx.prior:
            return True
        return ctx.prior[-1].reachable is False

    async def attempt(self, ctx: LoginContext) -> LoginResult:
        # Bare ``attempt`` resolves to the module-level function below, so a test that
        # monkeypatches ``spa_api.attempt`` still drives this strategy.
        result = await attempt(ctx.browser, ctx.url, ctx.email, ctx.password,
                               store=ctx.store, session=ctx.session, in_scope=ctx.in_scope,
                               probe=ctx.probe, totp_secret=ctx.totp_secret)
        return LoginResult(
            ok=bool(result.get("ok") and result.get("logged_in")),
            engine="spa_api",
            url=result.get("url") or ctx.url,
            endpoint=result.get("endpoint", ""),
            error=result.get("error", ""),
        )

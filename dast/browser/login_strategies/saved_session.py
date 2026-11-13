"""Reuse-first login strategy: restore a profile's persisted session and skip login.

The cascade historically went straight to CREATING a login (deterministic form -> SPA JSON ->
LLM) — it never looked up an already-saved session first, so every run re-drove the login form
even when a valid session was sitting in the profile. This strategy runs FIRST: if the profile
has a persisted ``saved_session``, it seeds those cookies into the browser context and probes an
authed endpoint. If the session is still valid it short-circuits the whole cascade (``ok=True``,
no form / no SPA / no LLM). If the seeded session is stale (auth wall) it returns a non-terminal
failure so the cascade falls through to a real login.

The probe is a cheap signal to AVOID the expensive cascade in the common case; the authoritative
provisioned-account gate-check still runs in the caller (``_ensure_profile_login``), which forces
a fresh login if a reused session turns out to be dead.
"""

from __future__ import annotations

from urllib.parse import urlparse

from dast.browser.login_strategies.base import LoginContext, LoginResult
from dast.triage.auth_wall import looks_like_auth_wall
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def _saved_cookies(ctx: LoginContext) -> list:
    state = ctx.saved_session or {}
    cookies = state.get("cookies") if isinstance(state, dict) else None
    return cookies if isinstance(cookies, list) and cookies else []


class SavedSessionStrategy:
    """Restore and reuse a persisted session before any real login is attempted."""

    name = "saved_session"

    async def can_attempt(self, ctx: LoginContext) -> bool:
        """Only when nothing has been tried yet AND the profile carries saved cookies."""
        return not ctx.prior and bool(_saved_cookies(ctx))

    async def attempt(self, ctx: LoginContext) -> LoginResult:
        cookies = _saved_cookies(ctx)
        try:
            seeded = await ctx.browser.seed_saved_session(cookies)
        except Exception as exc:  # noqa: BLE001 — reuse must never break the cascade
            logger.debug("saved_session: seeding failed", error=str(exc)[:160])
            return LoginResult(ok=False, engine="saved_session", url=ctx.url,
                               error="saved-session seed failed", reachable=False)
        if not seeded:
            return LoginResult(ok=False, engine="saved_session", url=ctx.url,
                               error="no usable saved cookies", reachable=False)

        # Probe a cheap authed endpoint with the seeded cookies. page.request.fetch follows
        # redirects, so a 302-to-IdP surfaces as a 200 login page whose body trips the wall
        # detector. NEVER probe the login URL itself — it is the login page, so it always looks
        # like a wall and would false-negative a perfectly valid session. Probe an explicit
        # success URL when given, else the origin root (authed -> app/dashboard, unauthed ->
        # redirect to login). Ambiguous SPA shells pass here and are caught by the caller's
        # authoritative gate-check.
        probe_url = ctx.success_url_suffix if (ctx.success_url_suffix or "").startswith("http") \
            else None
        if not probe_url:
            origin = urlparse(ctx.url)
            probe_url = f"{origin.scheme}://{origin.netloc}/"
        try:
            resp = await ctx.browser.api_get(probe_url)
        except Exception as exc:  # noqa: BLE001
            logger.debug("saved_session: probe failed", error=str(exc)[:160])
            resp = {"ok": False}

        if not resp.get("ok") or resp.get("status") is None:
            return LoginResult(ok=False, engine="saved_session", url=ctx.url,
                               error="saved-session probe failed", reachable=False)

        wall = looks_like_auth_wall(int(resp.get("status") or 0), probe_url,
                                    resp.get("text", "") or "")
        if wall:
            logger.info("saved_session: stored session is stale, falling through to login",
                        url=probe_url, status=resp.get("status"))
            return LoginResult(ok=False, engine="saved_session", url=ctx.url,
                               error="saved session expired", reachable=False)
        # NOTE: reachable=False on every fall-through above is deliberate — it tells the
        # cascade the login surface was NOT reached, so the DOM-independent spa_api fallback
        # still fires after us (it only runs when the prior strategy was unreachable).

        logger.info("saved_session: reused a still-valid stored session, skipping login",
                    url=probe_url, status=resp.get("status"), cookies=seeded)
        return LoginResult(ok=True, engine="saved_session", url=probe_url, reachable=True)

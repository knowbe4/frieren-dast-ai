"""
Session Refresh Worker — detects auth expiry and transparently re-authenticates.

Watches the proxy entry stream for session-expiry signals:
  - HTTP 401 or 403 responses on in-scope endpoints
  - HTTP 302 redirect to a URL containing 'login', 'signin', or 'auth'
  - Response body containing typical "session expired" phrases

When a signal is detected the worker:
  1. Waits for the cooldown window (avoids thundering herd on concurrent 401s)
  2. Runs AuthAgent.login() against the saved credentials
  3. Applies the refreshed auth state to the ContextPool
  4. Logs the outcome to the proxy event log

Only active when --auth-url and credentials were provided at startup.
Completely passive from the entry pipeline's perspective — no entries are
modified or re-queued.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Optional

from dast.proxy.plugin_manager import log_event
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.browser.context_pool import ContextPool
    from dast.proxy.session_store import ProxyEntry
    from dast.session.manager import SessionManager

logger = get_logger(__name__)

# Minimum gap between two re-auth attempts (seconds)
_REAUTH_COOLDOWN = 30.0

# Consecutive re-auth failures before the worker gives up. Re-authenticating with
# stale credentials (password changed, new MFA, login host down) will fail every
# time; without this the worker burns a browser context on every subsequent 401.
_MAX_REAUTH_FAILURES = 3

# Response body phrases that strongly suggest the session expired
_EXPIRY_PHRASES_RE = re.compile(
    r"(session\s+expired|your\s+session\s+has|you\s+have\s+been\s+logged\s+out"
    r"|please\s+log\s+in\s+again|authentication\s+required|unauthorized)",
    re.IGNORECASE,
)

# Location header patterns that indicate a redirect to the login page
_LOGIN_REDIRECT_RE = re.compile(
    r"/(login|signin|sign-in|sign_in|auth/login|account/login|users/sign_in)",
    re.IGNORECASE,
)


def _is_expiry_signal(entry: "ProxyEntry") -> bool:
    """Return True if the entry carries a session-expiry signal."""
    if entry.source == "agent":
        return False
    status = entry.status_code or 0

    # Explicit auth failure
    if status in (401, 403):
        return True

    # Redirect to login page
    if status in (301, 302, 303, 307, 308):
        location = entry.response_headers.get("location", "")
        if _LOGIN_REDIRECT_RE.search(location):
            return True

    # 200 response body that says "session expired"
    if status == 200 and entry.response_body:
        snippet = entry.response_body[:2048].decode("utf-8", errors="replace")
        if _EXPIRY_PHRASES_RE.search(snippet):
            return True

    return False


class SessionRefreshWorker:
    """
    Background worker that re-authenticates when session expiry is detected.

    Wire up by calling `attach(store)` then `run()` as a coroutine in
    asyncio.gather alongside the proxy.
    """

    def __init__(
        self,
        auth_url: str,
        username: str,
        password: Optional[str],
        pool: "ContextPool",
        session_manager: "SessionManager",
    ) -> None:
        self._auth_url = auth_url
        self._username = username
        self._password = password
        self._pool = pool
        self._session_manager = session_manager
        self._signal_queue: asyncio.Queue = asyncio.Queue()
        self._last_reauth: float = 0.0
        self._consecutive_failures: int = 0
        self._gave_up: bool = False

    def on_entry(self, entry: "ProxyEntry") -> None:
        """Called by the proxy store after each entry completes. Non-blocking."""
        if _is_expiry_signal(entry):
            try:
                self._signal_queue.put_nowait(entry)
            except asyncio.QueueFull:
                pass  # already queued — cooldown will handle it

    async def run(self) -> None:
        """Long-running coroutine — run alongside the proxy in asyncio.gather."""
        logger.info(
            "SessionRefreshWorker started",
            auth_url=self._auth_url,
            username=self._username,
        )
        while True:
            entry = await self._signal_queue.get()
            import time

            # Circuit breaker: after too many consecutive failures, stop trying —
            # the credentials are clearly stale and every attempt wastes a browser
            # context. A manual re-auth or session reload is needed to recover.
            if self._gave_up:
                logger.debug("Session refresh suppressed — gave up after repeated failures")
                continue

            now = time.monotonic()
            if now - self._last_reauth < _REAUTH_COOLDOWN:
                logger.debug(
                    "Session refresh suppressed — cooldown active",
                    remaining=f"{_REAUTH_COOLDOWN - (now - self._last_reauth):.0f}s",
                )
                continue

            self._last_reauth = now
            log_event(
                "session_refresh", "warning",
                f"Session expiry detected ({entry.status_code}) on {entry.url} — re-authenticating",
                url=entry.url, source="plugin",
            )
            logger.info(
                "Session expiry signal — triggering re-auth",
                url=entry.url,
                status=entry.status_code,
            )

            await self._reauth()

    async def _reauth(self) -> None:
        from dast.session.auth_agent import AuthAgent

        try:
            async with self._pool.acquire() as ctx:
                agent = AuthAgent(
                    context=ctx,
                    session_manager=self._session_manager,
                    auth_url=self._auth_url,
                    username=self._username,
                    password=self._password,
                )
                ok = await agent.login()
                if ok:
                    state = await ctx.storage_state()
                    await self._pool.apply_auth_state(state)
                    self._consecutive_failures = 0
                    log_event(
                        "session_refresh", "info",
                        "Re-authentication successful — auth state refreshed",
                        source="plugin",
                    )
                    logger.info("Session refresh: re-auth succeeded")
                else:
                    self._register_failure(
                        "Re-authentication failed — scan will continue unauthenticated"
                    )
        except Exception as exc:
            logger.error("Session refresh: unexpected error during re-auth", error=str(exc))
            self._register_failure(f"Re-auth error: {exc}")

    def _register_failure(self, message: str) -> None:
        """Record a re-auth failure and trip the breaker at the threshold."""
        self._consecutive_failures += 1
        logger.warning("Session refresh: re-auth failed",
                       consecutive_failures=self._consecutive_failures)
        if self._consecutive_failures >= _MAX_REAUTH_FAILURES:
            self._gave_up = True
            log_event(
                "session_refresh", "error",
                f"Re-authentication failed {self._consecutive_failures} times — giving up. "
                "Credentials may be stale (password/MFA changed). Re-authenticate via the "
                "Browse tab, then scanning resumes with a fresh session.",
                source="plugin",
            )
            logger.error("Session refresh: giving up after repeated failures",
                         failures=self._consecutive_failures)
        else:
            log_event("session_refresh", "error", message, source="plugin")

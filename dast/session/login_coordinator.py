"""Process-wide login coordinator — ONE per-host login lock for every component
that logs in, plus the bridge that lets login-side code reach the scan-time
re-auth breaker.

Before this module, ~10 code paths performed logins (scan-time refresh worker,
copilot reactive ladder, autonomous proactive login, breaker reauth, dashboard
adaptive login, replay jobs, model tools) and each had only a PRIVATE guard —
its own cooldown or flag. None of them serialized against each other, so e.g.
``run_validation_batch(max_concurrency=3)`` launched three concurrent
``adaptive_login`` calls with the SAME credentials against the SAME host: a
login flood that invalidates server-side sessions (the exact failure the
copilot's own RefreshTier docstring warns about) and tripped lockout controls.

Design:
- A per-host (site-keyed) ``asyncio.Lock``: a component acquires it around its
  whole login flow; a second component's login for the SAME host waits. Hosts
  are independent — logins to different products never block each other.
- A registered ``SessionRefreshWorker``: the proxy runner registers the live
  instance (the 2-A "worker unreachable from the dashboard/tools" gap), so any
  in-process code can reset the breaker when a fresh session lands — previously
  only dashboard routes could.
- Deliberately ASYMMETRIC: the lock only SERIALIZES. Cooldowns, breakers and
  once-per-run flags stay component-local — a copilot-initiated login neither
  consumes nor resets the scan-time re-auth cooldown; it just cannot overlap it
  on the same host.

Single module-level singleton (the ``bedrock_client`` pattern): survives the
MCP process split, needs no context plumbing, and degrades to a no-op breaker
reset when no worker is registered (e.g. proxy started without auth creds).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Dict, Optional
from urllib.parse import urlparse

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.session.refresh_worker import SessionRefreshWorker

logger = get_logger(__name__)


def site_key_for(host_or_url: str) -> str:
    """Site (product-group) key for a host/URL, falling back to the bare host —
    the same grouping the login journal uses, so the SSO identity host and the
    app host of one product share one login lock."""
    try:
        from dast.session import site_map
        return site_map.site_key(host_or_url) or _bare_host(host_or_url)
    except Exception:  # noqa: BLE001 — grouping is best-effort; host fallback is safe
        return _bare_host(host_or_url)


def _bare_host(host_or_url: str) -> str:
    value = (host_or_url or "").strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
    return value.split(":", 1)[0].lower().strip()


class LoginCoordinator:
    """Per-host login serialization + the refresh-breaker bridge. See module docstring."""

    def __init__(self) -> None:
        self._locks: Dict[str, asyncio.Lock] = {}
        self._refresh_worker: Optional["SessionRefreshWorker"] = None

    # ── serialization ──────────────────────────────────────────────────────

    def site_key_for(self, host_or_url: str) -> str:
        """Instance-method form of :func:`site_key_for` (call sites read naturally
        as ``coord.lock_for(coord.site_key_for(url))``)."""
        return site_key_for(host_or_url)

    def lock_for(self, site_key: str) -> asyncio.Lock:
        """The login lock for one site key, created on first use. Acquire it around
        the WHOLE login flow (cascade / replay / re-auth), not per request."""
        lock = self._locks.get(site_key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[site_key] = lock
        return lock

    # ── breaker bridge ─────────────────────────────────────────────────────

    def register_refresh_worker(self, worker: "SessionRefreshWorker") -> None:
        """Called by the proxy runner once the worker exists (None before that, and
        in processes without a proxy — reset_refresh_breaker degrades to no-op)."""
        self._refresh_worker = worker
        logger.info("login coordinator: refresh worker registered")

    def reset_refresh_breaker(self, reason: str = "") -> bool:
        """Re-arm the scan-time re-auth breaker because a fresh session just landed
        (profile activation / successful login via any component). Returns False
        when no worker is registered — callers treat that as best-effort."""
        if self._refresh_worker is None:
            return False
        try:
            self._refresh_worker.reset(reason or "fresh login landed")
            return True
        except Exception as exc:  # noqa: BLE001 — best-effort, never break a login
            logger.debug("login coordinator: breaker reset failed", error=str(exc)[:120])
            return False


_COORDINATOR: Optional[LoginCoordinator] = None


def get_login_coordinator() -> LoginCoordinator:
    """The process-wide coordinator (created on first use)."""
    global _COORDINATOR
    if _COORDINATOR is None:
        _COORDINATOR = LoginCoordinator()
    return _COORDINATOR


def reset_login_coordinator() -> None:
    """Test isolation: drop the singleton and all its locks (per-test event loops
    make carried-over asyncio.Lock objects unusable across tests)."""
    global _COORDINATOR
    _COORDINATOR = None

"""
Session manager with checkpoint-and-rollback.

Maintains a validated authentication state snapshot.
Workers can detect session expiry and roll back to the last good
checkpoint without blocking other workers.

Flow:
  1. Auth agent logs in → saves storage_state as checkpoint_0
  2. Every N requests, a health-check is issued against a known endpoint
  3. If health-check fails (401/redirect to /login) → rollback to checkpoint
  4. Re-authenticate if rollback fails → save new checkpoint
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from playwright.async_api import BrowserContext


@dataclass
class SessionCheckpoint:
    storage_state: Dict         # Playwright storage state (cookies + localStorage)
    captured_at: float = field(default_factory=time.time)
    health_url: Optional[str] = None
    valid: bool = True


class SessionManager:
    """
    Thread-safe session state store shared across all browser workers.

    Workers call `is_healthy()` before submitting attacks. If the session
    has expired they call `rollback()` which restores the last valid checkpoint
    on their context, then re-checks. If three rollbacks fail in a row the
    session is considered dead and the scan raises an auth error.
    """

    _MAX_ROLLBACK_ATTEMPTS = 3

    def __init__(self, health_url: Optional[str] = None):
        self._health_url = health_url
        self._checkpoint: Optional[SessionCheckpoint] = None
        self._lock = asyncio.Lock()
        self._rollback_count = 0

    async def save_checkpoint(
        self, context: BrowserContext, health_url: Optional[str] = None
    ) -> None:
        """Capture the current context's auth state as a checkpoint."""
        async with self._lock:
            state = await context.storage_state()
            self._checkpoint = SessionCheckpoint(
                storage_state=state,
                health_url=health_url or self._health_url,
            )
            self._rollback_count = 0

    async def rollback(self, context: BrowserContext) -> bool:
        """
        Restore the last valid checkpoint onto `context`.
        Returns True if successful, False if no checkpoint or max retries exceeded.
        """
        async with self._lock:
            if not self._checkpoint or not self._checkpoint.valid:
                return False
            if self._rollback_count >= self._MAX_ROLLBACK_ATTEMPTS:
                return False

            self._rollback_count += 1

        # Add cookies back (clear existing first)
        await context.clear_cookies()
        cookies = self._checkpoint.storage_state.get("cookies", [])
        if cookies:
            await context.add_cookies(cookies)
        return True

    async def is_healthy(self, context: BrowserContext) -> bool:
        """
        Issue a lightweight health-check request on `context`.
        Returns True if the session is still valid.
        """
        if not self._health_url:
            return True

        page = await context.new_page()
        try:
            resp = await page.goto(
                self._health_url,
                wait_until="domcontentloaded",
                timeout=8000,
            )
            if resp is None:
                return False
            # Redirect to /login means session expired
            final_url = page.url.lower()
            if "login" in final_url or "signin" in final_url:
                return False
            return resp.status < 400
        except Exception:
            return False
        finally:
            await page.close()

    @property
    def has_checkpoint(self) -> bool:
        return self._checkpoint is not None

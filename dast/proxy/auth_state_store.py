"""
Durable authenticated browser state.

A Browse login captures a Playwright ``storage_state`` (httpOnly session cookies
plus localStorage) that the crawlers reuse to browse authenticated. Held only in
memory it dies with the process, so every proxy restart forces the operator to
log in again. This module persists the last captured ``storage_state`` to disk
and reloads it on boot, so an authenticated session survives a restart until the
credentials actually expire.

Generic across any target. The blob holds live session tokens, so it is written
to the already-sensitive ``~/.dast-ai`` directory (alongside the CA key and saved
sessions), never into the repo, and with owner-only file permissions.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_AUTH_STATE_PATH = Path.home() / ".dast-ai" / "auth_storage_state.json"


def _is_populated(state: Optional[dict]) -> bool:
    """A storage_state is meaningful only if it carries cookies or origins."""
    return bool(state and (state.get("cookies") or state.get("origins")))


def save_auth_state(state: Optional[dict]) -> None:
    """Persist a captured storage_state to disk (owner-read/write only). An empty
    or None state is ignored so a transient blank capture never wipes a good one;
    use ``clear_auth_state`` to explicitly drop it."""
    if not _is_populated(state):
        return
    try:
        _AUTH_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _AUTH_STATE_PATH.write_text(json.dumps(state))
        try:
            os.chmod(_AUTH_STATE_PATH, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        logger.info("auth state persisted",
                    cookies=len(state.get("cookies") or []),
                    origins=len(state.get("origins") or []))
    except Exception as exc:  # noqa: BLE001 — persistence is best-effort, never fatal
        logger.warning("auth state persist failed", error=str(exc))


def load_auth_state() -> Optional[dict]:
    """Load the last persisted storage_state, or None if absent/empty/unreadable."""
    try:
        if not _AUTH_STATE_PATH.exists():
            return None
        state = json.loads(_AUTH_STATE_PATH.read_text())
        if _is_populated(state):
            return state
    except Exception as exc:  # noqa: BLE001 — a corrupt blob must not block startup
        logger.warning("auth state load failed", error=str(exc))
    return None


def clear_auth_state() -> None:
    """Drop the persisted auth state (e.g. after it is found expired)."""
    try:
        _AUTH_STATE_PATH.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("auth state clear failed", error=str(exc))

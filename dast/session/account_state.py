"""Shared account/session-state detection.

One source of truth for "is this browser session a real, authenticated, provisioned account?",
used by both the autonomous run's post-login gate-check and the interactive
``activate_login_profile`` self-heal. Keeping it here (not in the proxy API layer) lets the tools
layer reuse it without depending on the dashboard service.
"""

from __future__ import annotations

import json as _json
from typing import Any, Optional
from urllib.parse import urlparse

from dast.triage.auth_wall import looks_like_auth_wall
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def session_is_provisioned(data: dict) -> Optional[bool]:
    """Classify an app session-endpoint JSON body (e.g. a ``/spa/session`` endpoint).

    Returns False only when it positively reports a guest/unprovisioned account
    (account id ``-1``/``<=0`` or an explicit guest marker), True when it reports a
    real account, and None when it can't tell — so the caller fails open on an
    unknown app rather than blocking a legitimate login.
    """
    if not isinstance(data, dict):
        return None
    account_id: Any = None
    account = data.get("account")
    if isinstance(account, dict):
        account_id = account.get("id")
    if account_id is None:
        user = data.get("user")
        if isinstance(user, dict):
            account_id = user.get("account_id") or user.get("accountId")
    if account_id is None:
        account_id = data.get("account_id") or data.get("accountId")
    if account_id is not None:
        try:
            return int(account_id) > 0
        except (TypeError, ValueError):
            return None
    user = data.get("user")
    if isinstance(user, dict) and user:
        return True
    if data.get("guest") is True:
        return False
    return None


async def session_is_authenticated(browser: Any, base_url: str) -> Optional[bool]:
    """Best-effort check that the browser's current session is a real, authenticated account.

    False only when positively unauthenticated (auth wall) or a guest/unprovisioned account; True
    on a real account; None when it can't tell (so callers fail open rather than force a needless
    re-login). Never raises.
    """
    try:
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc:
            return None
        origin = f"{parsed.scheme}://{parsed.netloc}"
        # (a) A GET of the origin root that redirects to / renders a login page is a clear wall.
        root = await browser.api_get(f"{origin}/")
        if root.get("ok") and root.get("status") is not None:
            if looks_like_auth_wall(int(root.get("status") or 0), f"{origin}/",
                                    root.get("text", "") or ""):
                return False
        # (b) The app session endpoint is the authoritative signal when present (e.g. /spa/session).
        resp = await browser.api_get(f"{origin}/spa/session",
                                     headers={"X-Requested-With": "XMLHttpRequest"})
        if not resp.get("ok") or resp.get("status") != 200:
            return None
        try:
            data = _json.loads(resp.get("text") or "")
        except (ValueError, TypeError):
            return None
        return session_is_provisioned(data)
    except Exception as exc:  # noqa: BLE001 — detection is best-effort, never break the caller
        logger.debug("account_state: session check skipped", error=str(exc)[:160])
        return None

"""Paths whose request would end the session or destroy application data.

Shared by every component that must never touch them: the CLI crawler (does not
follow such links), the proxy scan adapter and worker (do not send payloads),
and the code-analysis probe route.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

# Matched against the last path segment so /auth/logout, /api/v1/logout, etc.
# are all caught. The file extension is ignored: classic server-rendered apps
# expose these as /logout.php, /signout.aspx, /logoff.jsp.
DESTRUCTIVE_SEGMENTS = frozenset({
    # Session termination
    "logout", "logoff", "log-out", "log_out", "signout", "sign-out", "sign_out",
    "end-session", "endsession", "invalidate-session", "revoke-session",
    # Account / data destruction
    "delete-account", "deleteaccount", "deactivate", "deactivate-account",
    "close-account", "closeaccount", "cancel-account", "cancelaccount",
    "unsubscribe", "drop", "truncate",
    # Password / credential reset (sending a payload here corrupts the reset flow)
    "reset-password", "resetpassword", "change-password", "changepassword",
})


def destructive_segment(url_or_path: str) -> Optional[str]:
    """Return the destructive last path segment of a URL or path, else None."""
    path = urlparse(url_or_path).path if "://" in url_or_path else url_or_path.split("?", 1)[0]
    last_segment = path.lower().rstrip("/").rsplit("/", 1)[-1]
    stem = last_segment.split(".", 1)[0]
    if last_segment in DESTRUCTIVE_SEGMENTS:
        return last_segment
    if stem in DESTRUCTIVE_SEGMENTS:
        return stem
    return None

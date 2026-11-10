"""Local, per-host login journal.

Append-only JSONL per target host under ``~/.dast-ai/login_journal/<host>.jsonl`` — OUTSIDE
the repository (never committed) — recording every login attempt's OUTCOME (success/error)
and, on success, the reproducible shape of what worked (strategy, auth endpoint, request-body
variant, success URL). Secrets are NEVER written (no password, token or cookie values) — only
the shape, so a login can be reproduced and failures debugged. Mirrors the per-host local-store
pattern of ``dast/app_knowledge/store.py`` (0700 dir + host resolver).

The SPA login strategy reads :func:`last_success` to try the known-good endpoint first instead
of re-probing every default endpoint each run.
"""

from __future__ import annotations

import json
import stat
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_JOURNAL_DIR = Path.home() / ".dast-ai" / "login_journal"
_MAX_SCAN_LINES = 500  # cap how many trailing lines last_success scans

# Defence-in-depth: these keys must never land in a journal entry even if a caller passes them.
_SECRET_KEYS = frozenset({
    "password", "secret", "token", "authorization", "cookie", "access_token",
    "refresh_token", "jwt",
})


def journal_dir() -> Path:
    """Return the login-journal directory, creating it 0700 if missing."""
    _JOURNAL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        _JOURNAL_DIR.chmod(stat.S_IRWXU)  # 0700
    except OSError as exc:
        logger.warning("could not chmod login_journal dir", error=str(exc))
    return _JOURNAL_DIR


def _normalise_host(host_or_url: str) -> str:
    """Bare lowercase hostname from a host or URL (no scheme, no port)."""
    value = (host_or_url or "").strip()
    if not value:
        return ""
    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
    return value.split(":", 1)[0].lower().strip()


def _path_for(host: str) -> Path:
    return journal_dir() / f"{host}.jsonl"


def record(host_or_url: str, outcome: str, *, strategy: str = "", endpoint: str = "",
           body_shape: str = "", success_url: str = "", reason: str = "") -> Optional[str]:
    """Append one login-attempt record for a host. Returns the host key, or None on bad
    input / write error. ``outcome`` must be "success" or "error". Never writes secrets."""
    host = _normalise_host(host_or_url)
    if not host or outcome not in ("success", "error"):
        return None
    entry: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "host": host,
        "outcome": outcome,
        "strategy": str(strategy or "")[:40],
        "endpoint": str(endpoint or "")[:300],
        "body_shape": str(body_shape or "")[:200],
        "success_url": str(success_url or "")[:300],
        "reason": str(reason or "")[:300],
    }
    entry = {k: v for k, v in entry.items() if k.lower() not in _SECRET_KEYS}
    try:
        with _path_for(host).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        return host
    except OSError as exc:
        logger.warning("could not append login journal", host=host, error=str(exc))
        return None


def last_success(host_or_url: str) -> Optional[Dict[str, Any]]:
    """Return the most recent success record (with endpoint/body_shape) for a host, or None."""
    host = _normalise_host(host_or_url)
    if not host:
        return None
    path = _path_for(host)
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[-_MAX_SCAN_LINES:]
    except OSError:
        return None
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(rec, dict) and rec.get("outcome") == "success" and rec.get("endpoint"):
            return rec
    return None

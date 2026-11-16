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

from dast.session import site_map
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_JOURNAL_DIR = Path.home() / ".dast-ai" / "login_journal"
_MAX_SCAN_LINES = 500  # cap how many trailing lines last_success scans

# Learned wins expire: a journal entry recorded long ago describes a login surface
# that may have moved/rotated since. Older entries (and everything written before
# ts_epoch existed) are ignored by last_success/last_winning_strategy.
_JOURNAL_TTL_S = 7 * 24 * 3600

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


def _key(host_or_url: str) -> str:
    """Storage key: the site (product-group) id when the host is grouped, else the bare host."""
    return site_map.site_key(host_or_url) or _normalise_host(host_or_url)


def _read_lines(host_or_url: str) -> list[str]:
    """Trailing journal lines for a host, read from its site-key file, falling back to the legacy
    per-host file when the host is now grouped but only the old per-host journal exists."""
    key = _key(host_or_url)
    path = _path_for(key)
    if not path.is_file():
        legacy = _normalise_host(host_or_url)
        if legacy and legacy != key:
            path = _path_for(legacy)
        if not path.is_file():
            return []
    try:
        return path.read_text(encoding="utf-8").splitlines()[-_MAX_SCAN_LINES:]
    except OSError:
        return []


def record(host_or_url: str, outcome: str, *, strategy: str = "", endpoint: str = "",
           body_shape: str = "", success_url: str = "", reason: str = "",
           verified: Optional[bool] = None) -> Optional[str]:
    """Append one login-attempt record for a host. Returns the host key, or None on bad
    input / write error. ``outcome`` must be "success" or "error". ``verified`` records
    whether a structural session probe confirmed the success (None = not probed). Never
    writes secrets."""
    host = _normalise_host(host_or_url)
    if not host or outcome not in ("success", "error"):
        return None
    # Key by the site (product-group) so all of a product's login hosts (e.g. an SSO identity host
    # + the app host) share one journal; falls back to the bare host when ungrouped.
    key = _key(host_or_url)
    entry: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ts_epoch": time.time(),
        "host": key,
        "outcome": outcome,
        "strategy": str(strategy or "")[:40],
        "endpoint": str(endpoint or "")[:300],
        "body_shape": str(body_shape or "")[:200],
        "success_url": str(success_url or "")[:300],
        "reason": str(reason or "")[:300],
    }
    if verified is not None:
        entry["verified"] = bool(verified)
    entry = {k: v for k, v in entry.items() if k.lower() not in _SECRET_KEYS}
    try:
        with _path_for(key).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        return key
    except OSError as exc:
        logger.warning("could not append login journal", host=key, error=str(exc))
        return None


def _is_stale(rec: Dict[str, Any]) -> bool:
    """Records without a parseable epoch (legacy entries) count as stale — the TTL's
    whole point is to stop a poisoned winner from living forever."""
    epoch = rec.get("ts_epoch")
    if not isinstance(epoch, (int, float)):
        return True
    return (time.time() - epoch) > _JOURNAL_TTL_S


def last_success(host_or_url: str) -> Optional[Dict[str, Any]]:
    """Return the most recent success record (with endpoint/body_shape) for a host, or None.

    Two invalidation rules keep a poisoned winner from living forever:
    - entries older than ``_JOURNAL_TTL_S`` (or predating ``ts_epoch``) are ignored;
    - a success whose endpoint is targeted by a NEWER error is skipped — the last
      attempt against that endpoint failed, so the learned shape no longer works."""
    if not _normalise_host(host_or_url):
        return None
    lines = _read_lines(host_or_url)
    invalidated_endpoints: set = set()
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict) or _is_stale(rec):
            continue
        if rec.get("outcome") == "error" and rec.get("endpoint"):
            invalidated_endpoints.add(rec["endpoint"])
            continue
        if (rec.get("outcome") == "success" and rec.get("endpoint")
                and rec["endpoint"] not in invalidated_endpoints):
            return rec
    return None


def recent_records(host_or_url: str, *, limit: int = _MAX_SCAN_LINES) -> list[Dict[str, Any]]:
    """Parsed records for a host, most-recent-first (all outcomes, all strategies). Unlike
    :func:`last_success` this does not require an ``endpoint``, so it sees deterministic/llm
    wins too. Tolerates malformed lines; returns [] for an unknown host. Never raises."""
    if not _normalise_host(host_or_url):
        return []
    lines = _read_lines(host_or_url)
    records: list[Dict[str, Any]] = []
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(rec, dict):
            records.append(rec)
        if len(records) >= limit:
            break
    return records


def last_winning_strategy(host_or_url: str) -> Optional[str]:
    """The ``strategy`` name of the most recent success for a host, or None. Any strategy
    (deterministic/spa_api/llm) — used to try a host's known-good strategy first.

    A poisoned winner is worse than no winner (it is reordered to the FRONT of the
    cascade), so the promotion is failure-invalidated: if the newest non-stale record
    for the host is an ERROR, the previous success is not trusted — fall back to the
    default order and let the cascade re-learn."""
    for rec in recent_records(host_or_url):
        if _is_stale(rec):
            continue
        if rec.get("outcome") == "error":
            return None
        if rec.get("outcome") == "success" and rec.get("strategy"):
            return str(rec["strategy"])
    return None

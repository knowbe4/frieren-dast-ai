"""Local, per-host learned transport capability.

Append-only JSONL per target host under ``~/.dast-ai/transport_capability/<host>.jsonl`` —
OUTSIDE the repository (never committed) — recording what Frieren has learned about HOW to
reach a host/sub-app: whether its authenticated requests work over the API path
(``send_request`` → httpx-through-proxy), the browser session (``browser_fetch`` →
``page.request.fetch``), or both, and which to prefer. The copilot's transport fallback seeds
this (e.g. an API 401 that only a browser re-issue resolves → ``prefer="browser"``), and later
turns read it so the preference is remembered instead of re-discovered.

Mirrors the per-host local-store pattern of ``dast/session/login_journal.py`` /
``dast/app_knowledge/store.py`` (0700 dir + host resolver + parent-domain fallback). No secrets
are involved (transport names only), but the same defence-in-depth key scrub is applied anyway.
Keyed by host + sub-app (``auth_provider.subapp_for_path``) + an optional task, because sub-apps
on one host can differ (two sub-apps) and a browser-only quirk of one must not flip the host.
"""

from __future__ import annotations

import json
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dast.session import site_map
from dast.session.auth_provider import subapp_for_path
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_DIR = Path.home() / ".dast-ai" / "transport_capability"
_MAX_SCAN_LINES = 500  # cap how many trailing lines a resolve scans

_AUTH_VALUES = frozenset({"api", "browser", "both"})
_PREFER_VALUES = frozenset({"api", "browser"})

# Defence-in-depth: these keys must never land in a record even if a caller passes them.
_SECRET_KEYS = frozenset({
    "password", "secret", "token", "authorization", "cookie", "access_token",
    "refresh_token", "jwt",
})


def capability_dir() -> Path:
    """Return the transport-capability directory, creating it 0700 if missing."""
    _DIR.mkdir(parents=True, exist_ok=True)
    try:
        _DIR.chmod(stat.S_IRWXU)  # 0700
    except OSError as exc:
        logger.warning("could not chmod transport_capability dir", error=str(exc))
    return _DIR


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
    return capability_dir() / f"{host}.jsonl"


def _path_component(host_or_url: str, path: str) -> str:
    """The request path to key the sub-app on: the explicit ``path`` when given, else the path
    component of ``host_or_url`` when it is a full URL."""
    if path:
        return path
    if "://" in (host_or_url or ""):
        return urlparse(host_or_url).path or ""
    return ""


def record_capability(host_or_url: str, path: str = "", *, auth: str, prefer: str,
                      reason: str = "", task: Optional[str] = None) -> Optional[str]:
    """Append one learned-transport record for a (host, sub-app, task). Returns the host key,
    or None on bad input / write error. ``auth`` must be api|browser|both, ``prefer`` api|browser.
    Never raises, never writes secrets."""
    host = _normalise_host(host_or_url)
    if not host or auth not in _AUTH_VALUES or prefer not in _PREFER_VALUES:
        return None
    # Key by the site (product-group) so a product's sibling hosts share learned transport;
    # falls back to the bare host when ungrouped.
    key = site_map.site_key(host_or_url) or host
    entry: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "host": key,
        "sub_app": subapp_for_path(_path_component(host_or_url, path), site_map.site_for_host(host_or_url) or "") or "",
        "task": str(task or ""),
        "auth": auth,
        "prefer": prefer,
        "reason": str(reason or "")[:300],
    }
    entry = {k: v for k, v in entry.items() if k.lower() not in _SECRET_KEYS}
    try:
        with _path_for(key).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        return key
    except OSError as exc:
        logger.warning("could not append transport capability", host=key, error=str(exc))
        return None


def _read_records(host: str) -> List[Dict[str, Any]]:
    """Parsed records for an exact host, most-recent-first. Tolerates malformed lines."""
    path = _path_for(host)
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[-_MAX_SCAN_LINES:]
    except OSError:
        return []
    out: List[Dict[str, Any]] = []
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def capability_for(host_or_url: str, path: str = "",
                   task: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Resolve the learned transport record for a (host, request path, task), or None.

    Host resolution uses parent-domain fallback (exact host, then broader parents, never a bare
    TLD) like app_knowledge. Within a host file, specificity widens from the exact
    (sub_app, task) to (sub_app, any-task) to host-level (no sub_app, no task); the freshest
    record of the most specific matching tier wins. A more specific HOST always beats a parent.
    Never raises."""
    host = _normalise_host(host_or_url)
    if not host:
        return None
    want_sub = subapp_for_path(_path_component(host_or_url, path), site_map.site_for_host(host_or_url) or "") or ""
    want_task = str(task or "")
    # Tiers from most to least specific, de-duplicated.
    tiers: List[tuple] = []
    for tier in ((want_sub, want_task), (want_sub, ""), ("", "")):
        if tier not in tiers:
            tiers.append(tier)

    labels = host.split(".")
    # Site (product-group) key first (shared across a product's hosts), then exact host and
    # broader parents (legacy per-host fallback). De-duped, order kept.
    host_candidates = [site_map.site_key(host_or_url)] + \
        ([".".join(labels[i:]) for i in range(len(labels) - 1)] or [host])
    _seen: set = set()
    host_candidates = [c for c in host_candidates if c and not (c in _seen or _seen.add(c))]
    for candidate in host_candidates:
        records = _read_records(candidate)
        if not records:
            continue
        for sub_key, task_key in tiers:
            for rec in records:  # most-recent-first
                if rec.get("sub_app", "") == sub_key and rec.get("task", "") == task_key:
                    return rec
    return None

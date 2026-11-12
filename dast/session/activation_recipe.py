"""Local, learned sub-app ACTIVATION-RECIPE store.

Some sub-apps only mint their working service Bearer after the SPA loads a particular page — an
"activation" route (e.g. a content-studio / customization view). Rather than hardcoding that nav
per sub-app in the sub-app map's ``prime.nav``, Frieren LEARNS it from observed traffic: the
``Referer`` of the SPA's OWN first authenticated call to the sub-app IS that activation page. This
store persists, per (site, sub_app), the learned activation nav so the prime recovery reuses it —
and, because it is keyed by the product-group ``site`` (``site_map.site_key``), a recipe learned on
one subdomain serves the product's siblings.

Append-only JSONL under ``~/.dast-ai/activation_recipe/<site>.jsonl`` — OUTSIDE the repository
(never committed). Mirrors the local-store pattern of ``dast/session/transport_capability.py`` (0700
dir + freshest-wins resolve). No secrets are stored (paths/URLs only); the same key scrub is applied.
"""

from __future__ import annotations

import json
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from dast.session import site_map
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_DIR = Path.home() / ".dast-ai" / "activation_recipe"
_MAX_SCAN_LINES = 500

# Defence-in-depth: never let a secret-ish key land in a record even if a caller passes one.
_SECRET_KEYS = frozenset({
    "password", "secret", "token", "authorization", "cookie", "access_token",
    "refresh_token", "jwt",
})


def recipe_dir() -> Path:
    """Return the activation-recipe directory, creating it 0700 if missing."""
    _DIR.mkdir(parents=True, exist_ok=True)
    try:
        _DIR.chmod(stat.S_IRWXU)  # 0700
    except OSError as exc:
        logger.warning("could not chmod activation_recipe dir", error=str(exc))
    return _DIR


def _path_for(key: str) -> Path:
    return recipe_dir() / f"{key}.jsonl"


def record_activation(host_or_url: str, sub_app: str, nav: str, *,
                      source: str = "learned") -> Optional[str]:
    """Append one learned activation recipe for (site, sub_app): the ``nav`` (a URL/path) whose SPA
    load mints the sub-app's working Bearer. Keyed by the product-group site (falls back to the bare
    host). Returns the storage key, or None on bad input / write error. Never raises, never writes
    secrets."""
    key = site_map.site_key(host_or_url)
    sub = (sub_app or "").strip()
    nav_s = (nav or "").strip()
    if not key or not sub or not nav_s:
        return None
    entry: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "site": key,
        "sub_app": sub,
        "nav": nav_s[:500],
        "source": str(source or "")[:40],
    }
    entry = {k: v for k, v in entry.items() if k.lower() not in _SECRET_KEYS}
    try:
        with _path_for(key).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        return key
    except OSError as exc:
        logger.warning("could not append activation recipe", site=key, error=str(exc))
        return None


def _read_records(key: str) -> List[Dict[str, Any]]:
    """Parsed records for a site key, most-recent-first. Tolerates malformed lines."""
    path = _path_for(key)
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


def activation_nav(host_or_url: str, sub_app: str) -> Optional[str]:
    """The freshest learned activation nav for (site, sub_app), or None. Resolved by the product
    site so a recipe learned on one subdomain serves the product's siblings."""
    key = site_map.site_key(host_or_url)
    sub = (sub_app or "").strip()
    if not key or not sub:
        return None
    for rec in _read_records(key):
        if rec.get("sub_app", "") == sub and rec.get("nav"):
            return str(rec["nav"])
    return None


def learn_from_history(store: Any, host_or_url: str, sub_app: str) -> Optional[str]:
    """Learn the activation nav for a sub-app from proxy history: the ``Referer`` of the SPA's OWN
    freshest authenticated (2xx, Bearer, source != copilot) request whose path maps to *sub_app*.
    That Referer is the page whose load minted the sub-app's working Bearer. Records it and returns
    the nav, or None when no such request is in history. Never raises."""
    from dast.session.auth_provider import subapp_for_path

    if store is None:
        return None
    site = site_map.site_for_host(host_or_url) or ""
    sub = (sub_app or "").strip()
    if not sub:
        return None
    try:
        entries = store.all_entries()
    except Exception:
        return None
    # Freshest first.
    for entry in reversed(entries):
        try:
            src = _get(entry, "source")
            if src == "copilot":
                continue
            status = _get(entry, "status") or _get(entry, "response_status")
            if not (isinstance(status, int) and 200 <= status < 300):
                continue
            url = _get(entry, "url") or ""
            path = _path_of(url)
            if subapp_for_path(path, site) != sub:
                continue
            headers = _get(entry, "request_headers") or {}
            referer = ""
            has_bearer = False
            for k, v in headers.items():
                lk = k.lower()
                if lk == "referer":
                    referer = str(v)
                elif lk == "authorization" and str(v).startswith("Bearer "):
                    has_bearer = True
            if not referer or not has_bearer:
                continue
            record_activation(host_or_url, sub, referer, source="history")
            return referer
        except Exception:
            continue
    return None


def _get(entry: Any, name: str) -> Any:
    if isinstance(entry, dict):
        return entry.get(name)
    return getattr(entry, name, None)


def _path_of(url: str) -> str:
    if "://" in (url or ""):
        from urllib.parse import urlparse
        return urlparse(url).path or "/"
    return url or "/"

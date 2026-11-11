"""Local, operator-supplied SITE (product-group) map.

A real target product spans several domains/subdomains with heavy integration — e.g. an admin
console, its SSO identity host, add-in hosts and API hosts are all ONE product, often sharing a
login (SSO) and sub-apps. Frieren's learned stores (app_knowledge, login_journal,
transport_capability, activation recipes) should therefore key off the PRODUCT, not each bare host,
so a learning on one subdomain is available to its siblings and isolated from unrelated products.

That grouping is TARGET-SPECIFIC topology, so it is NOT hardcoded in the repo. It is read from a
local file OUTSIDE the repository — ``~/.dast-ai/sites.json`` — mirroring ``dast/session/subapp_map``.
With no config the map is empty and ``site_key`` falls back to the bare host, so every store behaves
exactly as before (per-host) — safe on CI and any machine without the file.

Config shape (``~/.dast-ai/sites.json``)::

    { "sites": [
        {"id": "productA", "domains": ["admin.product-a.example.com", "*.esi.product-a.example.com"]},
        {"id": "productB", "domains": ["app.product-b.example.com"]}
    ] }

A ``domains`` entry is either an exact host (``admin.product-a.example.com``) or a wildcard suffix
(``*.esi.product-a.example.com`` — matches any subdomain of ``esi.product-a.example.com``, not the bare
``esi.product-a.example.com`` itself).
The most specific (longest) matching pattern wins. Nothing here is a secret (names only); the loader
never raises.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Local config, outside the repo. Test-redirectable (monkeypatch this attribute), like
# subapp_map._CONFIG_PATH / transport_capability._DIR.
_CONFIG_PATH = Path.home() / ".dast-ai" / "sites.json"

# Parsed-sites cache: site_key()/site_for_host() are called in hot paths, so the file is read once
# per process. _reset_cache() clears it (tests redirect _CONFIG_PATH then reset).
_cache: Optional[List[Tuple[str, Tuple[str, ...]]]] = None


def _reset_cache() -> None:
    """Drop the parsed-config cache so the next access re-reads _CONFIG_PATH (for tests)."""
    global _cache
    _cache = None


def normalise_host(host_or_url: str) -> str:
    """Bare lowercase hostname from a host or URL (no scheme, no port)."""
    value = (host_or_url or "").strip()
    if not value:
        return ""
    if "://" in value:
        from urllib.parse import urlparse
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
    return value.split(":", 1)[0].lower().strip()


def _load_sites() -> List[Tuple[str, Tuple[str, ...]]]:
    """Read the site groups from the local config. Cached. Never raises: a missing or malformed
    file yields an empty list. Returns ``[(site_id, (domain_pattern, ...)), ...]``."""
    global _cache
    if _cache is not None:
        return _cache
    sites: List[Tuple[str, Tuple[str, ...]]] = []
    try:
        data = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
        for item in (data.get("sites") or []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            sid = str(item.get("id", "")).strip()
            domains = item.get("domains") or []
            if not sid or not isinstance(domains, list):
                continue
            pats = tuple(
                str(d).strip().lower() for d in domains if str(d).strip()
            )
            if pats:
                sites.append((sid, pats))
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        logger.warning("site_map: could not read local config, using empty map",
                       path=str(_CONFIG_PATH), error=str(exc))
        sites = []
    _cache = sites
    return _cache


def _pattern_matches(pattern: str, host: str) -> bool:
    """Exact host, or ``*.suffix`` matching any subdomain of ``suffix`` (not the bare suffix)."""
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return bool(suffix) and host.endswith("." + suffix)
    return pattern == host


def site_for_host(host_or_url: str) -> Optional[str]:
    """The product-group id for a host, or None when no group matches. The most specific (longest)
    matching domain pattern wins, so a sibling-specific group beats a broad wildcard."""
    host = normalise_host(host_or_url)
    if not host:
        return None
    best_sid: Optional[str] = None
    best_len = -1
    for sid, pats in _load_sites():
        for pat in pats:
            if _pattern_matches(pat, host) and len(pat) > best_len:
                best_sid, best_len = sid, len(pat)
    return best_sid


def site_key(host_or_url: str) -> str:
    """The storage key for a host's learned knowledge: the product-group id when the host belongs to
    a configured site, else the bare host (so unmapped hosts keep their per-host behaviour). Empty
    string only for an empty/invalid input."""
    return site_for_host(host_or_url) or normalise_host(host_or_url)


def sites() -> Dict[str, Tuple[str, ...]]:
    """``{site_id: (domain_pattern, ...)}`` — the configured groups (for introspection/UX)."""
    return {sid: pats for sid, pats in _load_sites()}

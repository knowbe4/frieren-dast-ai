"""Local, operator-supplied sub-app / service map.

A target can serve several internal services under one host, each behind its own short-lived
Bearer minted from ``GET /spa/session`` (``user.attributes.<app>Jwt``). To attach the RIGHT
token per request path, Frieren needs to know which path prefix maps to which service and which
JWT field + probe endpoint that service uses.

That mapping is TARGET-SPECIFIC internal topology, so it is NOT hardcoded in the repo. It is read
from a local config file OUTSIDE the repository — ``~/.dast-ai/subapp_map.json`` — mirroring the
local-store pattern of ``dast/session/transport_capability.py`` and ``dast/profiles``. The repo
ships generic (``subapp_map.example.json`` shows the shape); each operator supplies their target's
map locally. With no config the map is empty and selection falls back to host-level Bearer exactly
as for any unmapped path — safe on CI and any machine without the file.

Config shape (``~/.dast-ai/subapp_map.json``)::

    { "sub_apps": [
        {"prefix": "/serviceA", "app": "appA", "jwt_field": "appAJwt", "probe": "/serviceA/graphql",
         "prime": {"endpoint": "/serviceA/session", "method": "GET", "cookie": "_serviceA_session"}},
        {"app": "appB", "jwt_field": "appBJwt"}
    ] }

``prefix`` and ``probe`` are optional (an app may have a JWT field but no path prefix). ``prime`` is an
optional per-app session-priming descriptor: some services gate on a session COOKIE (set by an
authenticated GET to a priming endpoint) that the Bearer alone cannot replace. When present
(``{endpoint, method?, cookie, referer?}``), Frieren can auto-mint that cookie through the proxy before
an authenticated request to the sub-app. Nothing here is a secret (names/paths only); the loader never
raises.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Local config, outside the repo. Test-redirectable (monkeypatch this attribute), like
# transport_capability._DIR.
_CONFIG_PATH = Path.home() / ".dast-ai" / "subapp_map.json"

# Parsed-entries cache: subapp_for_path() is called in a loop (collect_host_bearer), so the file
# is read once per process. _reset_cache() clears it (tests redirect _CONFIG_PATH then reset).
_cache: Optional[List[Dict[str, Any]]] = None


def _reset_cache() -> None:
    """Drop the parsed-config cache so the next access re-reads _CONFIG_PATH (for tests)."""
    global _cache
    _cache = None


def _parse_prime(raw: Any) -> Optional[Dict[str, str]]:
    """Normalize an optional per-app session-prime descriptor. Two independent, combinable modes
    (different login systems authenticate differently, so a descriptor may declare either or both;
    the recovery tries one then falls back to the other):

    - COOKIE mode (``endpoint`` + ``cookie``, ``method`` default GET, optional ``referer``): mint a
      session cookie by an authenticated GET to the prime endpoint (via ``prime_session``).
    - BROWSER-ACTIVATION mode (``nav``): a URL/path to open in the live browser so the SPA mints
      the sub-app's working service Bearer (then captured from history by per-service selection).

    Returns the normalized dict, or None when neither mode is validly declared."""
    if not isinstance(raw, dict):
        return None
    endpoint = str(raw.get("endpoint", "")).strip()
    cookie = str(raw.get("cookie", "")).strip()
    nav = str(raw.get("nav", "")).strip()
    cookie_mode = bool(endpoint and cookie)
    if not cookie_mode and not nav:
        return None
    return {
        "endpoint": endpoint if cookie_mode else "",
        "method": (str(raw.get("method", "")).strip().upper() or "GET") if cookie_mode else "",
        "cookie": cookie if cookie_mode else "",
        "referer": str(raw.get("referer", "")).strip() if cookie_mode else "",
        "nav": nav,
    }


def _load_entries() -> List[Dict[str, Any]]:
    """Read and validate the sub-app entries from the local config. Cached. Never raises:
    a missing or malformed file yields an empty list."""
    global _cache
    if _cache is not None:
        return _cache
    entries: List[Dict[str, Any]] = []
    try:
        raw = _CONFIG_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        for item in (data.get("sub_apps") or []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            app = str(item.get("app", "")).strip()
            if not app:
                continue
            entries.append({
                "app": app,
                "prefix": str(item.get("prefix", "")).strip().lower(),
                "jwt_field": str(item.get("jwt_field", "")).strip(),
                "probe": str(item.get("probe", "")).strip(),
                "prime": _parse_prime(item.get("prime")),
                "site": str(item.get("site", "")).strip(),
            })
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        logger.warning("subapp_map: could not read local config, using empty map",
                       path=str(_CONFIG_PATH), error=str(exc))
        entries = []
    _cache = entries
    return _cache


def subapp_prefixes(site: str = "") -> Tuple[Tuple[str, str], ...]:
    """``((path_prefix, app), ...)`` for entries that declare a prefix — the data behind
    ``auth_provider.subapp_for_path``.

    When *site* is given, restrict to sub-apps belonging to that site PLUS site-less entries
    (a sub-app with no ``site`` is global, as before). When *site* is empty (default), return all
    prefixes — so an unscoped call behaves exactly as it did before sites existed. This lets two
    products that happen to share a path prefix keep distinct sub-apps once each is tagged with a
    ``site``, while leaving today's untagged configs completely unchanged."""
    out = []
    for e in _load_entries():
        if not e["prefix"]:
            continue
        if site and e["site"] and e["site"] != site:
            continue
        out.append((e["prefix"], e["app"]))
    return tuple(out)


def app_site(app: str) -> str:
    """The site a sub-app belongs to (its ``site`` field), or "" when untagged/absent."""
    for e in _load_entries():
        if e["app"] == app and e["site"]:
            return e["site"]
    return ""


def app_map() -> Dict[str, Dict[str, str]]:
    """``{app: {"field": <jwt_field>, "probe": <probe_path>}}`` for entries that declare a JWT
    field — the data behind ``app_knowledge_tools`` token minting."""
    return {
        e["app"]: {"field": e["jwt_field"], "probe": e["probe"]}
        for e in _load_entries() if e["jwt_field"]
    }


def prime_for_app(app: str) -> Optional[Dict[str, str]]:
    """The session-prime descriptor ``{endpoint, method, cookie, referer}`` for *app*, or None when
    the app declares no (valid) ``prime`` — the data behind ``prime_session`` auto-minting."""
    for e in _load_entries():
        if e["app"] == app and e.get("prime"):
            return dict(e["prime"])
    return None

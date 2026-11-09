"""Single source of truth for sub-app Bearer selection from proxy history.

Phase 0 of the auth consolidation: this module collapses the two historical copies of the
same history scan — the module-level ``scan_history_bearer`` and
``CopilotSession._capture_bearer_tokens`` — into one implementation, and centralizes the
sub-app path map and the JWT ``exp``/freshness helpers that were duplicated across the copilot
engine and the raw tool path.

modstore and ccm share one host, so a single host-keyed token would let one sub-app's token
overwrite the other's; selection is by request path instead (``by_app`` index).
"""

from __future__ import annotations

import time as _time
from typing import Any, Dict, Optional

# Sub-app path prefixes -> app name. Keep in sync with
# dast/tools/app_knowledge_tools.py::_APP_MAP probe paths.
SUBAPP_PREFIXES: tuple = (
    ("/modstore", "modstore"),
    ("/customercontent", "ccm"),
)


def subapp_for_path(path: str) -> Optional[str]:
    """Map a request path to its sub-app name, or None for a non-sub-app path."""
    p = (path or "").lower()
    for prefix, app in SUBAPP_PREFIXES:
        if p.startswith(prefix):
            return app
    return None


def decode_jwt_exp(token: str) -> Optional[float]:
    """Extract the ``exp`` claim from a JWT without verifying the signature. None if the
    token is not a JWT, has no ``exp``, or cannot be parsed."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        import base64
        import json as _json
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = _json.loads(base64.urlsafe_b64decode(payload))
        exp = claims.get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


def rec_is_fresh(rec: Optional[Dict[str, Any]], now: Optional[float] = None) -> bool:
    """A Bearer record is usable when it has a token and is not past its ``exp``."""
    if not isinstance(rec, dict) or not rec.get("token"):
        return False
    exp = rec.get("exp")
    return exp is None or exp > (now if now is not None else _time.time())


def _field(entry: Any, name: str) -> Any:
    # Entries are ProxyEntry dataclasses in production and dicts in some tests/imports;
    # read either shape without assuming .get() exists.
    if isinstance(entry, dict):
        return entry.get(name)
    return getattr(entry, name, None)


def collect_host_bearer(store: Any, host: str, *,
                        exclude_source: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Scan proxy history (freshest first) for non-expired ``Authorization: Bearer`` tokens
    on *host*'s registrable domain, in ONE pass. Returns the freshest host-level record
    augmented with a ``by_app`` map (freshest token per sub-app, keyed by the auth
    endpoint's sub-app), or None. Never raises.

    ``exclude_source`` skips proxy-history entries whose ``source`` matches (the copilot
    engine passes ``"copilot"`` so it never re-selects a token it itself replayed)."""
    if store is None or not host:
        return None
    try:
        entries = store.all_entries()
    except Exception:
        return None
    now = _time.time()
    parts = host.lower().split(".")
    domain_suffix = ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()

    host_level: Optional[Dict[str, Any]] = None
    by_app: Dict[str, Dict[str, Any]] = {}
    for entry in reversed(entries):  # freshest first
        try:
            entry_host_raw = _field(entry, "host") or host
            entry_host = entry_host_raw.lower()
            if domain_suffix not in entry_host:
                continue
            if exclude_source is not None and _field(entry, "source") == exclude_source:
                continue
            req_headers = _field(entry, "request_headers") or {}
            auth_val = ""
            for key, value in req_headers.items():
                if key.lower() == "authorization":
                    auth_val = str(value)
                    break
            if not auth_val.startswith("Bearer "):
                continue
            token_val = auth_val[7:].strip()
            exp = decode_jwt_exp(token_val)
            if exp is not None and exp < now:
                continue
            auth_endpoint = _field(entry, "path") or ""
            record = {"token": token_val, "exp": exp, "auth_endpoint": auth_endpoint,
                      "captured_at": now, "source_entry_id": _field(entry, "id") or "",
                      "matched_host": entry_host_raw}
            if host_level is None:
                host_level = dict(record)  # freshest overall = host-level default
            app = subapp_for_path(auth_endpoint)
            if app and app not in by_app:
                by_app[app] = dict(record)  # freshest per sub-app
        except Exception:
            continue
    if host_level is None:
        return None
    if by_app:
        host_level["by_app"] = by_app
    return host_level


def select_bearer(record: Optional[Dict[str, Any]], path: str) -> Optional[Dict[str, Any]]:
    """Pick the Bearer record for a request path: the per-sub-app token when the path maps
    to a sub-app and one exists, else the host-level record."""
    if not isinstance(record, dict):
        return None
    app = subapp_for_path(path)
    by_app = record.get("by_app")
    if app and isinstance(by_app, dict) and app in by_app:
        return by_app[app]
    return record


def scan_history_bearer(store: Any, host: str, path: str, *,
                        exclude_source: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Freshest non-expired Bearer in proxy history for a (host, request path). One-call
    wrapper over collect_host_bearer + select_bearer. Returns a record
    ``{token, exp, auth_endpoint, ...}`` or None. Never raises."""
    rec = collect_host_bearer(store, host, exclude_source=exclude_source)
    return select_bearer(rec, path) if rec else None

"""Traffic-learned token inventory — a redacted view of every credential seen for a host.

Systems that integrate with other systems carry several live credentials at once (session
cookies, per-sub-app JWT Bearers, custom auth headers, query-param tokens). This builds a single
view of that landscape for a host so the operator and the copilot can reason about which
credential an endpoint needs. Computed on demand from live proxy history — the history IS the
source, so there is no separate store and it is never stale.

SECURITY: no token or cookie VALUE is ever stored or returned — only the TYPE, where it was seen,
non-secret JWT claims, and a short non-reversible fingerprint to tell credentials apart.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict
from urllib.parse import parse_qsl, urlparse

from dast.session.auth_provider import collect_host_bearer
from dast.utils.jwt import decode_jwt_claims
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Non-secret JWT claims safe to surface (identity / scope / validity). Everything else is dropped.
_SAFE_CLAIMS = ("sub", "scope", "scp", "aud", "iss", "exp", "iat", "roles", "role", "email", "site")
# Custom auth headers worth inventorying (Authorization is already covered by the Bearer scan).
_AUTH_HEADERS = ("x-api-key", "api-key", "x-auth-token", "x-access-token",
                 "x-amz-security-token", "authentication", "x-csrf-token", "x-xsrf-token")
# Query-param names that typically carry a credential.
_TOKEN_PARAMS = ("token", "access_token", "api_key", "apikey", "jwt", "sig", "signature", "auth")


def _fingerprint(value: str) -> str:
    """Short, non-reversible id so two credentials can be told apart without leaking the value."""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:8]


def _safe_claims(token: str) -> Dict[str, Any]:
    """Decode a JWT and keep ONLY the non-secret allowlisted claims. Empty dict if not a JWT."""
    claims = decode_jwt_claims(token or "")
    if not isinstance(claims, dict):
        return {}
    return {k: claims[k] for k in _SAFE_CLAIMS if k in claims}


def _looks_jwt(value: Any) -> bool:
    return isinstance(value, str) and value.count(".") == 2 and len(value) > 20


def build_token_inventory(store: Any, host: str) -> Dict[str, Any]:
    """Redacted inventory of credentials observed for *host* in proxy history. Never raises."""
    inv: Dict[str, Any] = {"host": host, "bearers": [], "cookies": [],
                           "headers": [], "query_tokens": []}
    if store is None or not host:
        return inv
    now = time.time()

    # ── Bearers: host-level + per sub-app (reuse the existing extractor) ──
    try:
        rec = collect_host_bearer(store, host, exclude_source="copilot")
    except Exception as exc:  # noqa: BLE001
        logger.debug("token_inventory: bearer scan failed", host=host, error=str(exc)[:120])
        rec = None
    if rec:
        seen_fp: set = set()

        def _add_bearer(app: str, r: Dict[str, Any]) -> None:
            tok = r.get("token") or ""
            fp = _fingerprint(tok)
            if not fp or fp in seen_fp:
                return
            seen_fp.add(fp)
            exp = r.get("exp")
            inv["bearers"].append({
                "app": app, "type": "jwt", "endpoint": r.get("auth_endpoint", ""),
                "fingerprint": fp, "exp": exp,
                "fresh": bool(exp is None or exp > now),
                "claims": _safe_claims(tok),
            })

        _add_bearer("(host)", rec)
        for app, r in (rec.get("by_app") or {}).items():
            if isinstance(r, dict):
                _add_bearer(app, r)

    # ── Cookies: names + flags; a cookie whose value is a JWT gets its claims ──
    try:
        cookies = store.get_cookies_for_host(host) or []
    except Exception as exc:  # noqa: BLE001
        logger.debug("token_inventory: cookie read failed", host=host, error=str(exc)[:120])
        cookies = []
    for c in cookies:
        name = c.get("name")
        if not name:
            continue
        val = c.get("value") or ""
        is_jwt = _looks_jwt(val)
        inv["cookies"].append({
            "name": name, "domain": c.get("domain", ""), "path": c.get("path", "/"),
            "secure": bool(c.get("secure", False)), "httpOnly": bool(c.get("httpOnly", False)),
            "type": "cookie+jwt" if is_jwt else "cookie",
            "fingerprint": _fingerprint(val),
            "claims": _safe_claims(val) if is_jwt else {},
        })

    # ── Custom auth headers + query-param tokens observed in traffic ──
    try:
        entries = store.in_scope_entries()
    except Exception as exc:  # noqa: BLE001
        logger.debug("token_inventory: history read failed", host=host, error=str(exc)[:120])
        entries = []
    hdr_seen: Dict[str, dict] = {}
    q_seen: Dict[str, dict] = {}
    hlow = host.lower()
    for e in entries:
        if (getattr(e, "host", "") or "").lower() != hlow:
            continue
        if getattr(e, "source", "") == "copilot":
            continue
        endpoint = getattr(e, "path", "") or getattr(e, "url", "") or ""
        for k, v in (getattr(e, "request_headers", {}) or {}).items():
            kl = str(k).lower()
            if kl in _AUTH_HEADERS and v and kl not in hdr_seen:
                hdr_seen[kl] = {"name": k, "type": "header", "endpoint": endpoint,
                                "fingerprint": _fingerprint(str(v))}
        query = urlparse(getattr(e, "url", "") or "").query
        if query:
            for pk, pv in parse_qsl(query):
                pkl = pk.lower()
                if pkl in _TOKEN_PARAMS and pv and pkl not in q_seen:
                    q_seen[pkl] = {"param": pk, "type": "query", "endpoint": endpoint,
                                   "fingerprint": _fingerprint(pv),
                                   "claims": _safe_claims(pv) if _looks_jwt(pv) else {}}
    inv["headers"] = list(hdr_seen.values())
    inv["query_tokens"] = list(q_seen.values())
    return inv

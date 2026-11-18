"""
Auth-header sniffing — find the most recent request headers that look like
credentials, for the "borrow auth from a real request" use case shared by
session snapshotting, suggestion scanning, and code-validation probing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence, Tuple

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry

logger = get_logger(__name__)

_AUTH_HEADER_NAMES = (
    "authorization", "x-auth-token", "x-api-key", "x-csrf-token",
    "x-requested-with", "cookie",
)


def extract_auth_headers(
    entries: Iterable["ProxyEntry"],
    host: Optional[str] = None,
    *,
    include_subdomains: bool = True,
    exclude_sources: Sequence[str] = ("agent", "imported"),
    limit: Optional[int] = None,
) -> Dict[str, str]:
    """
    Scan `entries` in reverse chronological order and return the auth-relevant
    headers (Authorization, X-Auth-Token, X-Api-Key, Cookie) from the most
    recent matching entry.

    `host=None` disables host filtering — any entry qualifies (used when
    snapshotting "whatever this whole session looked like most recently").
    `include_subdomains` also matches entries whose host is a subdomain of
    (or a parent domain of) `host`, via a 3-label base-domain heuristic.
    `limit` caps how many of the already-reverse-ordered entries are scanned
    before giving up; omit for an unbounded scan.
    """
    base_domain = None
    if host and include_subdomains:
        base_domain = ".".join(host.split(".")[-3:]) if host.count(".") >= 2 else host

    scanned = list(entries)[:limit] if limit is not None else entries

    auth_headers: Dict[str, str] = {}
    for entry in scanned:
        if entry.source in exclude_sources:
            continue
        if host is not None:
            host_matches = entry.host == host or (
                base_domain is not None and entry.host.endswith(base_domain)
            )
            if not host_matches:
                continue
        for k, v in (entry.request_headers or {}).items():
            if k.lower() in _AUTH_HEADER_NAMES:
                auth_headers[k] = v
        if auth_headers:
            break

    return auth_headers


# CSRF cookie names a double-submit / SPA framework typically mirrors into a header.
_CSRF_COOKIE_NAMES = ("CSRF-TOKEN", "csrf-token", "csrf_token", "XSRF-TOKEN", "xsrf-token")


def _cookie_value_map(cookies) -> Dict[str, str]:
    """Normalise cookies (a {name: value} map, a {name: playwright-dict} map, or an
    iterable of playwright cookie dicts) into a flat {name: value} map."""
    out: Dict[str, str] = {}
    if isinstance(cookies, dict):
        for name, val in cookies.items():
            out[name] = val.get("value", "") if isinstance(val, dict) else (val or "")
    else:
        for cookie in cookies or []:
            name = cookie.get("name")
            if name:
                out[name] = cookie.get("value", "") or ""
    return out


def build_cookie_header(cookies) -> str:
    """Join *cookies* into a ``Cookie`` header value.

    Accepts the same shapes as :func:`inject_csrf` (a ``{name: value}`` map, a
    ``{name: playwright-dict}`` map, or an iterable of playwright cookie dicts).
    """
    cookie_map = _cookie_value_map(cookies)
    return "; ".join(f"{name}={value}" for name, value in cookie_map.items() if name)


def _parent_domain(host: str) -> str:
    """Everything after the first label, when that leaves a >=2-label domain.
    ``api.foo.example.com`` -> ``foo.example.com``; ``example.com`` -> ``''`` (too short)."""
    labels = (host or "").split(".")
    parent = ".".join(labels[1:]) if len(labels) >= 3 else ""
    return parent if parent.count(".") >= 1 else ""


def host_matches_cookie_scope(entry_host: str, host: str) -> bool:
    """Match a proxy entry's host to *host* for cookie reuse. Session cookies are
    domain-scoped, so besides an exact / parent-child match we also treat SIBLING
    subdomains that share an immediate parent domain as a match
    (``api.foo.example.com`` <-> ``settings-api.foo.example.com``)."""
    eh = (entry_host or "").lower()
    h = (host or "").lower()
    if not h or not eh:
        return False
    if eh == h or eh.endswith("." + h) or h.endswith("." + eh):
        return True
    parent = _parent_domain(h)
    return bool(parent) and (eh == parent or eh.endswith("." + parent))


def parse_cookie_header(header: str) -> List[Tuple[str, str]]:
    """Split a ``Cookie`` request-header value into ``(name, value)`` pairs."""
    out: List[Tuple[str, str]] = []
    for seg in (header or "").split(";"):
        seg = seg.strip()
        if not seg or "=" not in seg:
            continue
        name, value = seg.split("=", 1)
        name = name.strip()
        if name:
            out.append((name, value.strip()))
    return out


def newest_cookie_header_for_host(store, host: str) -> Optional[str]:
    """Freshest live ``Cookie`` REQUEST header that actually transited the proxy for
    *host* (sibling-subdomain aware), or ``None``.

    This sidesteps the stale cookie jar: the in-memory jar is not reliably refreshed
    from SSO-callback ``Set-Cookie`` responses (those land under the callback host,
    a sibling of the app host, so ``get_cookies_for_host`` misses them), but the
    ``Cookie`` header the browser actually sent is ground truth for the host."""
    try:
        for entry in store.entries_newest_first():
            if not host_matches_cookie_scope(getattr(entry, "host", ""), host):
                continue
            headers = getattr(entry, "request_headers", None) or {}
            for k, v in headers.items():
                if k.lower() == "cookie" and v:
                    return str(v)
    except Exception as exc:
        logger.warning("newest_cookie_header_for_host failed", host=host, error=str(exc))
    return None


def freshest_cookie_header_for_host(store, host: str) -> Optional[str]:
    """Freshest ``Cookie`` header value for *host*: the newest live header that
    transited the proxy, falling back to one built from the cookie jar."""
    header = newest_cookie_header_for_host(store, host)
    if header:
        return header
    try:
        cookies = store.get_cookies_for_host(host) or []
    except Exception as exc:
        logger.warning("freshest_cookie_header_for_host jar lookup failed", host=host, error=str(exc))
        return None
    return build_cookie_header(cookies) or None


def freshest_cookies_for_host(store, host: str) -> List[dict]:
    """Freshest cookies for *host* as jar-shaped (Playwright-compatible) dicts.

    Values come from the newest live request ``Cookie`` header that transited the
    proxy (sibling-subdomain aware), with ``domain``/``path``/flags filled in from
    the jar when the cookie is known there. Falls back to the cookie jar when no
    live header is present. This is the capture equivalent of
    :func:`freshest_cookie_header_for_host`: it fixes capture grabbing pre-auth /
    stale jar cookies after an SSO login."""
    try:
        jar = store.get_cookies_for_host(host) or []
    except Exception as exc:
        logger.warning("freshest_cookies_for_host jar lookup failed", host=host, error=str(exc))
        jar = []
    header = newest_cookie_header_for_host(store, host)
    pairs = parse_cookie_header(header) if header else []
    if not pairs:
        return list(jar)
    by_name = {c.get("name"): c for c in jar if c.get("name")}
    result: List[dict] = []
    for name, value in pairs:
        meta = by_name.get(name) or {}
        result.append({
            "name": name,
            "value": value,
            "domain": meta.get("domain") or host,
            "path": meta.get("path") or "/",
            "secure": bool(meta.get("secure", True)),
            "httpOnly": bool(meta.get("httpOnly", False)),
        })
    return result


def apply_cookies(headers: Dict[str, str], cookies, *, refresh: bool = False) -> Dict[str, str]:
    """Set the ``Cookie`` header from *cookies* and inject the matching CSRF/XHR
    headers, mutating and returning ``headers``.

    Shared by the ``send_request`` tool and the repeater route so cookie + CSRF
    handling lives in one place (the copilot engine does the equivalent inline in
    ``_apply_session_auth``). Overwrites any existing ``Cookie`` header — the jar
    or named session is the source of truth; CSRF overwrite is governed by
    ``refresh`` (see :func:`inject_csrf`).
    """
    if not cookies:
        return headers
    cookie_header = build_cookie_header(cookies)
    if cookie_header:
        headers["Cookie"] = cookie_header
    return inject_csrf(headers, cookies, refresh=refresh)


def is_raw_secret_value(value: str) -> bool:
    """True when a header value is (or wraps) a raw JWT / long-opaque bearer token.

    A ``<placeholder>`` (e.g. ``<jwt>``) is NOT a secret (left for the placeholder
    gate). Reuses the existing credential detectors — no new heuristic."""
    from dast.plugins.sensitive_param_tracker import (
        _JWT_RE, _BEARER_RE, _shannon_entropy, _MIN_ENTROPY_BITS_PER_CHAR,
    )
    from dast.utils.placeholders import looks_like_placeholder

    raw = (value or "").strip()
    if not raw:
        return False
    candidates = [raw]
    low = raw.lower()
    for scheme in ("bearer ", "token ", "jwt "):
        if low.startswith(scheme):
            candidates.append(raw[len(scheme):].strip())
    for candidate in candidates:
        if not candidate or looks_like_placeholder(candidate):
            continue
        if _JWT_RE.match(candidate):
            return True
        if _BEARER_RE.match(candidate) and _shannon_entropy(candidate) >= _MIN_ENTROPY_BITS_PER_CHAR:
            return True
    return False


def strip_pasted_secret_headers(headers: Dict[str, str]) -> list:
    """Remove caller-pasted ``Authorization``/``Cookie`` headers whose value is a raw
    secret (JWT or long-opaque bearer), mutating ``headers``; return the stripped
    header NAMES.

    The tool layer injects the active session automatically (jar cookies + CSRF + a
    cached sub-app Bearer), so a hand-pasted raw token must never leave the machine —
    it is a secret-handling violation and usually stale/wrong anyway. A ``<placeholder>``
    value and ordinary (non-secret) header values are left untouched."""
    stripped = []
    for name in list(headers.keys()):
        if name.lower() not in ("authorization", "cookie"):
            continue
        value = str(headers.get(name, ""))
        if name.lower() == "cookie":
            parts = [seg.split("=", 1)[1] if "=" in seg else seg for seg in value.split(";")]
        else:
            parts = [value]
        if any(is_raw_secret_value(part) for part in parts):
            headers.pop(name, None)
            stripped.append(name)
    return stripped


_CALLER_AUTH_HEADER_NAMES = ("cookie", "authorization", "x-csrf-token", "x-xsrf-token")


def strip_caller_auth_headers(headers: Dict[str, str]) -> list:
    """Remove ALL caller-supplied auth headers (``Cookie``/``Authorization``/
    ``X-CSRF-Token``/``X-XSRF-Token``), case-insensitive, mutating ``headers``; return the
    stripped header NAMES.

    For the copilot-facing tools (``browser_fetch``, ``send_request``) where the managed
    session/browser is the sole source of truth for auth: the copilot repeatedly pastes a
    STALE raw Cookie/Bearer/CSRF token into the headers arg, and that override breaks the
    request (the live session would otherwise supply the right one). Unlike
    :func:`strip_pasted_secret_headers` this drops the header regardless of whether the value
    looks like a raw secret. Every other caller header (Origin/Referer/Content-Type/Accept/
    X-Requested-With/...) is left untouched."""
    stripped = []
    for name in list(headers.keys()):
        if name.lower() in _CALLER_AUTH_HEADER_NAMES:
            headers.pop(name, None)
            stripped.append(name)
    return stripped


def inject_csrf(headers: Dict[str, str], cookies, *, refresh: bool = False) -> Dict[str, str]:
    """Add the CSRF + XHR headers a cookie-authenticated SPA requires on a
    state-changing request, mutating and returning ``headers``.

    A SPA (Rails, Django, Angular, ...) mirrors a CSRF/XSRF cookie into an
    ``X-CSRF-Token`` request header; without it the server 403s every POST/PUT/
    PATCH/DELETE. ``cookies`` may be a ``{name: value}`` map, a ``{name:
    playwright-dict}`` map, or an iterable of playwright cookie dicts.

    - Sets ``X-CSRF-Token`` from the first matching CSRF/XSRF cookie.
    - Sets ``X-Requested-With: XMLHttpRequest`` when cookies exist.
    - ``refresh=False`` (copilot default): never overwrite a header already present.
    - ``refresh=True`` (scan default): overwrite a stale ``X-CSRF-Token`` with the
      current cookie value (the jar is the source of truth for active probes).
    """
    if not cookies:
        return headers
    cookie_map = _cookie_value_map(cookies)
    present = {k.lower(): k for k in headers}
    csrf = next((cookie_map[name] for name in _CSRF_COOKIE_NAMES if cookie_map.get(name)), None)
    if csrf and ("x-csrf-token" not in present or refresh):
        # Overwrite under the existing header key if one is present (any case), else add.
        headers[present.get("x-csrf-token", "X-CSRF-Token")] = csrf
    if "x-requested-with" not in present:
        headers["X-Requested-With"] = "XMLHttpRequest"
    return headers

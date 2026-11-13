"""Single source of truth for sub-app Bearer selection from proxy history.

Phase 0 of the auth consolidation: this module collapses the two historical copies of the
same history scan — the module-level ``scan_history_bearer`` and
``CopilotSession._capture_bearer_tokens`` — into one implementation, and centralizes the
sub-app path map and the JWT ``exp``/freshness helpers that were duplicated across the copilot
engine and the raw tool path.

sub-apps can share one host, so a single host-keyed token would let one sub-app's token
overwrite another's; selection is by request path instead (``by_app`` index).
"""

from __future__ import annotations

import time as _time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from dast.session import site_map, subapp_map


def subapp_for_path(path: str, site: str = "") -> Optional[str]:
    """Map a request path to its sub-app name, or None for a non-sub-app path.

    The prefix->app map is target-specific internal topology, so it is NOT hardcoded here — it is
    read from the operator's local ``~/.dast-ai/subapp_map.json`` (see ``dast/session/subapp_map``).
    With no local config the map is empty and every path returns None (host-level Bearer selection).

    When *site* (the host's product-group, from ``site_map``) is given, resolution is scoped to that
    site's sub-apps (+ site-less ones), so two products sharing a prefix do not collide. Empty *site*
    (default) matches all prefixes — unchanged behaviour for untagged configs / path-only callers."""
    p = (path or "").lower()
    for prefix, app in subapp_map.subapp_prefixes(site):
        if p.startswith(prefix):
            return app
    return None


# Generic path segments that are NOT a sub-app name (SPA shell, static, central session, API
# version markers), so a path-derived key is never minted for them.
_NON_SUBAPP_SEGMENTS = frozenset({
    "", "spa", "app", "static", "assets", "public", "_next", "cdn", "favicon.ico", "api",
})


def _derived_subapp(path: str) -> Optional[str]:
    """Best-effort sub-app key for a path with NO ``subapp_map`` entry, so the activation flow can
    label an unmapped sub-app for its learned-recipe key. Two shapes:

    - GraphQL (high-signal): the segment right before ``graphql`` (``/reports/graphql`` ->
      ``reports``).
    - REST: the first segment of a multi-segment API path (``/accounts/session`` ->
      ``accounts``), excluding shell/static/version segments.

    Deliberately NOT wired into ``subapp_for_path`` (that would change the global bearer-index /
    transport-capability keying contract); it is consulted ONLY by the activation path. Over-
    matching is harmless there — activation only navigates when a learned/known nav exists.
    Returns None when the path is not sub-app-shaped (shell/static/version/single-segment)."""
    import re as _re
    segs = [s for s in (path or "").lower().split("/") if s]
    if "graphql" in segs:
        i = segs.index("graphql")
        if i == 0:
            return None
        cand = segs[i - 1]
    elif len(segs) >= 2:
        # REST: a multi-segment path's first segment is the sub-app area (e.g. /<app>/<resource>).
        cand = segs[0]
    else:
        return None
    if cand in _NON_SUBAPP_SEGMENTS or _re.fullmatch(r"v\d+", cand):
        return None
    return cand


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


def _aud_allows_host(token: str, host: str) -> bool:
    """Whether a JWT's ``aud`` (audience) permits using it against *host*. True when there is no
    audience restriction (aud absent/empty) or when *host* matches an aud entry (exact, as a URL
    host, or apex overlap). Keeps an SSO/identity token from being handed to a service that would
    reject it. Never raises."""
    try:
        from dast.utils.jwt import decode_jwt_claims
        claims = decode_jwt_claims(token) or {}
    except Exception:
        return True  # can't decode -> don't block (same leniency as a non-JWT token)
    aud = claims.get("aud") if isinstance(claims, dict) else None
    if not aud:
        return True
    auds = aud if isinstance(aud, list) else [aud]
    hl = (host or "").lower()
    for a in auds:
        al = str(a).lower()
        if hl and (hl == al or hl in al or al in hl):
            return True
    return False


def _cross_host_bearer(store: Any, host: str, now: float,
                       exclude_source: Optional[str]) -> Optional[Dict[str, Any]]:
    """Cross-host FALLBACK: when no same-apex Bearer exists for *host*, borrow one from a host in
    the SAME learned service group (``store.service_graph``, grouped passively by shared iss /
    parent / cookie) whose token's ``aud`` allows *host*. Freshest-first; honors ``exclude_source``.
    Returns a host-level record tagged ``cross_host`` or None. Never raises. No service graph /
    no siblings -> None (today's behaviour)."""
    sg = getattr(store, "service_graph", None)
    if sg is None:
        return None
    try:
        siblings = {h.lower() for h in (sg.known_hosts_for(host) or [])}
    except Exception:
        siblings = set()
    if not siblings:
        return None
    try:
        entries = store.all_entries()
    except Exception:
        return None
    for entry in reversed(entries):  # freshest first
        try:
            entry_host = (_field(entry, "host") or "").lower()
            if entry_host not in siblings:
                continue
            if exclude_source is not None and _field(entry, "source") == exclude_source:
                continue
            auth_val = ""
            for key, value in (_field(entry, "request_headers") or {}).items():
                if key.lower() == "authorization":
                    auth_val = str(value)
                    break
            if not auth_val.startswith("Bearer "):
                continue
            token_val = auth_val[7:].strip()
            exp = decode_jwt_exp(token_val)
            if exp is not None and exp < now:
                continue
            if not _aud_allows_host(token_val, host):
                continue
            return {"token": token_val, "exp": exp,
                    "auth_endpoint": _field(entry, "path") or "",
                    "captured_at": now, "source_entry_id": _field(entry, "id") or "",
                    "matched_host": _field(entry, "host") or entry_host,
                    "cross_host": True}
        except Exception:
            continue
    return None


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
    site = site_map.site_for_host(host) or ""  # scope sub-app resolution to the host's product

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
            app = subapp_for_path(auth_endpoint, site)
            if app and app not in by_app:
                by_app[app] = dict(record)  # freshest per sub-app
        except Exception:
            continue
    if host_level is None:
        # No same-apex token — fall back to a service-group sibling's token whose aud allows host.
        host_level = _cross_host_bearer(store, host, now, exclude_source)
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
    site = site_map.site_for_host(str(record.get("matched_host", ""))) or ""
    app = subapp_for_path(path, site)
    by_app = record.get("by_app")
    if app and isinstance(by_app, dict) and app in by_app:
        return by_app[app]
    return record


def scan_history_csrf(store: Any, host: str, *,
                      exclude_source: Optional[str] = None) -> Optional[str]:
    """Freshest ``X-CSRF-Token`` request header seen on *host*'s registrable domain in proxy
    history (the SPA's own authenticated requests). For an SPA whose CSRF token is NOT mirrored
    into a cookie (e.g. Rails meta-tag CSRF), this is the only place to recover it so the tool can
    attach it to its own state-changing requests. Returns the token string or None. Never raises.

    ``exclude_source`` skips entries whose ``source`` matches (callers pass ``"copilot"`` so the
    tool never re-reads a token from its own prior failed attempts)."""
    if store is None or not host:
        return None
    try:
        entries = store.all_entries()
    except Exception:
        return None
    parts = host.lower().split(".")
    domain_suffix = ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()
    for entry in reversed(entries):  # freshest first
        try:
            entry_host = (_field(entry, "host") or host).lower()
            if domain_suffix not in entry_host:
                continue
            if exclude_source is not None and _field(entry, "source") == exclude_source:
                continue
            req_headers = _field(entry, "request_headers") or {}
            for key, value in req_headers.items():
                if key.lower() == "x-csrf-token" and str(value).strip():
                    return str(value).strip()
        except Exception:
            continue
    return None


def scan_history_bearer(store: Any, host: str, path: str, *,
                        exclude_source: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Freshest non-expired Bearer in proxy history for a (host, request path). One-call
    wrapper over collect_host_bearer + select_bearer. Returns a record
    ``{token, exp, auth_endpoint, ...}`` or None. Never raises."""
    rec = collect_host_bearer(store, host, exclude_source=exclude_source)
    return select_bearer(rec, path) if rec else None


@dataclass
class AttachResult:
    """What :func:`attach` did, for the caller's logging and loop watchdogs.

    ``stripped`` is the names of caller-pasted raw-secret headers removed; ``attached_bearer``
    is True when a Bearer was injected; ``overrode_session_header`` is True when a model-pasted
    session Cookie/CSRF was replaced with the active session's (the copilot increments its
    stuck-loop watchdog on this)."""
    stripped: List[str] = field(default_factory=list)
    attached_bearer: bool = False
    overrode_session_header: bool = False


def attach(headers: Dict[str, str], *, transport: str,
           cookies: Optional[Dict[str, str]] = None,
           bearer_rec: Optional[Dict[str, Any]] = None,
           trusted_marker: bool = False,
           drop_all_authorization: bool = False,
           csrf_token: Optional[str] = None,
           now: Optional[float] = None) -> AttachResult:
    """Attach the active session's cookie + CSRF + Bearer onto outgoing request *headers*,
    mutating them in place. ONE mechanism for all three call paths (the copilot engine,
    ``send_request``, ``browser_fetch``); the caller resolves the cookie/Bearer SOURCE and
    passes the transport plus policy flags, so the session-specific sourcing (scoped jar,
    handoff overlay, per-sub-app Bearer) stays at the call site and this helper stays pure.

    - ``transport="api"``: set ``Cookie`` from *cookies* (the jar/named session is the source
      of truth) and the CSRF/XHR headers a cookie-authed SPA needs.
    - ``transport="browser"``: the browser context owns the cookie jar, so NEVER set Cookie
      and drop any caller ``Cookie``/``Authorization``; still inject CSRF + X-Requested-With
      and ride the captured Bearer. (Pass CSRF-cookie values already URL-decoded — this helper
      does not unquote.)
    - ``trusted_marker``: the model's headers already carry our ``x-dast-cookies-injected=1``
      (we set them on a prior pass), so leave its Cookie/CSRF in place.
    - ``drop_all_authorization``: drop ANY remaining caller ``Authorization``, not only
      raw-secret ones (the ``send_request`` schema contract — auth is always auto-injected).

    A caller-pasted raw secret (JWT/bearer) in ``Authorization``/``Cookie`` is always stripped
    first; a Bearer is attached only when no ``Authorization`` is already present and the
    record is non-expired. Never raises."""
    from dast.proxy.auth_headers import (
        build_cookie_header,
        inject_csrf,
        strip_pasted_secret_headers,
    )

    result = AttachResult()
    now = now if now is not None else _time.time()

    # Always refuse a hand-pasted raw secret (Cookie/Authorization) — never forward it.
    result.stripped = strip_pasted_secret_headers(headers)

    if drop_all_authorization:
        for key in [k for k in list(headers) if k.lower() == "authorization"]:
            del headers[key]
            if key not in result.stripped:
                result.stripped.append(key)

    cookie_map = {str(k): str(v) for k, v in (cookies or {}).items() if k}

    if transport == "browser":
        # The browser context owns cookies/auth; never set them here.
        for key in [k for k in list(headers) if k.lower() in ("cookie", "authorization")]:
            del headers[key]
        inject_csrf(headers, cookie_map, refresh=False)
        # The old browser path set X-Requested-With unconditionally (even with no cookies).
        if "x-requested-with" not in {k.lower() for k in headers}:
            headers["X-Requested-With"] = "XMLHttpRequest"
    else:  # "api"
        if cookie_map and not trusted_marker:
            # The model must not be able to pin a stale/foreign session by pasting its own
            # Cookie/CSRF: strip them and re-seed from the active session. (A model Cookie
            # carrying our x-dast-cookies-injected=1 marker is ours — kept via trusted_marker.)
            removed = [k for k in list(headers)
                       if k.lower() in ("cookie", "x-csrf-token", "x-xsrf-token")]
            for key in removed:
                del headers[key]
            if removed:
                result.overrode_session_header = True
            headers["Cookie"] = build_cookie_header(cookie_map)
            headers["x-dast-cookies-injected"] = "1"
        if cookie_map:
            # refresh=True so a stale model CSRF (e.g. kept under the trusted marker) is
            # corrected to the active session's value.
            inject_csrf(headers, cookie_map, refresh=True)

    # CSRF fallback: a cookie-authed SPA whose CSRF token is NOT in a cookie (e.g. Rails
    # meta-tag CSRF) yields nothing from inject_csrf, so a state-changing POST 302/403s. When the
    # caller supplies a token captured from the SPA's own observed requests, inject it here (only
    # if the cookie path didn't already set one). This is what makes authenticated POSTs work.
    if csrf_token and not any(k.lower() in ("x-csrf-token", "x-xsrf-token") for k in headers):
        headers["X-CSRF-Token"] = csrf_token
        if "x-requested-with" not in {k.lower() for k in headers}:
            headers["X-Requested-With"] = "XMLHttpRequest"

    # Bearer: only when the caller left no Authorization and the record is still fresh.
    if (bearer_rec and rec_is_fresh(bearer_rec, now)
            and not any(k.lower() == "authorization" for k in headers)):
        headers["Authorization"] = f"Bearer {bearer_rec['token']}"
        result.attached_bearer = True

    return result

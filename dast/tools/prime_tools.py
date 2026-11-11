"""prime_session tool — auto-mint a sub-app's session COOKIE through the proxy.

Some sub-apps gate on a session cookie (set by an authenticated GET to a priming endpoint),
not only on the per-app Bearer: a request carrying the right Bearer but no session cookie still
comes back ``not_authorized``. The copilot cannot "just know" to visit the priming endpoint, so
authenticated confirmations on such a sub-app never close.

``prime_session`` closes that gap deterministically: given a host + sub-app that declares a
``prime`` descriptor in the local sub-app map (``{endpoint, method, cookie, referer}`` — see
``dast/session/subapp_map``), it issues the priming GET THROUGH the proxy with the app Bearer. The
proxy auto-ingests the response ``Set-Cookie`` into the shared jar (``_ingest_cookies``), and we also
seed it onto the engine session's cookie overlay so BOTH the ``send_request`` path (reads the shared
jar) and the engine's own ``_apply_session_auth`` path (``_session_cookies`` wins) carry it on the
retry. Read-only (a single GET); never returns a secret; never raises.

This is the "prime" capability the Coordinator invokes (directly or via the session-prime recovery)
so a failed authenticated request can be re-tried after the cookie is minted.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from dast.session import subapp_map
from dast.session.auth_provider import scan_history_bearer
from dast.tools.app_knowledge_tools import _cookie_header, _host_of
from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def _jar_cookie_value(ctx: ToolContext, host: str, cookie: str) -> str:
    """Current value of *cookie* for *host* from the shared jar or the engine overlay, else ''."""
    sess = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
    overlay = getattr(sess, "_session_cookies", None)
    if isinstance(overlay, dict) and overlay.get(cookie):
        return str(overlay[cookie])
    store = getattr(ctx, "store", None)
    if store is not None:
        try:
            for c in store.get_cookies_for_host(host) or []:
                if c.get("name") == cookie and c.get("value"):
                    return str(c["value"])
        except Exception:
            pass
    return ""


def _app_bearer(ctx: ToolContext, host: str, app: str, probe_path: str) -> str:
    """The app's Bearer: the per-sub-app cached token first, else one captured on the app's probe
    path in proxy history (the app's own request). Empty string when none is available."""
    sess = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
    cache = getattr(sess, "_bearer_tokens", None)
    if isinstance(cache, dict):
        rec = cache.get(host)
        if isinstance(rec, dict):
            by_app = rec.get("by_app")
            if isinstance(by_app, dict):
                entry = by_app.get(app)
                if isinstance(entry, dict) and entry.get("token"):
                    return str(entry["token"])
    store = getattr(ctx, "store", None)
    if store is not None and probe_path:
        try:
            cap = scan_history_bearer(store, host, probe_path, exclude_source="copilot")
        except Exception as exc:
            logger.debug("prime_session bearer history lookup failed",
                         host=host, error=str(exc)[:160])
            cap = None
        if cap and cap.get("token"):
            return str(cap["token"])
    return ""


def _referer_url(referer: str, host: str) -> Optional[str]:
    """Resolve the descriptor's optional referer to an absolute URL (path -> https://host/path)."""
    r = (referer or "").strip()
    if not r:
        return None
    if "://" in r:
        return r
    return f"https://{host}{r if r.startswith('/') else '/' + r}"


async def _prime_session(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    host = _host_of(str(args.get("host", "")))
    app = str(args.get("app", "")).strip().lower()
    if not host:
        return {"ok": False, "error": "host is required"}
    if not app:
        return {"ok": False, "error": "app is required"}

    prime = subapp_map.prime_for_app(app)
    if not prime:
        primeable = sorted({e["app"] for e in subapp_map._load_entries() if e.get("prime")})
        return {"ok": False, "error": f"app '{app}' has no session-prime descriptor in the local "
                f"sub-app map; primeable apps: {primeable}", "host": host}

    cookie = prime["cookie"]
    endpoint = prime["endpoint"]
    method = prime.get("method", "GET") or "GET"
    url = f"https://{host}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "prime endpoint is out of scope", "host": host, "url": url}

    # Already primed? No-op (idempotent — cheap to call before every authenticated request).
    existing = _jar_cookie_value(ctx, host, cookie)
    if existing:
        return {"ok": True, "app": app, "host": host, "cookie": cookie,
                "primed": False, "verified": True, "note": "session cookie already present"}

    probe_path = subapp_map.app_map().get(app, {}).get("probe", "")
    bearer = _app_bearer(ctx, host, app, probe_path)
    if not bearer:
        return {"ok": False, "app": app, "host": host, "cookie": cookie, "primed": False,
                "verified": False,
                "error": "no app Bearer available to prime with; call get_app_token (or browse the "
                         "sub-app area so the app issues its token) first, then retry"}

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Cookie": _cookie_header(ctx, host),
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
        "x-dast-source": "copilot",
    }
    ref = _referer_url(prime.get("referer", ""), host)
    if ref:
        headers["Referer"] = ref

    status: Optional[int] = None
    try:
        async with httpx.AsyncClient(proxy=ctx.proxy_url, verify=False,
                                     follow_redirects=True, timeout=15) as client:
            resp = await client.request(method, url, headers=headers)
            status = resp.status_code
    except Exception as exc:
        return {"ok": False, "app": app, "host": host, "cookie": cookie, "primed": False,
                "verified": False, "error": f"prime request failed: {str(exc)[:160]}"}

    # The proxy auto-ingested any Set-Cookie into the shared jar. Read it back and ALSO seed the
    # engine's cookie overlay so the scoped _apply_session_auth path (where _session_cookies wins)
    # carries it on the retry, not only the send_request shared-jar path.
    value = ""
    store = getattr(ctx, "store", None)
    if store is not None:
        try:
            for c in store.get_cookies_for_host(host) or []:
                if c.get("name") == cookie and c.get("value"):
                    value = str(c["value"])
                    break
        except Exception:
            pass
    if value:
        sess = getattr(ctx, "_session", None) or getattr(ctx, "session", None)
        overlay = getattr(sess, "_session_cookies", None)
        if isinstance(overlay, dict):
            overlay[cookie] = value

    verified = bool(value)
    return {
        "ok": verified, "app": app, "host": host, "cookie": cookie,
        "primed": verified, "verified": verified, "prime_status": status,
        "note": ("session cookie minted and seeded; retry the authenticated request" if verified
                 else f"prime endpoint returned {status} but no {cookie} cookie was set — the Bearer "
                      "may be stale (refresh it) or this sub-app may not use a primed session cookie"),
    }


register(Tool(
    name="prime_session",
    input_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Target host (e.g. app.example.com)."},
            "app": {"type": "string",
                    "description": "Which sub-app's session cookie to mint (an app that declares a "
                                   "'prime' descriptor in the local sub-app map; the error lists the "
                                   "primeable names)."},
        },
        "required": ["host", "app"],
    },
    handler=_prime_session,
    tags=["auth"],
    description="Mint a sub-app's SESSION COOKIE when the per-app Bearer alone is not enough and the "
                "sub-app returns not_authorized/403. Does one authenticated GET to the app's priming "
                "endpoint THROUGH the proxy (riding the app Bearer); the proxy ingests the Set-Cookie "
                "and it is seeded onto the session, so the next authenticated request to that sub-app "
                "carries it. Idempotent (no-op if already present); read-only; never returns a secret. "
                "Use BEFORE (or on a failed) authenticated request to a sub-app that uses a session "
                "cookie (configured via the local sub-app map's 'prime' descriptor).",
))

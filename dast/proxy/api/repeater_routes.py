"""
Repeater routes: /api/repeater/send.
"""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Request

from dast.proxy.api.http_utils import strip_recomputed_headers
from dast.proxy.api.context import DashboardContext
from dast.proxy.auth_headers import apply_cookies
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()

    @router.post("/api/repeater/send")
    async def repeater_send(request: Request):
        import time as _time
        import httpx as _httpx

        data = await request.json()
        method  = str(data.get("method", "GET")).upper()
        url     = str(data.get("url", ""))
        headers = dict(data.get("headers") or {})
        body    = data.get("body") or None
        follow_redirects = bool(data.get("follow_redirects", False))
        session_name = str(data.get("session_name", "")).strip()

        headers = strip_recomputed_headers(headers)

        # Opt-in: when a named session is given, inject that session's cookies
        # (host-scoped) plus the CSRF/XHR headers a cookie-authed SPA needs. Not
        # applied without session_name so a hand-pasted request (with its own
        # Cookie header) is sent verbatim.
        if session_name:
            store = getattr(ctx, "store", None)
            host = urlparse(url).hostname or ""
            if store is not None and host:
                try:
                    cookies = store.get_named_session_cookies_for_host(session_name, host) or []
                    if cookies:
                        apply_cookies(headers, cookies, refresh=True)
                except Exception as exc:
                    logger.warning("repeater: session cookie injection failed",
                                   session=session_name, host=host, error=str(exc))

        t0 = _time.monotonic()
        try:
            async with _httpx.AsyncClient(
                follow_redirects=follow_redirects,
                timeout=_httpx.Timeout(30.0),
                verify=False,
            ) as client:
                resp = await client.request(method, url, headers=headers,
                                            content=body.encode() if body else None)
            elapsed = int((_time.monotonic() - t0) * 1000)
            try:
                body_text = resp.text[:500_000]
            except Exception:
                body_text = ""
            # Expose the redirect chain so the operator can see each hop that was
            # followed (final_url differs from the requested url when redirected).
            redirect_chain = [str(r.url) for r in resp.history]
            return {
                "status":     resp.status_code,
                "elapsed_ms": elapsed,
                "headers":    dict(resp.headers),
                "body":       body_text,
                "final_url":  str(resp.url),
                "redirect_chain": redirect_chain,
            }
        except Exception as e:
            return {"status": 0, "elapsed_ms": 0, "headers": {}, "body": str(e)}

    return router

"""
Repeater routes: /api/repeater/send.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from dast.proxy.api.context import DashboardContext


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

        for h in ("host", "content-length", "transfer-encoding", "connection", "accept-encoding"):
            headers.pop(h, None)
            headers.pop(h.title(), None)

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
                body_text = resp.text[:50000]
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

"""Adaptive-login route: POST /api/login/adaptive.

Exposes the deterministic-first, LLM-on-failure login cascade
(``dast.browser.login_cascade.adaptive_login``) over HTTP, mirroring the
``browser_login_adaptive`` MCP/agent tool so the capability is reachable from the
dashboard and external automation alike.

A fresh headless AgentBrowser is created per request (routed through the proxy,
seeded from the cookie jar), driven to log in, and closed. The target URL is
hard scope-gated before any browser work. The LLM fallback spends tokens only when
the deterministic engine cannot authenticate.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Upper bound on a single adaptive-login attempt (deterministic engine + any LLM
# steps). Keeps a stuck page/model from pinning the request forever.
_ADAPTIVE_LOGIN_TIMEOUT_SECONDS = 180


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    settings = ctx.settings

    @router.post("/api/login/adaptive")
    async def adaptive_login_route(body: dict):
        url = (body.get("url") or "").strip()
        email = (body.get("email") or body.get("username") or "").strip()
        password = (body.get("password") or "").strip()
        if not url or not email or not password:
            return JSONResponse(
                {"error": "url, email and password are required"}, status_code=400)
        # HARD SAFETY GATE: never drive a browser login against an out-of-scope host.
        if settings is None or not settings.is_in_scope(url):
            return JSONResponse(
                {"error": "url is out of scope — add it to the Target scope first"},
                status_code=400)
        success_url_suffix = (body.get("success_url_suffix") or "").strip() or None

        try:
            from dast.browser.agent_browser import AgentBrowser
            from dast.browser.login_cascade import adaptive_login
        except Exception as exc:
            return JSONResponse(
                {"error": f"browser support unavailable: {str(exc)[:160]}"},
                status_code=503)

        browser = AgentBrowser(proxy_port=ctx.proxy_port, store=ctx.store, headless=True)
        try:
            result = await asyncio.wait_for(
                adaptive_login(browser, url, email, password,
                               success_url_suffix=success_url_suffix,
                               in_scope=settings.is_in_scope),
                timeout=_ADAPTIVE_LOGIN_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return JSONResponse({"error": "adaptive login timed out"}, status_code=504)
        except Exception as exc:
            logger.warning("adaptive-login route failed", error=str(exc)[:200])
            return JSONResponse({"error": f"login failed: {str(exc)[:160]}"},
                                status_code=500)
        finally:
            try:
                await browser.close()
            except Exception:
                pass

        return result.to_dict()

    return router

"""
Browser and crawler routes: /api/browse/*, /api/crawl/*, /api/plugins/*.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    store = ctx.store
    crawl_queue = ctx.crawl_queue
    browse_queue = ctx.browse_queue
    discovery_queue = ctx.discovery_queue
    plugin_manager = ctx.plugin_manager
    settings = ctx.settings

    @router.post("/api/crawl")
    async def start_crawl(body: dict):
        if not crawl_queue:
            return JSONResponse({"error": "crawl not available"}, status_code=503)
        url = body.get("url", "").strip()
        if not url:
            return JSONResponse({"error": "url required"}, status_code=400)

        async def log_cb(msg: str) -> None:
            await ctx.broadcast_crawl_log(msg)

        await crawl_queue.put({
            "url": url,
            "headless": body.get("headless", True),
            "max_clicks": body.get("max_clicks", 200),
            "extra_seeds": body.get("extra_seeds"),
            "log_cb": log_cb,
        })
        return {"ok": True}

    @router.post("/api/crawl/stop")
    async def stop_crawl():
        if crawl_queue:
            await crawl_queue.put({"action": "stop"})
        return {"ok": True}

    @router.post("/api/discovery")
    async def start_discovery(body: dict):
        """Start content discovery (forced browsing) against an in-scope URL."""
        if not discovery_queue:
            return JSONResponse({"error": "discovery not available"}, status_code=503)
        url = (body.get("url") or "").strip()
        if not url:
            return JSONResponse({"error": "url required"}, status_code=400)
        # HARD SAFETY GATE: never run discovery against an out-of-scope host.
        if settings is not None and not settings.is_in_scope(url):
            return JSONResponse(
                {"error": "url is out of scope — add it to the Target scope first"},
                status_code=400,
            )

        async def log_cb(msg: str) -> None:
            await ctx.broadcast_crawl_log(msg)

        await discovery_queue.put({
            "url": url,
            "headers": body.get("headers") or {},
            "dirs": bool(body.get("dirs", True)),
            "files": bool(body.get("files", True)),
            "graphql": bool(body.get("graphql", True)),
            "log_cb": log_cb,
        })
        return {"ok": True}

    @router.post("/api/discovery/stop")
    async def stop_discovery():
        if discovery_queue:
            await discovery_queue.put({"action": "stop"})
        return {"ok": True}

    # NOTE: hidden-parameter mining is no longer a manual UI action. It now runs
    # automatically as part of a scan: deterministically on the AI-off scan path
    # (see ProxyRunner._mine_params_for_entry) and, with AI on, when the LLM
    # planner decides an endpoint warrants it (Coordinator._run_param_mining_pass).

    @router.get("/api/crawl/cookie-status")
    async def crawl_cookie_status():
        # Mirror the crawler's own cookie source (shared jar + named sessions) so
        # the UI's "log in first" nudge matches what the crawl will actually use.
        cookies = store.get_crawl_cookies()
        return {"cookie_count": len(cookies)}

    @router.post("/api/sessions/save")
    async def save_named_session(body: dict):
        """Save current proxy cookie jar as a named session (legacy flow)."""
        name = (body.get("name") or "").strip()
        role = (body.get("role") or "user").strip()
        if not name:
            return JSONResponse({"error": "name required"}, status_code=400)
        session = store.save_named_session(name, role)
        return {
            "ok": True,
            "name": session.name,
            "role": session.role,
            "cookie_count": len(session.cookies),
            "auth_header_count": len(session.auth_headers),
        }

    @router.post("/api/sessions/browser")
    async def open_named_browser(body: dict):
        """Open an isolated named browser session for multi-user testing."""
        if not browse_queue:
            return JSONResponse({"error": "browse not available"}, status_code=503)
        name = (body.get("name") or "").strip()
        role = (body.get("role") or "user").strip()
        if not name:
            return JSONResponse({"error": "name required"}, status_code=400)
        result: dict = {}
        done = asyncio.Event()

        def result_cb(ok: bool, error: str, session_id: str) -> None:
            result.update({"ok": ok, "error": error, "session_id": session_id})
            done.set()

        await browse_queue.put({
            "action": "start_named",
            "name": name,
            "role": role,
            "url": body.get("url"),
            "result_cb": result_cb,
        })
        try:
            await asyncio.wait_for(done.wait(), timeout=15)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "browser failed to open"}, status_code=500)
        if not result.get("ok"):
            return JSONResponse({"error": result.get("error", "unknown")}, status_code=400)
        return {"ok": True, "session_id": result["session_id"], "name": name}

    @router.post("/api/sessions/browser/{name}/save")
    async def save_named_browser_session(name: str, body: dict):
        """Capture cookies from the named browser context and persist as a named session."""
        if not browse_queue:
            return JSONResponse({"error": "browse not available"}, status_code=503)
        role = (body.get("role") or "user").strip()
        result: dict = {}
        done = asyncio.Event()

        def result_cb(ok: bool, error: str, cookie_count: int) -> None:
            result.update({"ok": ok, "error": error, "cookie_count": cookie_count})
            done.set()

        await browse_queue.put({
            "action": "save_named",
            "name": name,
            "role": role,
            "result_cb": result_cb,
        })
        try:
            await asyncio.wait_for(done.wait(), timeout=10)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "timeout saving session"}, status_code=500)
        if not result.get("ok"):
            return JSONResponse({"error": result.get("error", "unknown")}, status_code=400)
        return {"ok": True, "name": name, "cookie_count": result["cookie_count"]}

    @router.post("/api/sessions/browser/{name}/stop")
    async def stop_named_browser_session(name: str):
        """Close the named browser window (does not delete the saved session)."""
        if not browse_queue:
            return JSONResponse({"error": "browse not available"}, status_code=503)
        done = asyncio.Event()
        await browse_queue.put({"action": "stop_named", "name": name,
                                "result_cb": lambda *_: done.set()})
        await asyncio.wait_for(done.wait(), timeout=10)
        return {"ok": True}

    @router.get("/api/sessions/browser")
    async def list_named_browsers():
        """List currently open named browser sessions."""
        if not browse_queue:
            return []
        result: dict = {}
        done = asyncio.Event()

        def result_cb(r: list) -> None:
            result["data"] = r
            done.set()

        await browse_queue.put({"action": "list_named", "result_cb": result_cb})
        try:
            await asyncio.wait_for(done.wait(), timeout=5)
        except asyncio.TimeoutError:
            return []
        return result.get("data", [])

    @router.post("/api/sessions/credentials")
    async def login_with_credentials(body: dict):
        """Headless login: fill credentials, capture cookies, save as named session."""
        if not browse_queue:
            return JSONResponse({"error": "browse not available"}, status_code=503)
        name = (body.get("name") or "").strip()
        role = (body.get("role") or "user").strip()
        login_url = (body.get("login_url") or "").strip()
        username = (body.get("username") or "").strip()
        password = (body.get("password") or "").strip()
        if not name:
            return JSONResponse({"error": "name required"}, status_code=400)
        if not login_url or not username or not password:
            return JSONResponse({"error": "login_url, username and password required"}, status_code=400)

        result: dict = {}
        done = asyncio.Event()

        def result_cb(ok: bool, error: str, cookie_count: int) -> None:
            result.update({"ok": ok, "error": error, "cookie_count": cookie_count})
            done.set()

        await browse_queue.put({
            "action": "credentials",
            "name": name,
            "role": role,
            "login_url": login_url,
            "username": username,
            "password": password,
            "username_selector": body.get("username_selector", ""),
            "password_selector": body.get("password_selector", ""),
            "submit_selector": body.get("submit_selector", ""),
            "result_cb": result_cb,
        })
        try:
            await asyncio.wait_for(done.wait(), timeout=45)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "login timed out"}, status_code=500)
        if not result.get("ok"):
            return JSONResponse({"error": result.get("error", "login failed")}, status_code=400)
        return {"ok": True, "name": name, "cookie_count": result["cookie_count"]}

    @router.get("/api/named-sessions")
    async def list_named_sessions():
        return [
            {
                "name": s.name,
                "role": s.role,
                "cookie_count": len(s.cookies) if s.cookies else 0,
                "created_at": s.created_at,
            }
            for s in store.get_named_sessions()
        ]

    @router.delete("/api/named-sessions/{name}")
    async def delete_named_session(name: str):
        ok = store.delete_named_session(name)
        if not ok:
            return JSONResponse({"error": "session not found"}, status_code=404)
        return {"ok": True}

    @router.post("/api/browse/start")
    async def browse_start(body: dict):
        if not browse_queue:
            return JSONResponse({"error": "browse not available"}, status_code=503)
        result: dict = {}
        done = asyncio.Event()

        def result_cb(session_id: str) -> None:
            result["session_id"] = session_id
            done.set()

        await browse_queue.put({"action": "start", "url": body.get("url"), "result_cb": result_cb})
        try:
            await asyncio.wait_for(done.wait(), timeout=15)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "browser failed to open"}, status_code=500)
        return result

    @router.post("/api/browse/stop")
    async def browse_stop():
        if browse_queue:
            await browse_queue.put({"action": "stop"})
        return {"ok": True}

    @router.get("/api/browse/status")
    async def browse_status():
        return {
            "active": store.active_browse_session_id is not None,
            "session_id": store.active_browse_session_id,
        }

    @router.get("/api/plugins")
    async def get_plugins():
        if plugin_manager is None:
            return []
        return plugin_manager.list_plugins()

    @router.patch("/api/plugins/{name}")
    async def patch_plugin(name: str, body: dict):
        if plugin_manager is None:
            return JSONResponse({"error": "plugin manager not available"}, status_code=503)
        ok = plugin_manager.set_enabled(name, bool(body.get("enabled", True)))
        if not ok:
            return JSONResponse({"error": "plugin not found"}, status_code=404)
        return {"ok": True}

    return router

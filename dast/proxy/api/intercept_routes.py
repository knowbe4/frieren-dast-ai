"""
Intercept mode API routes — request/response pause/edit/forward.

GET    /api/intercept/status                {"enabled": bool, "intercept_response": bool, "queue_size": int}
POST   /api/intercept/toggle               body: {} or {"enabled": bool}
POST   /api/intercept/toggle-response      body: {} or {"enabled": bool}  — toggle response intercept
GET    /api/intercept/queue                list of pending requests (and responses awaiting forward)
POST   /api/intercept/{id}/forward         body: {} or {method,url,headers,body}
POST   /api/intercept/{id}/forward-response body: {} or {status,headers,body}
POST   /api/intercept/{id}/drop            drop request or response
POST   /api/intercept/forward-all          forward all pending without modification
"""

from __future__ import annotations

import json

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    store = ctx.intercept_store

    @router.get("/api/intercept/status")
    async def get_status():
        if store is None:
            return {"enabled": False, "intercept_response": False, "queue_size": 0}
        return {
            "enabled": store.enabled,
            "intercept_response": store.intercept_response,
            "queue_size": store.queue_size,
        }

    @router.post("/api/intercept/toggle")
    async def toggle(body: dict = {}):
        if store is None:
            return JSONResponse({"error": "intercept not available"}, status_code=503)
        if "enabled" in body:
            new_state = store.toggle(bool(body["enabled"]))
        else:
            new_state = store.toggle()
        await _broadcast_status(ctx)
        return {"enabled": new_state}

    @router.post("/api/intercept/toggle-response")
    async def toggle_response(body: dict = {}):
        if store is None:
            return JSONResponse({"error": "intercept not available"}, status_code=503)
        if "enabled" in body:
            new_state = bool(body["enabled"])
        else:
            new_state = not store.intercept_response
        store.set_intercept_response(new_state)
        await _broadcast_status(ctx)
        return {"intercept_response": new_state}

    @router.get("/api/intercept/queue")
    async def get_queue():
        if store is None:
            return []
        return store.get_queue()

    @router.post("/api/intercept/{req_id}/forward")
    async def forward(req_id: str, body: dict = {}):
        if store is None:
            return JSONResponse({"error": "intercept not available"}, status_code=503)
        modified = body if body else None
        if not store.forward(req_id, modified):
            return JSONResponse({"error": "request not found"}, status_code=404)
        await _broadcast_queue(ctx)
        return {"ok": True}

    @router.post("/api/intercept/{req_id}/drop")
    async def drop(req_id: str):
        if store is None:
            return JSONResponse({"error": "intercept not available"}, status_code=503)
        if not store.drop(req_id):
            return JSONResponse({"error": "request not found"}, status_code=404)
        await _broadcast_queue(ctx)
        return {"ok": True}

    @router.post("/api/intercept/{req_id}/forward-response")
    async def forward_response(req_id: str, body: dict = {}):
        if store is None:
            return JSONResponse({"error": "intercept not available"}, status_code=503)
        modified = body if body else None
        if not store.forward_response(req_id, modified):
            return JSONResponse({"error": "response not found"}, status_code=404)
        await _broadcast_queue(ctx)
        return {"ok": True}

    @router.post("/api/intercept/forward-all")
    async def forward_all():
        if store is None:
            return JSONResponse({"error": "intercept not available"}, status_code=503)
        count = store.forward_all()
        await _broadcast_queue(ctx)
        return {"ok": True, "forwarded": count}

    return router


async def _broadcast_status(ctx: DashboardContext) -> None:
    if ctx.intercept_store is None:
        return
    msg = json.dumps({
        "type": "intercept_status",
        "enabled": ctx.intercept_store.enabled,
        "intercept_response": ctx.intercept_store.intercept_response,
        "queue_size": ctx.intercept_store.queue_size,
    })
    dead = set()
    for ws in list(ctx.ws_clients):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    ctx.ws_clients.difference_update(dead)


async def _broadcast_queue(ctx: DashboardContext) -> None:
    if ctx.intercept_store is None:
        return
    msg = json.dumps({
        "type": "intercept_queue",
        "queue": ctx.intercept_store.get_queue(),
        "queue_size": ctx.intercept_store.queue_size,
    })
    dead = set()
    for ws in list(ctx.ws_clients):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    ctx.ws_clients.difference_update(dead)

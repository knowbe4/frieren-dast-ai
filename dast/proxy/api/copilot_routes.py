"""
Exploration Copilot routes — the conversational exploration surface.

Where ``agent_triage_routes.py`` drives an autonomous loop to a stored verdict,
this drives a *dialogue* (``dast/ai/copilot/session.py``): the operator sends a
message, the copilot runs tools and replies, and the thread continues. Mid-turn it
pauses on the same two human walls as the triage agent — an out-of-scope host
(approve) and an auth wall/captcha (browser handoff) — reusing the identical
pause/resume plumbing.

Session state and the turn runner live in ``CopilotService`` (``ctx.copilot``) so
the scanner can escalate a WAF-disabled attack type into a live conversation
in-process. These routes are a thin HTTP adapter over that service.

  POST /api/copilot/message              — send an operator message; returns session_id
  GET  /api/copilot/sessions             — list recent sessions
  GET  /api/copilot/session/{sid}        — full transcript + messages + pause + reply
  POST /api/copilot/resume/{sid}         — answer a pause (approve/auth)
  POST /api/copilot/open-browser/{sid}   — open a browser for the auth pause
  POST /api/copilot/cancel/{sid}         — cancel the running turn
  WS   /ws/copilot                       — stream step/observation/pause/reply events
"""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_MESSAGE_CHARS = 20_000


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    service = ctx.copilot

    @router.post("/api/copilot/message")
    async def message(body: dict):
        text = (body.get("message") or "").strip()
        if not text:
            return JSONResponse({"error": "message required"}, status_code=400)
        if len(text) > _MAX_MESSAGE_CHARS:
            return JSONResponse(
                {"error": f"message too large (max {_MAX_MESSAGE_CHARS} chars)"},
                status_code=400,
            )

        sid = (body.get("session_id") or "").strip()
        if sid and not service.has(sid):
            return JSONResponse({"error": "session not found"}, status_code=404)
        if not sid:
            sid = service.new_session()

        session = service.get(sid)
        running = session.get("_task")
        if running and not running.done():
            return JSONResponse({"error": "a turn is already in progress"}, status_code=409)

        service.start_turn(sid, text)
        return {"session_id": sid, "status": "running"}

    @router.get("/api/copilot/sessions")
    async def list_sessions():
        return service.list_summaries()

    @router.get("/api/copilot/session/{sid}")
    async def get_session(sid: str):
        if not service.has(sid):
            return JSONResponse({"error": "session not found"}, status_code=404)
        return service.session_dict(sid)

    @router.post("/api/copilot/resume/{sid}")
    async def resume(sid: str, body: dict):
        """Answer the current pause. Body: {kind, value}.

        approve -> value.decision in allow_once|always_host|deny
        auth    -> value.cookies {name: value}
        """
        session = service.get(sid)
        if session is None:
            return JSONResponse({"error": "session not found"}, status_code=404)
        pause = session.get("pause")
        if not pause:
            return JSONResponse({"error": "session is not paused"}, status_code=400)

        kind = str(body.get("kind", pause.get("kind", ""))).strip()
        value = body.get("value") or {}
        if not isinstance(value, dict):
            return JSONResponse({"error": "value must be an object"}, status_code=400)

        if kind == "approve":
            decision = str(value.get("decision", "deny")).strip().lower()
            if decision not in ("allow_once", "always_host", "deny"):
                return JSONResponse(
                    {"error": "decision must be allow_once|always_host|deny"},
                    status_code=400,
                )
            session["_pause_result"] = {"decision": decision}
        elif kind == "auth":
            from dast.hackerone.validator import _sanitise_cookies
            raw = value.get("cookies") or {}
            if not isinstance(raw, dict):
                return JSONResponse({"error": "cookies must be an object"}, status_code=400)
            session["_pause_result"] = {"cookies": _sanitise_cookies(raw)}
        else:
            return JSONResponse({"error": "kind must be approve|auth"}, status_code=400)

        event: asyncio.Event = session.get("_pause_event")
        if event:
            event.set()
        return {"ok": True}

    @router.post("/api/copilot/open-browser/{sid}")
    async def open_browser(sid: str):
        """Open a browser window so the operator can authenticate during an auth pause."""
        session = service.get(sid)
        if session is None:
            return JSONResponse({"error": "session not found"}, status_code=404)
        pause = session.get("pause") or {}
        if pause.get("kind") != "auth":
            return JSONResponse({"error": "session is not in an auth pause"}, status_code=400)

        target_url = (pause.get("payload") or {}).get("url", "")
        if not ctx.browse_queue:
            return JSONResponse({"error": "browse not available"}, status_code=503)
        from dast.hackerone.validator import _is_safe_url
        if not _is_safe_url(target_url):
            return JSONResponse({"error": "No valid public URL to open"}, status_code=400)

        result: dict = {}
        done = asyncio.Event()

        def result_cb(session_id: str) -> None:
            result["session_id"] = session_id
            done.set()

        await ctx.browse_queue.put({"action": "start", "url": target_url, "result_cb": result_cb})
        try:
            await asyncio.wait_for(done.wait(), timeout=15)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "browser failed to open"}, status_code=500)
        return {"ok": True, "session_id": result.get("session_id"), "target_url": target_url}

    @router.post("/api/copilot/cancel/{sid}")
    async def cancel(sid: str):
        session = service.get(sid)
        if session is None:
            return JSONResponse({"error": "session not found"}, status_code=404)
        task: Optional[asyncio.Task] = session.get("_task")
        if task and not task.done():
            task.cancel()
        session["status"] = "idle"
        return {"ok": True}

    @router.websocket("/ws/copilot")
    async def copilot_ws(ws: WebSocket):
        await ws.accept()
        ctx.copilot_ws_clients.add(ws)
        # Re-push in-flight pauses so a late-connecting UI still sees them.
        for sid in service.list_summaries():
            session = service.get(sid["session_id"])
            pause = session.get("pause") if session else None
            if pause:
                try:
                    await ws.send_json({"type": "pause", "session_id": sid["session_id"], **pause})
                except Exception:
                    pass
        try:
            while True:
                await ws.receive_text()
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            ctx.copilot_ws_clients.discard(ws)

    return router

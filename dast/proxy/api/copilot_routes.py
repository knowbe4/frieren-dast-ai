"""
Exploration Copilot routes — the conversational exploration surface.

Where ``agent_triage_routes.py`` drives an autonomous loop to a stored verdict,
this drives a *dialogue* (``dast/ai/copilot/session.py``): the operator sends a
message, the copilot runs tools and replies, and the thread continues. Mid-turn it
pauses on the same two human walls as the triage agent — an out-of-scope host
(approve) and an auth wall/captcha (browser handoff) — reusing the identical
pause/resume plumbing.

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
import time
import uuid
from typing import Dict, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from dast.proxy.api.agent_triage_routes import AgentToolContext
from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_SESSIONS = 50
_MAX_MESSAGE_CHARS = 20_000

# Human-in-the-loop pause budgets, matching the triage surface: approve bounds a
# quick decision; auth allows time to open a browser and log in.
_APPROVE_TIMEOUT_SECONDS = 120.0
_AUTH_TIMEOUT_SECONDS = 300.0


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    _sessions: Dict[str, dict] = {}

    def _gc_sessions() -> None:
        if len(_sessions) > _MAX_SESSIONS:
            oldest = sorted(_sessions.keys(), key=lambda k: _sessions[k].get("created_at", 0))
            for k in oldest[:len(_sessions) - _MAX_SESSIONS]:
                _sessions.pop(k, None)

    def _new_session() -> str:
        from dast.ai.copilot import CopilotSession
        sid = str(uuid.uuid4())[:12]
        _sessions[sid] = {
            "engine": CopilotSession(sid),
            "status": "idle",
            "created_at": time.time(),
            "updated_at": time.time(),
            "trace": [],
            "pause": None,
            "last_reply": None,
            "_pause_event": asyncio.Event(),
            "_pause_result": None,
            "approved_hosts": set(),
            "_task": None,
        }
        _gc_sessions()
        return sid

    def _session_dict(sid: str) -> dict:
        session = _sessions.get(sid)
        if not session:
            return {}
        engine = session["engine"]
        return {
            "session_id": sid,
            "status": session.get("status", "idle"),
            "created_at": session.get("created_at", 0),
            "updated_at": session.get("updated_at", 0),
            "messages": list(engine.messages),
            "trace": session.get("trace", []),
            "pause": session.get("pause"),
            "last_reply": session.get("last_reply"),
        }

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
        if sid and sid not in _sessions:
            return JSONResponse({"error": "session not found"}, status_code=404)
        if not sid:
            sid = _new_session()

        session = _sessions[sid]
        running = session.get("_task")
        if running and not running.done():
            return JSONResponse({"error": "a turn is already in progress"}, status_code=409)

        session["_task"] = asyncio.create_task(_run_turn(sid, text))
        return {"session_id": sid, "status": "running"}

    @router.get("/api/copilot/sessions")
    async def list_sessions():
        return [
            {
                "session_id": sid,
                "status": _sessions[sid].get("status", "idle"),
                "created_at": _sessions[sid].get("created_at", 0),
                "updated_at": _sessions[sid].get("updated_at", 0),
                "message_count": len(_sessions[sid]["engine"].messages),
            }
            for sid in sorted(_sessions.keys(), key=lambda k: -_sessions[k].get("updated_at", 0))
        ]

    @router.get("/api/copilot/session/{sid}")
    async def get_session(sid: str):
        if sid not in _sessions:
            return JSONResponse({"error": "session not found"}, status_code=404)
        return _session_dict(sid)

    @router.post("/api/copilot/resume/{sid}")
    async def resume(sid: str, body: dict):
        """Answer the current pause. Body: {kind, value}.

        approve -> value.decision in allow_once|always_host|deny
        auth    -> value.cookies {name: value}
        """
        if sid not in _sessions:
            return JSONResponse({"error": "session not found"}, status_code=404)
        session = _sessions[sid]
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
        if sid not in _sessions:
            return JSONResponse({"error": "session not found"}, status_code=404)
        session = _sessions[sid]
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
        if sid not in _sessions:
            return JSONResponse({"error": "session not found"}, status_code=404)
        task: Optional[asyncio.Task] = _sessions[sid].get("_task")
        if task and not task.done():
            task.cancel()
        _sessions[sid]["status"] = "idle"
        return {"ok": True}

    @router.websocket("/ws/copilot")
    async def copilot_ws(ws: WebSocket):
        await ws.accept()
        ctx.copilot_ws_clients.add(ws)
        # Re-push in-flight pauses so a late-connecting UI still sees them.
        for sid, session in list(_sessions.items()):
            pause = session.get("pause")
            if pause:
                try:
                    await ws.send_json({"type": "pause", "session_id": sid, **pause})
                except Exception:
                    pass
        try:
            while True:
                await ws.receive_text()
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            ctx.copilot_ws_clients.discard(ws)

    # ── Turn runner ──────────────────────────────────────────────────────────────
    async def _run_turn(sid: str, text: str) -> None:
        session = _sessions[sid]

        async def on_event(payload: dict) -> None:
            event = {"session_id": sid, **payload}
            session["trace"].append(event)
            await ctx.broadcast_copilot(event)

        async def wait_for_human(kind: str, payload: dict) -> dict:
            timeout = {
                "approve": _APPROVE_TIMEOUT_SECONDS,
                "auth": _AUTH_TIMEOUT_SECONDS,
            }.get(kind, _APPROVE_TIMEOUT_SECONDS)
            defaults = {
                "approve": {"decision": "deny"},
                "auth": {"cookies": {}},
            }
            event: asyncio.Event = session["_pause_event"]
            event.clear()
            session["_pause_result"] = None
            session["status"] = f"paused_{kind}"
            session["pause"] = {"kind": kind, "payload": payload}
            await ctx.broadcast_copilot({"type": "pause", "session_id": sid,
                                         "kind": kind, "payload": payload})
            try:
                await asyncio.wait_for(event.wait(), timeout=timeout)
                result = session.get("_pause_result") or defaults.get(kind, {})
            except asyncio.TimeoutError:
                logger.warning("Copilot pause timed out", session_id=sid, kind=kind)
                result = defaults.get(kind, {})
            session["pause"] = None
            session["status"] = "running"
            await ctx.broadcast_copilot({"type": "resumed", "session_id": sid, "kind": kind})
            return result

        try:
            session["status"] = "running"
            session["updated_at"] = time.time()
            tool_ctx = AgentToolContext(
                proxy_port=ctx.proxy_port,
                dashboard_port=getattr(ctx, "dashboard_port", 8088),
                store=ctx.store,
                settings=ctx.settings,
                approved_hosts=session["approved_hosts"],
            )
            reply = await session["engine"].send(
                text, tool_ctx, on_event=on_event, wait_for_human=wait_for_human,
            )
            session["last_reply"] = {
                "message": reply.message,
                "blocked_reason": reply.blocked_reason,
            }
            session["status"] = "blocked" if reply.blocked_reason else "idle"
            session["updated_at"] = time.time()
        except asyncio.CancelledError:
            session["status"] = "idle"
        except Exception as exc:
            logger.error("Copilot turn runner error", session_id=sid, error=str(exc))
            session["status"] = "error"
            session["last_reply"] = {"message": f"Internal error: {str(exc)[:300]}",
                                     "blocked_reason": "error"}

    return router

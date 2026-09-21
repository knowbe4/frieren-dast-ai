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
  POST /api/copilot/explore-hypothesis   — open a conversation from an app-context hypothesis
  POST /api/copilot/autonomous           — start a fully autonomous orchestrator run
  POST /api/copilot/autonomous/{sid}/stop|pause|resume — control an autonomous run
  GET  /api/copilot/sessions             — list recent sessions
  GET  /api/copilot/session/{sid}        — full transcript + messages + pause + reply
  POST /api/copilot/resume/{sid}         — answer a pause (approve/auth/guidance)
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


def _collect_jar_cookies(ctx: DashboardContext, pause: dict) -> dict:
    """Collect the proxy jar's session cookies for a paused auth wall's host.

    The operator logs in through the browser opened for the pause; every
    Set-Cookie on that traffic is ingested into the shared proxy jar. Return
    them as a ``{name: value}`` map for the handoff (sanitised by the caller)."""
    store = getattr(ctx, "store", None)
    if store is None:
        return {}
    payload = pause.get("payload") or {}
    host = str(payload.get("host") or "").strip().lower()
    if not host:
        from urllib.parse import urlparse
        host = (urlparse(str(payload.get("url") or "")).hostname or "").lower()
    if not host:
        return {}
    try:
        cookies = store.get_cookies_for_host(host)
    except Exception as exc:
        logger.warning("could not read proxy jar cookies", host=host, error=str(exc))
        return {}
    result: dict = {}
    for cookie in cookies or []:
        name = cookie.get("name")
        value = cookie.get("value")
        if name and value is not None:
            result[name] = value
    return result


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

    @router.post("/api/copilot/explore-hypothesis")
    async def explore_hypothesis(body: dict):
        """Open (or reuse) a conversation to investigate an app-context
        vulnerability hypothesis. Body: {host, attack_type, endpoint,
        parameter?, rationale?}."""
        host = (body.get("host") or "").strip()
        attack_type = (body.get("attack_type") or "").strip()
        endpoint = (body.get("endpoint") or "").strip()
        if not host or not attack_type or not endpoint:
            return JSONResponse(
                {"error": "host, attack_type and endpoint are required"},
                status_code=400,
            )
        parameter = (body.get("parameter") or "").strip()
        rationale = (body.get("rationale") or "").strip()[:2000]
        sid = service.explore_hypothesis(host, attack_type, endpoint, parameter, rationale)
        if sid is None:
            return JSONResponse({"error": "could not start exploration"}, status_code=503)
        return {"session_id": sid, "status": "running"}

    @router.post("/api/copilot/autonomous")
    async def autonomous(body: dict):
        """Start a fully autonomous orchestrator run.

        Body: {objective (required), focus_hosts?: [str], profile_slug?: str,
        auto_ai_mode?: bool (default true),
        budget?: {max_tool_calls, max_wall_clock_seconds, max_stuck_turns,
        allow_scope_escalation}}. Missing budget fields fall back to the defaults.
        """
        objective = (body.get("objective") or "").strip()
        if not objective:
            return JSONResponse({"error": "objective required"}, status_code=400)
        if len(objective) > _MAX_MESSAGE_CHARS:
            return JSONResponse(
                {"error": f"objective too large (max {_MAX_MESSAGE_CHARS} chars)"},
                status_code=400,
            )
        focus_hosts = body.get("focus_hosts")
        if focus_hosts is not None and not isinstance(focus_hosts, list):
            return JSONResponse({"error": "focus_hosts must be a list"}, status_code=400)
        budget = body.get("budget")
        if budget is not None and not isinstance(budget, dict):
            return JSONResponse({"error": "budget must be an object"}, status_code=400)
        profile_slug = (body.get("profile_slug") or "").strip() or None
        auto_ai_mode = bool(body.get("auto_ai_mode", True))
        try:
            sid = service.run_autonomous(
                objective, focus_hosts=focus_hosts, profile_slug=profile_slug,
                budget=budget, auto_ai_mode=auto_ai_mode,
            )
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except RuntimeError:
            return JSONResponse({"error": "could not start autonomous run"}, status_code=503)
        return {"session_id": sid, "status": "running"}

    @router.post("/api/copilot/autonomous/{sid}/stop")
    async def autonomous_stop(sid: str):
        if not service.stop_autonomous(sid):
            return JSONResponse({"error": "no autonomous run for this session"},
                                status_code=404)
        return {"ok": True}

    @router.post("/api/copilot/autonomous/{sid}/pause")
    async def autonomous_pause(sid: str):
        if not service.pause_autonomous(sid):
            return JSONResponse({"error": "no autonomous run for this session"},
                                status_code=404)
        return {"ok": True}

    @router.post("/api/copilot/autonomous/{sid}/resume")
    async def autonomous_resume(sid: str):
        if not service.resume_autonomous(sid):
            return JSONResponse({"error": "no autonomous run for this session"},
                                status_code=404)
        return {"ok": True}

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

        approve  -> value.decision in allow_once|always_host|deny
        auth     -> value.cookies {name: value}
        guidance -> value.action in continue|pause|abort, value.answer (free text)
                    — answers a need_human escalation on an autonomous run and
                    resumes it.
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
            # "Login done" handoff: the browser's Set-Cookie responses were ingested
            # into the shared proxy jar, not into the header-less UI entry list, so
            # the client cannot read them. When it asks us to source from the jar,
            # collect the session cookies server-side for the paused host.
            if value.get("from_jar") and not raw:
                raw = _collect_jar_cookies(ctx, pause)
                logger.info(
                    "Copilot auth resume collected cookies from proxy jar",
                    session_id=sid, cookie_count=len(raw),
                )
            session["_pause_result"] = {"cookies": _sanitise_cookies(raw)}
        elif kind == "guidance":
            action = str(value.get("action", "continue")).strip().lower()
            if action not in ("continue", "pause", "abort"):
                return JSONResponse(
                    {"error": "action must be continue|pause|abort"}, status_code=400)
            answer = str(value.get("answer", "")).strip()[:_MAX_MESSAGE_CHARS]
            session["_pause_result"] = {"answer": answer, "action": action}
        else:
            return JSONResponse(
                {"error": "kind must be approve|auth|guidance"}, status_code=400)

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
        from dast.proxy.api.browse_targets import is_openable_target_url
        if not is_openable_target_url(target_url):
            return JSONResponse({"error": "No valid http(s) URL to open"}, status_code=400)

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

    @router.post("/api/copilot/refresh-session/{sid}")
    async def refresh_session(sid: str):
        """Re-read the proxy jar's current cookies for every host this session has
        touched and inject them into the copilot engine. Call this after the operator
        logs in via the browser to give the copilot a fresh authenticated session."""
        session = service.get(sid)
        if session is None:
            return JSONResponse({"error": "session not found"}, status_code=404)
        result = service.refresh_session(sid)
        if not result.get("ok"):
            return JSONResponse({"error": result.get("error", "refresh failed")}, status_code=500)
        return result

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

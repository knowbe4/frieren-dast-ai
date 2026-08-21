"""
Login-flow routes — record a login by hand, replay it, and pause for a human.

  POST /api/login-flow/record/start    open a visible recording browser
  POST /api/login-flow/record/stop     stop + persist the flow onto a profile
  POST /api/login-flow/record/cancel   discard the in-progress recording
  POST /api/login-flow/replay          replay a saved flow (pauses on captcha/MFA)
  POST /api/login-flow/resume          release a paused replay (analyst solved it)
  GET  /api/login-flow/{slug}          the saved flow for a profile (no secrets)
  WS   /ws/login                       live recording/replay/needs-human events

The recorder classifies credential fields in-page, so secrets are NEVER captured
into the flow (only ``value_ref`` markers). Replay substitutes the decrypted
credential at run time. On a captcha/MFA wall the replayer emits a needs-human
event over /ws/login and blocks until POST /api/login-flow/resume fires.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dast.profiles.models import LoginProfile
from dast.profiles.store import load_profile, save_profile
from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Bound on how long a replay may run, including a human-solved captcha pause.
_REPLAY_TIMEOUT_S = 360.0
_RECORD_TIMEOUT_S = 20.0


class RecordStartIn(BaseModel):
    url: str = ""


class RecordStopIn(BaseModel):
    slug: str
    save_session: bool = True  # also persist the captured cookies as a fallback


class ReplayIn(BaseModel):
    slug: str
    credential_label: str = ""  # empty = first credential


def _pick_credential(profile: LoginProfile, label: str):
    """Return the requested credential, or the first one, or None."""
    if not profile.credentials:
        return None
    if label:
        for cred in profile.credentials:
            if cred.label == label:
                return cred
    return profile.credentials[0]


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    login_queue = ctx.login_queue

    @router.post("/api/login-flow/record/start")
    async def record_start(req: RecordStartIn) -> dict:
        if not login_queue:
            return JSONResponse({"error": "login worker not available"}, status_code=503)
        result: dict = {}
        done = asyncio.Event()

        def result_cb(ok: bool, error: str, session_id: str) -> None:
            result.update({"ok": ok, "error": error, "session_id": session_id})
            done.set()

        await login_queue.put(
            {"action": "start_record", "url": req.url, "result_cb": result_cb}
        )
        try:
            await asyncio.wait_for(done.wait(), timeout=_RECORD_TIMEOUT_S)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "recorder failed to open"}, status_code=500)
        if not result.get("ok"):
            return JSONResponse({"error": result.get("error", "unknown")}, status_code=400)
        await ctx.broadcast_login({"type": "recording_started", "url": req.url})
        return {"recording": True, "session_id": result["session_id"]}

    @router.post("/api/login-flow/record/stop")
    async def record_stop(req: RecordStopIn) -> dict:
        if not login_queue:
            return JSONResponse({"error": "login worker not available"}, status_code=503)
        profile = load_profile(req.slug)
        if profile is None:
            return JSONResponse({"error": "profile not found"}, status_code=404)

        result: dict = {}
        done = asyncio.Event()

        def result_cb(ok: bool, error: str, payload: dict) -> None:
            result.update({"ok": ok, "error": error, "payload": payload or {}})
            done.set()

        await login_queue.put({"action": "stop_record", "result_cb": result_cb})
        try:
            await asyncio.wait_for(done.wait(), timeout=_RECORD_TIMEOUT_S)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "recorder failed to stop"}, status_code=500)
        if not result.get("ok"):
            return JSONResponse({"error": result.get("error", "unknown")}, status_code=400)

        payload = result["payload"]
        flow = payload.get("flow") or {}
        profile.login_flow = flow
        if not profile.host_pattern and flow.get("start_url"):
            from dast.profiles.models import host_from_url
            profile.host_pattern = host_from_url(flow["start_url"])
        # Persist the captured session as the replay fallback (encrypted at rest).
        if req.save_session:
            storage_state = payload.get("storage_state")
            if storage_state:
                profile.saved_session = storage_state
            elif payload.get("cookies"):
                profile.saved_session = {"cookies": payload["cookies"], "origins": []}
        save_profile(profile)
        await ctx.broadcast_login(
            {"type": "recording_saved", "slug": req.slug,
             "steps": len(flow.get("steps", []))}
        )
        return profile.to_public_dict()

    @router.post("/api/login-flow/record/cancel")
    async def record_cancel() -> dict:
        if not login_queue:
            return JSONResponse({"error": "login worker not available"}, status_code=503)
        done = asyncio.Event()
        await login_queue.put(
            {"action": "cancel_record", "result_cb": lambda *_: done.set()}
        )
        try:
            await asyncio.wait_for(done.wait(), timeout=_RECORD_TIMEOUT_S)
        except asyncio.TimeoutError:
            pass
        return {"cancelled": True}

    @router.post("/api/login-flow/replay")
    async def replay(req: ReplayIn) -> dict:
        if not login_queue:
            return JSONResponse({"error": "login worker not available"}, status_code=503)
        profile = load_profile(req.slug)
        if profile is None:
            return JSONResponse({"error": "profile not found"}, status_code=404)
        if not profile.login_flow or not profile.login_flow.get("steps"):
            return JSONResponse(
                {"error": "profile has no recorded login flow"}, status_code=400
            )
        cred = _pick_credential(profile, req.credential_label)
        username = cred.username if cred else ""
        password = cred.secret if cred else ""

        # Arm the shared resume gate for this replay's human-in-loop pause.
        ctx.login_resume_event.clear()

        async def on_pause(reason: str) -> None:
            await ctx.broadcast_login(
                {"type": "needs_human", "slug": req.slug, "reason": reason}
            )

        result: dict = {}
        done = asyncio.Event()

        def result_cb(res: dict) -> None:
            result.update(res or {})
            done.set()

        await login_queue.put({
            "action": "replay",
            "flow": profile.login_flow,
            "username": username,
            "password": password,
            "on_pause": on_pause,
            "resume_event": ctx.login_resume_event,
            "result_cb": result_cb,
        })
        try:
            await asyncio.wait_for(done.wait(), timeout=_REPLAY_TIMEOUT_S)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "replay timed out"}, status_code=504)

        cookies_imported = 0
        if result.get("success"):
            # Fold the freshly authenticated session into the live proxy jar and
            # register it as a named session (mirrors profile activate).
            cookies = list(result.get("cookies", []))
            auth_headers = dict(result.get("auth_headers", {}))
            ctx.store.save_named_session_from_playwright(
                name=profile.slug, role=profile.name,
                playwright_cookies=cookies, auth_headers=auth_headers,
            )
            cookies_imported = ctx.store.import_playwright_cookies(cookies)
            # Refresh the saved fallback session with the new state.
            if result.get("storage_state"):
                profile.saved_session = result["storage_state"]
                save_profile(profile)
        await ctx.broadcast_login(
            {"type": "replay_done", "slug": req.slug,
             "success": bool(result.get("success")), "error": result.get("error", "")}
        )
        return {
            "success": bool(result.get("success")),
            "error": result.get("error", ""),
            "needed_human": bool(result.get("needed_human")),
            "cookies_imported": cookies_imported,
        }

    @router.post("/api/login-flow/resume")
    async def resume() -> dict:
        """Release a replay paused for a human (analyst solved the captcha/MFA)."""
        ctx.login_resume_event.set()
        await ctx.broadcast_login({"type": "resumed"})
        return {"resumed": True}

    @router.get("/api/login-flow/{slug}")
    async def get_flow(slug: str) -> dict:
        profile = load_profile(slug)
        if profile is None:
            return JSONResponse({"error": "profile not found"}, status_code=404)
        flow = profile.login_flow or {}
        # Steps carry no secrets (credential fields are value_ref markers) — safe to return.
        return {
            "slug": slug,
            "start_url": flow.get("start_url", ""),
            "steps": flow.get("steps", []),
            "step_count": len(flow.get("steps", [])),
        }

    @router.websocket("/ws/login")
    async def login_ws_endpoint(ws: WebSocket):
        await ws.accept()
        ctx.login_ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            ctx.login_ws_clients.discard(ws)

    return router

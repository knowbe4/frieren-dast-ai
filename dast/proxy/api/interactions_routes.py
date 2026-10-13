"""
Interactions routes — OOB callback tracker.

POST   /api/interactions/new       — register new interactsh session
POST   /api/interactions/{id}/stop — stop polling + deregister, KEEP callbacks
DELETE /api/interactions/{id}      — stop + remove the session entirely
GET    /api/interactions           — list all sessions with callbacks
GET    /api/interactions/{id}      — single session detail
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_SESSIONS = 100
_MAX_CALLBACKS_PER_SESSION = 50

# Module-level store so external callers (H1 validator, SSRF agent) can
# register sessions that will appear in the Interactions tab automatically.
_sessions: Dict[str, dict] = {}
_tasks: Dict[str, asyncio.Task] = {}
_broadcast_fn = None   # set to _broadcast_raw when the router is created
_store = None           # set to ctx.store when the router is created


class _NewSessionIn(BaseModel):
    origin_url: str = ""
    origin_method: str = "GET"
    origin_param: str = ""
    label: str = ""


def _auto_create_finding(session: dict) -> None:
    """Create a finding in the session store when an OOB callback is confirmed.

    Only fires once per session (guarded by ``finding_created`` flag) and only
    when the session carries an ``origin_url`` so the finding is linked to a
    real request the operator proxied through Frieren.
    """
    if _store is None:
        return
    origin_url = session.get("origin_url", "").strip()
    if not origin_url:
        return
    if session.get("finding_created"):
        return
    session["finding_created"] = True
    try:
        cb = session["callbacks"][-1] if session.get("callbacks") else {}
        cb_type = cb.get("type", "dns/http")
        evidence = (
            f"OOB {cb_type.upper()} callback received on {session['oob_url']}. "
            f"Server fetched attacker-controlled URL — confirms out-of-band interaction. "
            f"Callback raw (truncated): {cb.get('raw', '')[:300]}"
        )
        finding = {
            "title": "Out-of-Band (OOB) Interaction — Potential Blind SSRF/XXE/CMDI",
            "severity": "high",
            "attack_type": "ssrf",
            "cwe": "CWE-918",
            "parameter": session.get("origin_param", ""),
            "evidence": evidence,
            "confirmed": True,
            "confidence": 0.9,
            "validated_by": ["oob_callback"],
            "source": "interactions",
        }
        if session.get("label"):
            finding["reasoning"] = f"OOB session label: {session['label']}"
        origin_method = (session.get("origin_method") or "GET").upper()
        entry_id = _store.record_manual_finding(finding, origin_url, origin_method)
        logger.info(
            "interactions: auto-created OOB finding",
            origin_url=origin_url,
            entry_id=entry_id,
            oob_url=session["oob_url"],
        )
    except Exception as exc:
        logger.warning("interactions: failed to auto-create finding", error=str(exc))


async def register_external_session(
    interactsh_session,
    label: str = "",
    origin_url: str = "",
    origin_method: str = "GET",
    origin_param: str = "",
) -> Optional[str]:
    """
    Register an already-initialised InteractshSession into the Interactions tab.
    Returns the session_id, or None if interactsh is not registered yet.
    Call this after interactsh_session.register() succeeds.

    Pass origin_url/origin_method/origin_param so that when a callback arrives the
    system can auto-create a finding linked to the originating request.
    """
    if not interactsh_session.url:
        return None

    session_id = str(uuid.uuid4())[:8]
    now = time.time()
    _sessions[session_id] = {
        "session_id": session_id,
        "oob_url": interactsh_session.url,
        "label": label,
        "origin_url": origin_url,
        "origin_method": origin_method,
        "origin_param": origin_param,
        "created_at": now,
        "active": True,
        "callbacks": [],
        "_interactsh": interactsh_session,
    }
    _gc_external()

    task = asyncio.create_task(_poll_loop_external(session_id))
    _tasks[session_id] = task

    from dast.proxy.plugin_manager import log_event
    log_event(
        "interactions", "info",
        f"OOB session registered: {interactsh_session.url}{' (' + label + ')' if label else ''}",
        url=interactsh_session.url, source="agent",
    )
    return session_id


def _gc_external() -> None:
    if len(_sessions) > _MAX_SESSIONS:
        oldest = sorted(_sessions.keys(), key=lambda k: _sessions[k].get("created_at", 0))
        for k in oldest[: len(_sessions) - _MAX_SESSIONS]:
            task = _tasks.pop(k, None)
            if task and not task.done():
                task.cancel()
            _sessions.pop(k, None)


async def _poll_loop_external(session_id: str) -> None:
    session = _sessions.get(session_id)
    if not session:
        return
    interactsh_session = session.get("_interactsh")
    if not interactsh_session:
        return

    from dast.proxy.plugin_manager import log_event
    log_event("interactions", "info",
              f"Polling started: {session['oob_url']}", url=session["oob_url"], source="agent")
    poll_count = 0
    while session.get("active"):
        try:
            await asyncio.sleep(3)
            if not session.get("active"):
                break
            poll_count += 1
            callbacks = await _poll_once(interactsh_session)
            logger.debug("interactions poll", session_id=session_id, poll=poll_count, hits=len(callbacks))
            for cb in callbacks:
                if len(session["callbacks"]) >= _MAX_CALLBACKS_PER_SESSION:
                    session["callbacks"].pop(0)
                session["callbacks"].append(cb)
                log_event(
                    "interactions", "finding",
                    f"Interaction received [{cb['type']}] on {session['oob_url']}",
                    url=session["oob_url"], source="agent",
                )
                logger.info("interactions hit", session_id=session_id,
                            type=cb["type"], raw=cb["raw"][:80])
                _auto_create_finding(session)
                try:
                    interactsh_session.hit_event.set()
                except Exception:
                    pass
                if _broadcast_fn:
                    await _broadcast_fn({
                        "type": "interaction",
                        "session_id": session_id,
                        "oob_url": session["oob_url"],
                        "callback": cb,
                    })
        except asyncio.CancelledError:
            log_event("interactions", "info",
                      f"Polling stopped: {session['oob_url']}", url=session["oob_url"], source="agent")
            break
        except Exception as exc:
            logger.warning("interactions external poll error", session_id=session_id, error=str(exc))


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    # Use module-level stores so external callers share the same sessions
    global _broadcast_fn, _store
    _store = getattr(ctx, "store", None)

    def _gc_sessions() -> None:
        if len(_sessions) > _MAX_SESSIONS:
            oldest = sorted(
                _sessions.keys(),
                key=lambda k: _sessions[k].get("created_at", 0),
            )
            for k in oldest[: len(_sessions) - _MAX_SESSIONS]:
                task = _tasks.pop(k, None)
                if task and not task.done():
                    task.cancel()
                _sessions.pop(k, None)

    def _session_dict(session_id: str) -> dict:
        s = _sessions.get(session_id)
        if not s:
            return {}
        return {
            "session_id": s["session_id"],
            "oob_url": s["oob_url"],
            "label": s.get("label", ""),
            "created_at": s["created_at"],
            "stopped_at": s.get("stopped_at"),
            "active": s["active"],
            "callbacks": list(s["callbacks"]),
        }

    async def _broadcast_raw(msg: dict) -> None:
        dead = set()
        text = json.dumps(msg)
        for ws in list(ctx.ws_clients):
            try:
                await ws.send_text(text)
            except Exception:
                dead.add(ws)
        ctx.ws_clients.difference_update(dead)

    _broadcast_fn = _broadcast_raw  # expose to external callers

    async def _poll_loop(session_id: str) -> None:
        from dast.proxy.plugin_manager import log_event

        session = _sessions.get(session_id)
        if not session:
            return

        interactsh_session = session.get("_interactsh")
        if not interactsh_session:
            return

        log_event("interactions", "info",
                  f"Polling started: {session['oob_url']}", url=session["oob_url"], source="agent")
        poll_count = 0
        while session.get("active"):
            try:
                await asyncio.sleep(3)
                if not session.get("active"):
                    break

                poll_count += 1
                callbacks = await _poll_once(interactsh_session)
                logger.debug("interactions poll", session_id=session_id,
                             poll=poll_count, hits=len(callbacks))
                for cb in callbacks:
                    if len(session["callbacks"]) >= _MAX_CALLBACKS_PER_SESSION:
                        session["callbacks"].pop(0)
                    session["callbacks"].append(cb)

                    log_event(
                        "interactions", "finding",
                        f"Interaction received [{cb['type']}] on {session['oob_url']}",
                        url=session["oob_url"], source="agent",
                    )
                    logger.info("interactions hit", session_id=session_id,
                                type=cb["type"], raw=cb["raw"][:80])
                    _auto_create_finding(session)

                    try:
                        interactsh_session.hit_event.set()
                    except Exception:
                        pass

                    await _broadcast_raw({
                        "type": "interaction",
                        "session_id": session_id,
                        "oob_url": session["oob_url"],
                        "callback": cb,
                    })

            except asyncio.CancelledError:
                log_event("interactions", "info",
                          f"Polling stopped: {session['oob_url']}", url=session["oob_url"], source="agent")
                break
            except Exception as exc:
                logger.warning("interactions poll error", session_id=session_id, error=str(exc))

    @router.post("/api/interactions/new")
    async def create_session(body: Optional[_NewSessionIn] = None) -> dict:
        from dast.utils.interactsh import InteractshSession

        session_id = str(uuid.uuid4())[:8]
        interactsh = InteractshSession()
        registered = await interactsh.register()

        if not registered or not interactsh.url:
            return JSONResponse(
                {"error": "Could not register interactsh session — all servers unavailable"},
                status_code=503,
            )

        now = time.time()
        _sessions[session_id] = {
            "session_id": session_id,
            "oob_url": interactsh.url,
            "origin_url": body.origin_url if body else "",
            "origin_method": body.origin_method if body else "GET",
            "origin_param": body.origin_param if body else "",
            "label": body.label if body else "",
            "created_at": now,
            "active": True,
            "callbacks": [],
            "_interactsh": interactsh,
        }
        _gc_sessions()

        task = asyncio.create_task(_poll_loop(session_id))
        _tasks[session_id] = task

        from dast.proxy.plugin_manager import log_event
        log_event(
            "interactions",
            "info",
            f"Interaction session created: {interactsh.url}",
            url=interactsh.url,
            source="agent",
        )

        return {
            "session_id": session_id,
            "oob_url": interactsh.url,
            "created_at": now,
        }

    async def _stop_polling(session_id: str) -> None:
        """Stop the poll loop and deregister the OOB server, keeping the
        session record and its received callbacks intact."""
        session = _sessions.get(session_id)
        if not session:
            return
        if session.get("active"):
            session["stopped_at"] = time.time()
        session["active"] = False

        task = _tasks.pop(session_id, None)
        if task and not task.done():
            task.cancel()

        interactsh = session.get("_interactsh")
        if interactsh:
            try:
                await interactsh.deregister()
            except Exception as exc:
                logger.warning("interactions deregister failed",
                               session_id=session_id, error=str(exc))

    @router.post("/api/interactions/{session_id}/stop")
    async def stop_session(session_id: str) -> dict:
        """Stop polling but retain the session and its callbacks so the
        operator can still review the interactions already received."""
        if session_id not in _sessions:
            return JSONResponse({"error": "session not found"}, status_code=404)
        await _stop_polling(session_id)
        from dast.proxy.plugin_manager import log_event
        log_event("interactions", "info",
                  f"OOB session stopped (callbacks retained): {_sessions[session_id]['oob_url']}",
                  url=_sessions[session_id]["oob_url"], source="agent")
        return {"ok": True, "active": False}

    @router.delete("/api/interactions/{session_id}")
    async def delete_session(session_id: str) -> dict:
        if session_id not in _sessions:
            return JSONResponse({"error": "session not found"}, status_code=404)

        await _stop_polling(session_id)
        _sessions.pop(session_id, None)
        return {"ok": True}

    @router.get("/api/interactions")
    async def list_sessions() -> list:
        return [
            _session_dict(sid)
            for sid in sorted(
                _sessions.keys(),
                key=lambda k: -_sessions[k].get("created_at", 0),
            )
        ]

    @router.get("/api/interactions/{session_id}")
    async def get_session(session_id: str) -> dict:
        if session_id not in _sessions:
            return JSONResponse({"error": "session not found"}, status_code=404)
        return _session_dict(session_id)

    return router


# Raw callbacks are kept for display; long enough that a typical DNS or HTTP
# interaction stays valid JSON so the tab can format it.
_MAX_CALLBACK_RAW_CHARS = 2000


def _callback_from_interaction(interaction: dict, received_at: float) -> dict:
    """Shape one interactsh interaction as an Interactions-tab callback."""
    protocol = str(interaction.get("protocol") or "").lower()
    if protocol in ("http", "https"):
        interaction_type = "http"
    elif protocol == "dns":
        interaction_type = "dns"
    else:
        interaction_type = "unknown"
    return {
        "received_at": received_at,
        "type": interaction_type,
        "raw": json.dumps(interaction)[:_MAX_CALLBACK_RAW_CHARS],
    }


async def _poll_once(interactsh_session) -> List[dict]:
    """
    Poll interactsh once and return a list of callback dicts with
    type, raw text, and received_at timestamp.
    """
    now = time.time()
    interactions = await interactsh_session.fetch_interactions()
    return [_callback_from_interaction(interaction, now) for interaction in interactions]


def register_display_session(oob_url: str, label: str = "") -> str:
    """Create an Interactions-tab session that its owner feeds; it is never polled here.

    For components that poll their own interactsh session and attribute each
    callback themselves (the header OOB plugin). Polling here as well would race
    them for the same interactions — the server deletes interactions once polled.
    No finding is auto-created: the owner records precise findings itself.
    """
    session_id = str(uuid.uuid4())[:8]
    _sessions[session_id] = {
        "session_id": session_id,
        "oob_url": oob_url,
        "label": label,
        "origin_url": "",
        "created_at": time.time(),
        "active": True,
        "callbacks": [],
    }
    _gc_external()
    return session_id


async def publish_callbacks(session_id: str, interactions: List[dict]) -> None:
    """Append interactions to a display session and push them to open dashboards."""
    session = _sessions.get(session_id)
    if not session:
        return
    now = time.time()
    for interaction in interactions:
        callback = _callback_from_interaction(interaction, now)
        if len(session["callbacks"]) >= _MAX_CALLBACKS_PER_SESSION:
            session["callbacks"].pop(0)
        session["callbacks"].append(callback)
        if _broadcast_fn:
            try:
                await _broadcast_fn({
                    "type": "interaction",
                    "session_id": session_id,
                    "oob_url": session["oob_url"],
                    "callback": callback,
                })
            except Exception as exc:
                logger.warning("interactions broadcast failed", session_id=session_id, error=str(exc))

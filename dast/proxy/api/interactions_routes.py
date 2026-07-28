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
import base64
import json
import time
import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse

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


async def register_external_session(
    interactsh_session,
    label: str = "",
) -> Optional[str]:
    """
    Register an already-initialised InteractshSession into the Interactions tab.
    Returns the session_id, or None if interactsh is not registered yet.
    Call this after interactsh_session.register() succeeds.
    """
    if not interactsh_session.url:
        return None

    session_id = str(uuid.uuid4())[:8]
    now = time.time()
    _sessions[session_id] = {
        "session_id": session_id,
        "oob_url": interactsh_session.url,
        "label": label,
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
    global _broadcast_fn

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
    async def create_session() -> dict:
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


async def _poll_once(interactsh_session) -> List[dict]:
    """
    Poll interactsh once and return a list of callback dicts with
    type, raw text, and received_at timestamp.
    """
    try:
        import httpx
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as _pad
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        async with httpx.AsyncClient(
            timeout=10, verify=False, headers=interactsh_session._headers
        ) as client:
            r = await client.get(
                f"{interactsh_session._server}/poll",
                params={
                    "id": interactsh_session._correlation_id,
                    "secret": interactsh_session._secret_key,
                },
            )
            if r.status_code != 200:
                return []
            data = r.json()

        results: List[dict] = []
        now = time.time()

        if data.get("extra"):
            results.append(
                {
                    "received_at": now,
                    "type": "unknown",
                    "raw": str(data["extra"])[:500],
                }
            )
            return results

        encrypted_entries = data.get("data") or []
        aes_key_b64 = data.get("aes_key", "")
        if (
            not encrypted_entries
            or not aes_key_b64
            or not interactsh_session._private_key
        ):
            return []

        aes_key = interactsh_session._private_key.decrypt(
            base64.b64decode(aes_key_b64),
            _pad.OAEP(
                mgf=_pad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        for entry_b64 in encrypted_entries:
            raw_bytes = base64.b64decode(entry_b64)
            iv, ciphertext = raw_bytes[:16], raw_bytes[16:]
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
            dec = cipher.decryptor()
            plaintext_bytes = dec.update(ciphertext) + dec.finalize()
            if not plaintext_bytes:
                continue

            try:
                plaintext = plaintext_bytes.decode("utf-8", errors="replace")
            except Exception:
                plaintext = repr(plaintext_bytes)

            interaction_type = "unknown"
            plaintext_lower = plaintext.lower()
            if '"protocol":"http"' in plaintext_lower or "http request" in plaintext_lower:
                interaction_type = "http"
            elif '"protocol":"dns"' in plaintext_lower or "dns" in plaintext_lower[:80]:
                interaction_type = "dns"

            try:
                import json as _json
                parsed = _json.loads(plaintext)
                proto = (parsed.get("protocol") or "").lower()
                if proto in ("http", "https"):
                    interaction_type = "http"
                elif proto == "dns":
                    interaction_type = "dns"
            except Exception:
                pass

            results.append(
                {
                    "received_at": now,
                    "type": interaction_type,
                    "raw": plaintext[:500],
                }
            )

        return results

    except Exception as exc:
        logger.debug("interactions _poll_once error", error=str(exc))
        return []

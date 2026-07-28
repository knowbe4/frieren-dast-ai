"""
Session persistence routes: save, load, delete, export, import.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse, Response

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def _restore_extra(store, data: dict, ctx: "DashboardContext") -> None:
    """Restore AI context, suggestions, named sessions and logs from session data."""
    from dast.proxy.session_store import NamedSession

    # Named sessions (multi-user IDOR)
    named_data = data.get("named_sessions", {})
    if named_data:
        store.named_sessions = {
            name: NamedSession(
                name=s["name"],
                role=s.get("role", "user"),
                cookies=s.get("cookies", {}),
                auth_headers=s.get("auth_headers", {}),
                created_at=s.get("created_at", 0.0),
            )
            for name, s in named_data.items()
        }

    # AI suggestions
    suggestions = data.get("active_suggestions")
    if suggestions is not None:
        store.active_suggestions = suggestions

    # System logs — restore into plugin manager event log
    event_log = data.get("event_log")
    if event_log:
        pm = getattr(store, "_plugin_manager", None) or getattr(ctx, "plugin_manager", None)
        if pm is not None:
            existing = list(getattr(pm, "_event_log", []))
            pm._event_log = event_log + [e for e in existing if e not in event_log]
            pm._event_log = pm._event_log[:500]

    # App profiles + threat models — inject into discovery workers
    discovery = getattr(store, "discovery_engine", None)
    if discovery is None:
        return

    app_profiles = data.get("app_profiles", {})
    if app_profiles:
        worker = getattr(discovery, "_app_context_worker", None)
        if worker is not None:
            from dast.discovery.app_context import AppProfile
            import dataclasses
            fields = {f.name for f in dataclasses.fields(AppProfile)}
            for host, raw in app_profiles.items():
                try:
                    if not worker.get_profile(host):
                        profile = AppProfile(**{k: v for k, v in raw.items() if k in fields})
                        worker._profiles[host] = profile
                except Exception:
                    pass

    threat_models = data.get("threat_models", {})
    if threat_models:
        tm_worker = getattr(discovery, "_threat_model_worker", None)
        if tm_worker is not None:
            from dast.discovery.threat_model import ThreatModel
            import dataclasses
            fields = {f.name for f in dataclasses.fields(ThreatModel)}
            for host, raw in threat_models.items():
                try:
                    if not tm_worker.get_model(host):
                        tm = ThreatModel(**{k: v for k, v in raw.items() if k in fields})
                        tm_worker._models[host] = tm
                except Exception:
                    pass


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    store = ctx.store
    settings = ctx.settings

    def _broadcast_all():
        """Return a coroutine that broadcasts every entry in the store."""
        async def _inner():
            for entry in store.all_entries():
                await ctx.broadcast(entry)
        return _inner()

    @router.get("/api/sessions")
    async def list_sessions_api():
        from dast.proxy.session_manager import list_sessions
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, list_sessions)

    @router.post("/api/sessions")
    async def save_session_api(body: dict):
        from dast.proxy.session_manager import save_session
        name = body.get("name", "Untitled session").strip() or "Untitled session"
        desc = body.get("description", "").strip()
        # If session_id is provided, overwrite that file (auto-save / re-save flow)
        session_id = body.get("session_id") or None
        loop = asyncio.get_running_loop()
        meta = await loop.run_in_executor(
            None, lambda: save_session(store, settings, name, desc, session_id=session_id)
        )
        return meta

    @router.post("/api/sessions/export")
    async def export_session_api(body: dict):
        import json as _json
        from datetime import datetime, timezone
        name = body.get("name", "Untitled session").strip() or "Untitled session"
        desc = body.get("description", "").strip()
        entries = [entry.to_dict(include_bodies=True) for entry in store.all_entries()]
        data = {
            "id": f"export-{int(datetime.now(timezone.utc).timestamp())}",
            "name": name,
            "description": desc,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(entries),
            "settings": settings.to_dict() if settings else {},
            "entries": entries,
            "cookies": getattr(store, "_cookies", {}),
        }
        return Response(
            content=_json.dumps(data, indent=2, default=str),
            media_type="application/json",
        )

    @router.post("/api/sessions/{session_id}/load")
    async def load_session_api(session_id: str):
        from dast.proxy.session_manager import load_session
        from dast.proxy.dashboard_server import _apply_settings_data
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, lambda: load_session(session_id))
        if data is None:
            logger.warning("Session load failed: not found", session_id=session_id)
            return JSONResponse({"error": "session not found"}, status_code=404)
        entry_count = store.load_from_session_data(data.get("entries", []), data.get("cookies", {}), settings=settings)
        si_data = data.get("session_intelligence")
        if si_data:
            store.load_session_intelligence(si_data)
        _restore_extra(store, data, ctx)
        if settings and data.get("settings"):
            _apply_settings_data(settings, data["settings"])
        await _broadcast_all()
        logger.info("Session loaded", session_id=session_id, name=data.get("name"), entry_count=entry_count)
        return {"id": data.get("id"), "name": data.get("name", ""), "entry_count": entry_count}

    @router.delete("/api/sessions/{session_id}")
    async def delete_session_api(session_id: str):
        from dast.proxy.session_manager import delete_session
        loop = asyncio.get_running_loop()
        ok = await loop.run_in_executor(None, lambda: delete_session(session_id))
        return {"ok": ok}

    @router.get("/api/sessions/{session_id}/download")
    async def download_session_api(session_id: str):
        from dast.proxy.session_manager import get_session_path
        loop = asyncio.get_running_loop()
        path = await loop.run_in_executor(None, lambda: get_session_path(session_id))
        if path is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(path=str(path), media_type="application/json", filename=path.name)

    @router.post("/api/sessions/import")
    async def import_session_api(body: dict):
        from dast.proxy.dashboard_server import _validate_session_import, _apply_settings_data
        error = _validate_session_import(body)
        if error:
            return JSONResponse({"error": error}, status_code=400)
        entry_count = store.load_from_session_data(body.get("entries", []), body.get("cookies", {}))
        si_data = body.get("session_intelligence")
        if si_data:
            store.load_session_intelligence(si_data)
        _restore_extra(store, body, ctx)
        if settings and body.get("settings"):
            _apply_settings_data(settings, body["settings"])
        await _broadcast_all()
        return {"id": body.get("id", ""), "name": body.get("name", "Imported session"), "entry_count": entry_count}

    return router

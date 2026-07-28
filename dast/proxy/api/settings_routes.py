"""
Settings routes: proxy settings, scope rules, bypass, extensions, projects, scan-config.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    settings = ctx.settings
    _scan_config = ctx._scan_cfg

    @router.get("/api/settings")
    async def get_settings():
        if settings is None:
            return {"bypass_domains": [], "hidden_extensions": []}
        return settings.to_dict()

    @router.post("/api/settings/scope")
    async def add_scope(body: dict):
        if settings and body.get("rule"):
            settings.add_scope_rule(body["rule"])
        return {"ok": True}

    @router.delete("/api/settings/scope")
    async def remove_scope(body: dict):
        if settings and body.get("index") is not None:
            settings.remove_scope_rule(int(body["index"]))
        return {"ok": True}

    @router.patch("/api/settings/scope/{index}")
    async def toggle_scope(index: int, body: dict):
        if settings:
            settings.toggle_scope_rule(index, bool(body.get("enabled", True)))
        return {"ok": True}

    @router.get("/api/projects")
    async def list_projects():
        if settings is None:
            return []
        return settings.list_projects()

    @router.post("/api/projects")
    async def save_project(body: dict):
        if settings is None:
            return JSONResponse({"error": "settings not available"}, status_code=503)
        name = body.get("name", "").strip()
        if not name:
            return JSONResponse({"error": "name required"}, status_code=400)
        path = settings.save_project(name)
        return {"ok": True, "path": path}

    @router.post("/api/projects/{project_id}/load")
    async def load_project(project_id: str):
        if settings is None:
            return JSONResponse({"error": "settings not available"}, status_code=503)
        if not settings.load_project(project_id):
            return JSONResponse({"error": "project not found"}, status_code=404)
        return settings.to_dict()

    @router.delete("/api/projects/{project_id}")
    async def delete_project(project_id: str):
        if settings is None:
            return JSONResponse({"error": "settings not available"}, status_code=503)
        found = settings.delete_project(project_id)
        return {"ok": found}

    @router.post("/api/settings/bypass")
    async def add_bypass(body: dict):
        if settings and body.get("domain"):
            settings.add_bypass(body["domain"])
        return {"ok": True}

    @router.delete("/api/settings/bypass")
    async def remove_bypass(body: dict):
        if settings and body.get("domain"):
            settings.remove_bypass(body["domain"])
        return {"ok": True}

    @router.post("/api/settings/extension")
    async def add_extension(body: dict):
        if settings and body.get("ext"):
            settings.add_hidden_ext(body["ext"])
        return {"ok": True}

    @router.delete("/api/settings/extension")
    async def remove_extension(body: dict):
        if settings and body.get("ext"):
            settings.remove_hidden_ext(body["ext"])
        return {"ok": True}

    @router.get("/api/settings/match-replace")
    async def get_match_replace():
        if settings is None:
            return []
        return settings.get_match_replace()

    @router.post("/api/settings/match-replace")
    async def add_match_replace(body: dict):
        if settings is None:
            return JSONResponse({"error": "settings not available"}, status_code=503)
        settings.add_match_replace(body)
        return {"ok": True}

    @router.delete("/api/settings/match-replace")
    async def remove_match_replace(body: dict):
        if settings is None:
            return JSONResponse({"error": "settings not available"}, status_code=503)
        idx = body.get("index")
        if idx is None:
            return JSONResponse({"error": "index required"}, status_code=400)
        settings.remove_match_replace(int(idx))
        return {"ok": True}

    @router.post("/api/settings/match-replace/toggle")
    async def toggle_match_replace(body: dict):
        if settings is None:
            return JSONResponse({"error": "settings not available"}, status_code=503)
        idx = body.get("index")
        if idx is None:
            return JSONResponse({"error": "index required"}, status_code=400)
        settings.toggle_match_replace(int(idx), bool(body.get("enabled", True)))
        return {"ok": True}

    @router.post("/api/settings/import")
    async def import_settings_api(body: dict):
        from dast.proxy.dashboard_server import _validate_settings_import, _apply_settings_data
        error = _validate_settings_import(body)
        if error:
            return JSONResponse({"error": error}, status_code=400)
        if settings is None:
            return JSONResponse({"error": "settings not available"}, status_code=503)
        _apply_settings_data(settings, body)
        return {"ok": True, "name": body.get("name", "")}

    def _safe_scan_config() -> dict:
        # Never echo raw API keys back to the browser — expose only whether one
        # is set so the UI can show a "configured" state without leaking secrets.
        from dast.config import settings as _settings
        safe = dict(_scan_config)
        for key in ("anthropic_api_key", "openai_api_key"):
            if key in safe:
                safe[f"{key}_set"] = bool(safe[key])
                del safe[key]
        # Named model presets for the AI tab's dropdowns — sourced from
        # dast.config.settings so the UI never hardcodes model ARNs.
        safe["model_presets"] = _settings.model_presets
        return safe

    @router.get("/api/scan-config")
    async def get_scan_config():
        return _safe_scan_config()

    @router.post("/api/scan-config")
    async def set_scan_config(body: dict):
        import dast.scanners.active_checks as _ac
        if "workers" in body:
            n = max(1, min(20, int(body["workers"])))
            _scan_config["workers"] = n
            if ctx.runner is not None:
                ctx.runner._workers = n
                import asyncio as _asyncio
                ctx.runner._scan_sem = _asyncio.Semaphore(n)
        if "probe_concurrency" in body:
            n = max(1, min(20, int(body["probe_concurrency"])))
            _scan_config["probe_concurrency"] = n
            import asyncio as _asyncio
            _ac._PROBE_SEM = _asyncio.Semaphore(n)
        for flag in ("passive_enabled", "passive_ai", "active_enabled", "llm_planner",
                     "llm_validator", "discovery_llm_classify", "probe_diff"):
            if flag in body:
                _scan_config[flag] = bool(body[flag])
        if "confidence_threshold" in body:
            _scan_config["confidence_threshold"] = max(0.0, min(1.0, float(body["confidence_threshold"])))
        if "passive_aggressive_rules" in body:
            from dast.plugins.passive_scanner import set_aggressive_rules
            enabled = bool(body["passive_aggressive_rules"])
            _scan_config["passive_aggressive_rules"] = enabled
            set_aggressive_rules(enabled)
        if "model_id" in body:
            new_model = str(body["model_id"]).strip()
            _scan_config["model_id"] = new_model
            from dast.ai import bedrock_client as _bc
            _bc.set_active_model(new_model)
        if "fast_model_id" in body or "validation_model_id" in body:
            from dast.ai import bedrock_client as _bc2
            fast = str(body.get("fast_model_id", _scan_config.get("fast_model_id", ""))).strip()
            validation = str(body.get("validation_model_id", _scan_config.get("validation_model_id", ""))).strip()
            _scan_config["fast_model_id"] = fast
            _scan_config["validation_model_id"] = validation
            _bc2.set_tiered_models(fast=fast, validation=validation)
        _provider_keys = (
            "ai_provider", "anthropic_api_key", "anthropic_base_url",
            "openai_api_key", "openai_base_url",
        )
        if any(k in body for k in _provider_keys):
            from dast.ai import bedrock_client as _bc3
            # Empty string in the body means "clear"; a key absent from the body
            # keeps the current value. This lets the UI omit a key field it is
            # not touching (e.g. re-selecting provider without re-typing a key).
            for k in _provider_keys:
                if k in body:
                    _scan_config[k] = str(body[k] or "").strip()
            _bc3.set_provider(
                provider=_scan_config.get("ai_provider", ""),
                anthropic_api_key=_scan_config.get("anthropic_api_key", ""),
                anthropic_base_url=_scan_config.get("anthropic_base_url", ""),
                openai_api_key=_scan_config.get("openai_api_key", ""),
                openai_base_url=_scan_config.get("openai_base_url", ""),
            )
        if "scan_budget_seconds" in body:
            from dast.ai.coordinator import Coordinator as _Coord
            budget = max(30, min(900, int(body["scan_budget_seconds"])))
            _scan_config["scan_budget_seconds"] = budget
            _Coord.SCAN_BUDGET_SECONDS = float(budget)
        return {"ok": True, "config": _safe_scan_config()}

    return router

"""
AI routes: agents, activity log, app context, threat models,
auto-scan toggle, suggestions, session intelligence, service graph.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    store = ctx.store
    scan_queue = ctx.scan_queue
    scan_queue_state = ctx.scan_queue_state

    @router.get("/api/ai/agents")
    async def get_ai_agents():
        import os
        import yaml as _yaml
        import dast.agents  # noqa: F401
        from dast.ai.coordinator import Coordinator

        agents_info = []
        for attack_type, agent_cls in Coordinator._registry.items():
            inst = agent_cls()
            agents_info.append({
                "name": inst.name,
                "attack_type": attack_type,
                "description": inst.description,
            })

        payloads_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "payloads"))
        payload_files = []
        if os.path.isdir(payloads_dir):
            for fname in sorted(os.listdir(payloads_dir)):
                if not fname.endswith(".yaml"):
                    continue
                fpath = os.path.join(payloads_dir, fname)
                try:
                    with open(fpath) as f:
                        data = _yaml.safe_load(f) or {}
                    groups = list(data.get("payloads", {}).keys())
                    count = sum(len(v) for v in data.get("payloads", {}).values() if isinstance(v, list))
                    payload_files.append({"file": fname, "groups": groups, "count": count})
                except Exception:
                    pass

        ai_scanned = len([e for e in store._entries.values() if e.scan_result in ("vulnerable", "safe", "error")])
        ai_findings = [
            f for e in store._entries.values()
            for f in e.findings
            if f.get("validated_by") in ("ai", "pattern") and f.get("confirmed")
        ]
        passive_findings = [
            f for e in store._entries.values()
            for f in e.findings
            if f.get("validated_by") in ("passive", "passive+ai")
        ]
        ai_rejected = sum(
            1 for e in store._entries.values()
            if e.scan_result == "safe" and not any(
                f.get("validated_by") in ("ai", "pattern") for f in e.findings
            )
        )

        return {
            "agents": agents_info,
            "payload_files": payload_files,
            "stats": {
                "ai_scanned": ai_scanned,
                "ai_confirmed": len(ai_findings),
                "ai_rejected": ai_rejected,
                "passive_findings": len(passive_findings),
            },
        }

    @router.get("/api/ai/log")
    async def get_ai_log():
        from dast.ai.coordinator import _activity_log
        return {"events": list(_activity_log)}

    @router.get("/api/logs")
    async def get_system_logs():
        from dast.proxy.plugin_manager import _event_log
        return {"events": list(_event_log)}

    @router.post("/api/logs/clear")
    async def clear_system_logs():
        from dast.proxy.plugin_manager import _event_log
        _event_log.clear()
        return {"ok": True}

    @router.get("/api/ai/app-context")
    async def get_app_context():
        profiles = store.discovery_engine.all_app_profiles()
        return {host: p.to_dict() for host, p in profiles.items()}

    @router.get("/api/ai/threat-models")
    async def get_threat_models():
        models = store.discovery_engine.all_threat_models()
        return {host: m.to_dict() for host, m in models.items()}

    @router.get("/api/ai/auto-scan")
    async def get_auto_scan():
        return {"enabled": ctx.auto_scan_enabled[0]}

    @router.post("/api/ai/auto-scan")
    async def set_auto_scan(request: Request):
        body = await request.json()
        ctx.auto_scan_enabled[0] = bool(body.get("enabled", False))
        store.auto_scan_suggestions = ctx.auto_scan_enabled[0]
        if ctx.auto_scan_enabled[0] and scan_queue:
            queued = 0
            for s in store.active_suggestions:
                if s.get("status", "pending") != "pending":
                    continue
                host   = s.get("host", "")
                method = s.get("method", "GET").upper()
                path   = s.get("path", "/")
                best = None
                best_ts = 0.0
                for e in store.all_entries():
                    if e.host != host or e.method != method or e.source in ("agent", "imported"):
                        continue
                    ep = e.path.split("?")[0]
                    if ep == path or ep.startswith(path.rstrip("/") + "/"):
                        if e.ts > best_ts:
                            best = e
                            best_ts = e.ts
                if best and not best.queued_for_scan:
                    best.queued_for_scan = True
                    if scan_queue_state:
                        scan_queue_state.enqueue(best.id, best.method, best.url, best.host)
                    await scan_queue.put(best.id)
                    s["status"] = "queued"
                    queued += 1
            from dast.proxy.plugin_manager import log_event as _le
            if queued:
                _le("app-context", "info", f"Auto-scan enabled — queued {queued} pending suggestion(s)", source="agent")
        return {"enabled": ctx.auto_scan_enabled[0]}

    @router.get("/api/ai/suggestions")
    async def get_suggestions():
        settings = getattr(store, "_settings", None)
        suggestions = [
            s for s in store.active_suggestions
            if settings is None or settings.is_in_scope(
                f"https://{s.get('host','')}{s.get('path','/')}"
            )
        ]
        return {"suggestions": suggestions}

    @router.post("/api/ai/suggestions/scan-all")
    async def scan_all_suggestions():
        from dast.proxy.session_store import ProxyEntry
        import time, uuid
        queued = 0
        skipped_no_entry = 0
        pending = [s for s in store.active_suggestions if s.get("status", "pending") == "pending"]
        for s in pending:
            host        = s.get("host", "")
            method      = s.get("method", "GET").upper()
            path        = s.get("path", "/")
            attack_type = s.get("attack_type", "")
            parameter   = s.get("parameter", "")

            # Find the best matching real entry from HTTP history
            best = None
            best_ts = 0.0
            path_prefix = path.split(":")[0].split("{")[0].rstrip("/")
            for e in store.all_entries():
                if e.host != host or e.method != method or e.source in ("agent", "imported"):
                    continue
                ep = e.path.split("?")[0]
                if ep == path or (path_prefix and ep.startswith(path_prefix + "/")):
                    if e.ts > best_ts:
                        best = e
                        best_ts = e.ts

            # No matching entry — create a synthetic one so the scan can still run
            if best is None:
                if not host:
                    s["status"] = "skipped"
                    skipped_no_entry += 1
                    continue
                scheme = "https"
                synthetic_url = f"{scheme}://{host}{path}"
                # Borrow auth headers from any recent real request on the same host
                from dast.proxy.auth_headers import extract_auth_headers
                auth_headers = extract_auth_headers(store.all_entries(), host=host)
                synthetic_id = f"syn-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}"
                best = ProxyEntry(
                    id=synthetic_id,
                    method=method,
                    url=synthetic_url,
                    host=host,
                    path=path,
                    request_headers=auth_headers,
                    request_body=None,
                    source="imported",
                )
                with store._lock:
                    store._entries[synthetic_id] = best
                    store._order.append(synthetic_id)
                store._notify(best)

            hint = {"parameter": parameter, "payload": "", "attack_type": attack_type}
            existing = list(best.import_hints or [])
            if hint not in existing:
                best.import_hints = existing + [hint]

            # Always allow re-scan for suggestions (reset queued state if needed)
            if scan_queue:
                best.queued_for_scan = True
                best.scan_result = None
                if scan_queue_state:
                    scan_queue_state.enqueue(best.id, best.method, best.url, best.host)
                await scan_queue.put(best.id)

            s["status"] = "queued"
            queued += 1

        msg = f"Queued {queued} suggestion(s) for scanning"
        if skipped_no_entry:
            msg += f" ({skipped_no_entry} skipped — no host info)"
        return {"queued": queued, "message": msg}

    @router.post("/api/ai/suggestions/test")
    async def test_suggestion(request: Request):
        body = await request.json()
        host        = str(body.get("host", "")).strip()
        method      = str(body.get("method", "GET")).upper()
        path        = str(body.get("path", "/")).strip()
        attack_type = str(body.get("attack_type", "")).strip()
        parameter   = str(body.get("parameter", "")).strip()

        if not host or not path:
            return JSONResponse({"error": "host and path required"}, status_code=400)

        best = None
        best_ts = 0.0
        path_prefix = path.split(":")[0].split("{")[0].rstrip("/")
        for e in store.all_entries():
            if e.host != host or e.method != method or e.source in ("agent", "imported"):
                continue
            ep = e.path.split("?")[0]
            if ep == path or (path_prefix and ep.startswith(path_prefix + "/")):
                if e.ts > best_ts:
                    best = e
                    best_ts = e.ts

        # No matching entry — create a synthetic one
        if best is None:
            from dast.proxy.session_store import ProxyEntry
            import time, uuid
            scheme = "https"
            synthetic_url = f"{scheme}://{host}{path}"
            from dast.proxy.auth_headers import extract_auth_headers
            auth_headers = extract_auth_headers(store.all_entries(), host=host)
            synthetic_id = f"syn-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}"
            best = ProxyEntry(
                id=synthetic_id,
                method=method,
                url=synthetic_url,
                host=host,
                path=path,
                request_headers=auth_headers,
                request_body=None,
                source="imported",
            )
            with store._lock:
                store._entries[synthetic_id] = best
                store._order.append(synthetic_id)
            store._notify(best)

        hint = {"parameter": parameter, "payload": "", "attack_type": attack_type}
        existing = list(best.import_hints or [])
        if hint not in existing:
            best.import_hints = existing + [hint]

        if scan_queue:
            best.queued_for_scan = True
            best.scan_result = None
            if scan_queue_state:
                scan_queue_state.enqueue(best.id, best.method, best.url, best.host)
            await scan_queue.put(best.id)

        for s in store.active_suggestions:
            if s["host"] == host and s["path"] == path and s["attack_type"] == attack_type:
                s["status"] = "queued"
                break

        from dast.proxy.plugin_manager import log_event as _le
        _le("app-context", "info",
            f"Suggestion manually queued: {attack_type} on {method} {path}",
            url=best.url, source="agent")

        return {"ok": True, "entry_id": best.id, "url": best.url}

    @router.get("/api/ai/session-intelligence")
    async def get_session_intelligence():
        si = store.session_intelligence
        settings = getattr(store, "_settings", None)
        result = {}
        for host in si.all_hosts():
            if settings is not None and not settings.is_in_scope(f"https://{host}/"):
                continue
            intel = si.get(host)
            result[host] = {
                "confirmed_vulns": [
                    {"path": p, "param": param, "attack_types": types}
                    for (p, param), types in intel.confirmed_vulns.items()
                ],
                "effective_attack_types":   sorted(intel.effective_attack_types),
                "ineffective_attack_types": sorted(intel.ineffective_attack_types),
                "structural_errors": {
                    f"{p}[{op}]" if op else p: errors
                    for (p, op), errors in intel.structural_errors.items()
                },
                "waf_observations": [
                    {"payload_prefix": p, "signal": s, "attack_type": at}
                    for p, s, at in intel.waf_observations[-20:]
                ],
                "rate_limit_observed": intel.rate_limit_observed,
                "graphql_endpoints": sorted(intel.graphql_endpoints),
                "graphql_schemas_loaded": sorted(
                    url for url in store.graphql_schemas if host in url
                ),
            }
        return result

    # ── service graph ───────────────────────────────────────────────────

    @router.get("/api/service-graph")
    async def get_service_graph():
        return store.service_graph.to_dict()

    @router.post("/api/service-graph/merge")
    async def merge_service_graph(body: dict):
        host_a = str(body.get("host_a", "")).strip()
        host_b = str(body.get("host_b", "")).strip()
        if not host_a or not host_b:
            return JSONResponse({"error": "host_a and host_b required"}, status_code=400)
        gid = store.service_graph.merge(host_a, host_b, reason="manual")
        return {"ok": True, "group_id": gid}

    @router.post("/api/service-graph/split")
    async def split_service_graph(body: dict):
        host = str(body.get("host", "")).strip()
        if not host:
            return JSONResponse({"error": "host required"}, status_code=400)
        gid = store.service_graph.split(host)
        return {"ok": True, "group_id": gid}

    return router

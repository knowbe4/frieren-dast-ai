"""
Code analysis routes.

POST /api/code/analyze          — Phase 1: load + pattern scan (fast, no LLM)
POST /api/code/enrich/{id}      — Phase 2: AI endpoint extraction + hypotheses
GET  /api/code/status/{id}      — poll job status
GET  /api/code/results/{id}     — full results
GET  /api/code/search           — search files by path/keyword
GET  /api/code/list             — all past analyses
DELETE /api/code/{id}           — remove job
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_JOBS = 20
_MAX_SOURCES = 10


class AnalyzeRequest(BaseModel):
    sources: Optional[List[str]] = None
    source: Optional[str] = None   # legacy single-source compat
    gitlab_token: Optional[str] = ""
    target_url: Optional[str] = ""  # live target, e.g. https://app.example.com


def _resolve_sources(body: AnalyzeRequest) -> List[str]:
    """Return a deduplicated, non-empty list of sources from the request."""
    raw: List[str] = []
    if body.sources:
        raw = [s.strip() for s in body.sources if (s or "").strip()]
    elif body.source:
        raw = [body.source.strip()]
    seen: set = set()
    result: List[str] = []
    for s in raw:
        if s and s not in seen:
            seen.add(s)
            result.append(s)
    return result[:_MAX_SOURCES]


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()

    @router.post("/api/code/analyze")
    async def start_analysis(body: AnalyzeRequest) -> dict:
        from dast.code_analysis import run_analysis, create_analysis_id, _analyses

        sources = _resolve_sources(body)
        if not sources:
            return JSONResponse({"error": "at least one source is required"}, status_code=400)

        analysis_id = create_analysis_id()

        if len(_analyses) >= _MAX_JOBS:
            oldest = sorted(_analyses.keys(), key=lambda k: _analyses[k].started_at)
            for k in oldest[: len(_analyses) - _MAX_JOBS + 1]:
                _analyses.pop(k, None)

        target_url = (body.target_url or "").strip().rstrip("/")
        asyncio.create_task(
            run_analysis(analysis_id, sources, gitlab_token=body.gitlab_token or "",
                         target_url=target_url)
        )

        from dast.proxy.plugin_manager import log_event
        log_event(
            "code-analysis", "info",
            f"Loading {len(sources)} source(s): {', '.join(s[:60] for s in sources[:3])}",
            source="agent",
        )

        return {"analysis_id": analysis_id, "status": "scanning"}

    @router.post("/api/code/enrich/{analysis_id}")
    async def enrich_analysis(analysis_id: str) -> dict:
        from dast.code_analysis import enrich_with_ai, _analyses

        result = _analyses.get(analysis_id)
        if not result:
            return JSONResponse({"error": "analysis not found"}, status_code=404)
        if result.status not in ("scanned", "enriched"):
            return JSONResponse(
                {"error": f"Cannot enrich — current status is '{result.status}'"},
                status_code=400,
            )

        asyncio.create_task(enrich_with_ai(analysis_id))

        from dast.proxy.plugin_manager import log_event
        log_event(
            "code-analysis", "info",
            f"AI enrichment started for {analysis_id[:8]}",
            source="agent",
        )

        return {"analysis_id": analysis_id, "status": "enriching"}

    @router.get("/api/code/status/{analysis_id}")
    async def get_status(analysis_id: str) -> dict:
        from dast.code_analysis import _analyses
        result = _analyses.get(analysis_id)
        if not result:
            return JSONResponse({"error": "analysis not found"}, status_code=404)
        return {
            "analysis_id": result.analysis_id,
            "status": result.status,
            "sources": result.sources,
            "source": result.source,
            "files_scanned": result.files_scanned,
            "endpoints": len(result.endpoints),
            "pattern_matches": len(result.pattern_matches),
            "hypotheses": len(result.hypotheses),
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "error": result.error,
        }

    @router.get("/api/code/results/{analysis_id}")
    async def get_results(analysis_id: str) -> dict:
        from dast.code_analysis import _analyses
        result = _analyses.get(analysis_id)
        if not result:
            return JSONResponse({"error": "analysis not found"}, status_code=404)
        return result.to_dict()

    @router.get("/api/code/search")
    async def search_code(
        q: str = Query("", description="Search term — matches file paths and content"),
        analysis_id: Optional[str] = Query(None, description="Limit to a specific analysis"),
        limit: int = Query(20, ge=1, le=100),
    ) -> list:
        from dast.code_analysis import _analyses

        q = (q or "").strip().lower()
        if not q:
            return []

        results_to_search = (
            [_analyses[analysis_id]] if analysis_id and analysis_id in _analyses
            else list(_analyses.values())
        )

        matches = []
        for analysis in results_to_search:
            if not analysis._files:
                continue
            for file_dict in analysis._files:
                file_path = file_dict.get("path", "")
                content = file_dict.get("content", "")

                if q in file_path.lower() or q in content.lower():
                    # Find first matching line for preview
                    preview = ""
                    for line_num, line in enumerate(content.splitlines(), 1):
                        if q in line.lower():
                            preview = line.strip()[:200]
                            break

                    matches.append({
                        "analysis_id": analysis.analysis_id,
                        "file_path": file_path,
                        "language": file_dict.get("language", ""),
                        "preview": preview,
                        "content_length": len(content),
                    })

                if len(matches) >= limit:
                    break

            if len(matches) >= limit:
                break

        return matches

    @router.get("/api/code/file")
    async def get_file(
        analysis_id: str = Query(...),
        path: str = Query(...),
    ) -> dict:
        from dast.code_analysis import _analyses
        result = _analyses.get(analysis_id)
        if not result:
            return JSONResponse({"error": "analysis not found"}, status_code=404)
        for file_dict in result._files:
            if file_dict.get("path") == path:
                return {
                    "path": path,
                    "language": file_dict.get("language", ""),
                    "content": file_dict.get("content", ""),
                }
        return JSONResponse({"error": "file not found"}, status_code=404)

    @router.get("/api/code/list")
    async def list_analyses() -> list:
        from dast.code_analysis import _analyses
        return [
            {
                "analysis_id": r.analysis_id,
                "status": r.status,
                "sources": r.sources,
                "source": r.source,
                "files_scanned": r.files_scanned,
                "endpoints": len(r.endpoints),
                "pattern_matches": len(r.pattern_matches),
                "hypotheses": len(r.hypotheses),
                "started_at": r.started_at,
                "finished_at": r.finished_at,
            }
            for r in sorted(_analyses.values(), key=lambda r: -r.started_at)
        ]

    @router.post("/api/code/validate-hypothesis")
    async def validate_hypothesis(body: dict):
        """
        Queue a code-analysis hypothesis for active agent validation.

        Resolution strategy (in order):
          1. Exact path match in proxy history (any method, any host)
          2. Path prefix match (strips template params like /{id})
          3. Segment similarity — shared static path segments scored
          4. Same path depth on any host
          5. Most recently seen in-scope host (synthetic entry)

        Safety: destructive HTTP methods are downgraded to GET for probing.
        Truly dangerous paths (delete-account, logout, etc.) are blocked.
        """
        from dast.proxy.session_store import ProxyEntry
        from dast.proxy.plugin_manager import log_event
        import time, uuid

        method           = str(body.get("method", "GET")).upper()
        path             = str(body.get("path", "/")).strip()
        host             = str(body.get("host", "")).strip()
        vuln_type        = str(body.get("vuln_type", "")).strip()
        notes            = str(body.get("notes", "")).strip()
        suggested_payload = str(body.get("suggested_payload", "")).strip()
        analysis_id      = str(body.get("analysis_id", "")).strip()

        # Strip method prefix that the LLM sometimes includes in the path
        # e.g. "GET /Account/SignIn/AzureAD" → "/Account/SignIn/AzureAD"
        import re as _re
        _method_prefix = _re.match(
            r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/\S*)', path, _re.IGNORECASE
        )
        if _method_prefix:
            method = _method_prefix.group(1).upper()
            path   = _method_prefix.group(2)
        elif not path.startswith("/"):
            path = "/" + path

        if not path:
            return JSONResponse({"error": "path required"}, status_code=400)

        # ── Safety: downgrade destructive methods ────────────────────────
        # DELETE and PUT are not safe to probe with fuzzing payloads —
        # downgrade to GET so agents only read, never mutate or destroy.
        _DESTRUCTIVE = {"DELETE", "PUT", "PATCH"}
        probe_method = "GET" if method in _DESTRUCTIVE else method

        # ── Safety: block known-destructive path segments ────────────────
        _DANGEROUS_SEGMENTS = frozenset({
            "logout", "logoff", "log-out", "log_out", "signout", "sign-out",
            "sign_out", "end-session", "endsession", "revoke-session",
            "delete-account", "deleteaccount", "deactivate", "deactivate-account",
            "close-account", "closeaccount", "cancel-account", "cancelaccount",
            "unsubscribe", "reset-password", "resetpassword",
            "change-password", "changepassword", "drop", "truncate",
        })
        last_seg = path.rstrip("/").rsplit("/", 1)[-1].lower().split("?")[0]
        if last_seg in _DANGEROUS_SEGMENTS:
            return JSONResponse(
                {"error": f"Path '{path}' is destructive — blocked for safety"},
                status_code=400,
            )

        # ── URL resolution ────────────────────────────────────────────────
        # Priority order:
        # 1. target_url stored on the analysis job (set by user at load time or via PATCH)
        # 2. host hint explicitly passed in request body
        # 3. Proxy history — scored path match across all in-scope entries
        # 4. Imported entries from findings import (source="imported")
        # 5. Most recently seen in-scope entry (last resort — creates synthetic)
        from dast.code_analysis import _analyses as _code_analyses
        _analysis = _code_analyses.get(analysis_id) if analysis_id else None
        _analysis_target_url = (_analysis.target_url if _analysis else "").strip().rstrip("/")
        if _analysis_target_url:
            from urllib.parse import urlparse as _urlp
            _parsed = _urlp(_analysis_target_url)
            host = host or _parsed.netloc  # analysis target takes priority over empty hint

        # Strip template params to get the static prefix: /{id}/download → /download
        path_static_segments = [s for s in path.split("/") if s and not s.startswith("{")]
        path_prefix = path.split("{")[0].rstrip("/")
        has_template = "{" in path

        in_scope = [
            e for e in ctx.store.all_entries()
            if e.source not in ("agent", "out-of-scope") and e.host
        ]

        def _score(e) -> int:
            """Higher = better match. Returns 0 if no match at all."""
            ep = e.path.split("?")[0]
            ep_segs = [s for s in ep.split("/") if s]
            # Exact path match — best possible
            if ep == path:
                return 100
            # Prefix match (covers template paths like /{id}/download)
            if path_prefix and ep.startswith(path_prefix):
                return 80
            # All static segments of the hypothesis appear in the entry path
            if path_static_segments and all(s in ep_segs for s in path_static_segments):
                return 60
            # Any static segment matches
            matching = sum(1 for s in path_static_segments if s in ep_segs)
            if matching:
                return 20 + matching * 10
            # Same path depth (number of segments) — weakest signal
            if len(ep_segs) == len(path.strip("/").split("/")):
                return 5
            return 0

        # Pre-compute scores once to avoid calling _score() twice per entry
        _scored = [(e, _score(e)) for e in in_scope]
        candidates = sorted(
            [(e, s) for e, s in _scored if s > 0],
            key=lambda x: (x[1], x[0].ts),
            reverse=True,
        )

        # If a host hint was given, prefer it but don't require it
        best = None
        if host:
            host_match = next((e for e, _ in candidates if e.host == host), None)
            if host_match:
                best = host_match

        if best is None and candidates:
            best = candidates[0][0]

        resolved_host = best.host if best else None

        # Last resort resolution — priority order:
        # 1. Analysis target_url host (most explicit — user set this)
        # 2. Most recently seen in-scope proxy host
        if not resolved_host:
            if _analysis_target_url:
                from urllib.parse import urlparse as _urlp3
                resolved_host = _urlp3(_analysis_target_url).netloc or None
            if not resolved_host:
                recent = max(in_scope, key=lambda e: e.ts, default=None)
                if recent:
                    resolved_host = recent.host
            if not resolved_host:
                return JSONResponse(
                    {"error": "No in-scope entries found — browse the target first, or set a Target URL on the analysis"},
                    status_code=400,
                )

        # ── Validate the resolved host ────────────────────────────────────
        # A placeholder like "<sentry-admin-platform-host>" (from an unfilled Target
        # URL or a malformed entry) will never resolve — reject it up front instead
        # of queueing a scan that can only fail with a DNS error.
        if not _is_valid_host(resolved_host):
            return JSONResponse(
                {"error": f"Resolved host '{resolved_host}' is not a valid hostname — "
                          "set a real Target URL on the analysis (Code tab) before validating"},
                status_code=400,
            )

        # ── Build or reuse a proxy entry ─────────────────────────────────
        # If the best match IS the right path on the right host (or subdomain), reuse it.
        # Otherwise create a synthetic entry so the agent has a real URL to probe.
        # Base domain used for subdomain matching (e.g. browse was on sub.example.com,
        # target is example.com) — computed once, used both here and further below.
        _base_domain = ".".join(resolved_host.split(".")[-3:]) if resolved_host.count(".") >= 2 else resolved_host
        _host_matches = (
            best is not None
            and (best.host == resolved_host or best.host.endswith(_base_domain))
        )
        use_existing = _host_matches and _score(best) >= 60

        if use_existing:
            target_entry = best
            # Downgrade destructive method on reused entry too
            if target_entry.method in _DESTRUCTIVE:
                target_entry.method = probe_method
        else:
            # Collect auth headers from the most recent real request to this host
            # (also matches subdomains, via _base_domain above).
            from dast.proxy.auth_headers import extract_auth_headers
            auth_headers = extract_auth_headers(ctx.store.all_entries(), host=resolved_host)

            # Reconstruct the concrete path: replace template params with
            # realistic values extracted from a matching proxy entry if available
            concrete_path = path
            if has_template:
                if best:
                    best_segs = best.path.split("?")[0].split("/")
                    hyp_segs  = path.split("/")
                    if len(best_segs) == len(hyp_segs):
                        concrete_path = "/".join(
                            best_segs[i] if hyp_segs[i].startswith("{") else hyp_segs[i]
                            for i in range(len(hyp_segs))
                        )
                # If templates still remain (no match or segment count mismatch),
                # replace with realistic placeholder values.
                # Handle both {param} and URL-encoded %7Bparam%7D forms.
                import re as _re_tpl
                from urllib.parse import unquote as _unquote_tpl
                concrete_path = _unquote_tpl(concrete_path)  # decode %7B → {
                def _gen_placeholder(match):
                    name = match.group(1).lower()
                    if any(kw in name for kw in ("id", "uuid", "guid")):
                        return "507f1f77bcf86cd799439011"  # realistic Mongo ObjectId
                    if "user" in name or "name" in name:
                        return "testuser"
                    if "email" in name:
                        return "test@example.com"
                    return "test-value"
                concrete_path = _re_tpl.sub(r'\{([^}]+)\}', _gen_placeholder, concrete_path)

            # Resolve params for this endpoint from code analysis.
            # For POST/PUT/PATCH we build a skeleton JSON body so agents
            # can inject into body params — without this only GET probing works.
            import json as _json
            endpoint_params: list = []
            if _analysis:
                for ep in (_analysis.endpoints or []):
                    ep_p = ep.path if hasattr(ep, "path") else (ep.get("path", "") if isinstance(ep, dict) else "")
                    ep_m = ep.method if hasattr(ep, "method") else (ep.get("method", "") if isinstance(ep, dict) else "")
                    if ep_p == path and ep_m.upper() == method:
                        raw_params = ep.params if hasattr(ep, "params") else (ep.get("params", []) if isinstance(ep, dict) else [])
                        endpoint_params = [str(p) for p in (raw_params or []) if p]
                        break

            # Build body for non-GET methods.
            # Priority: 1) real body from a similar browse request, 2) skeleton from params
            synthetic_body: bytes | None = None
            if probe_method in ("POST", "PUT", "PATCH"):
                # Try to borrow body from a matching browse/proxy request (same path pattern)
                _path_prefix = concrete_path.rsplit("/", 1)[0] if "/" in concrete_path else concrete_path
                for e in reversed(ctx.store.all_entries()):
                    if e.source in ("agent", "imported"):
                        continue
                    if not (e.host == resolved_host or e.host.endswith(_base_domain)):
                        continue
                    if e.method != probe_method:
                        continue
                    ep = e.path.split("?")[0]
                    if ep == concrete_path or (_path_prefix and ep.startswith(_path_prefix)):
                        if e.request_body:
                            synthetic_body = e.request_body
                            # Also borrow content-type from the real request
                            real_ct = (e.request_headers or {}).get("content-type", "")
                            if real_ct:
                                auth_headers["content-type"] = real_ct
                            logger.debug("validate-hypothesis: borrowed body from browse entry",
                                         entry_id=e.id, path=ep, body_len=len(synthetic_body))
                            break

                # Fallback: skeleton body from code analysis params
                if not synthetic_body and endpoint_params:
                    body_params = [p for p in endpoint_params if not p.startswith(":") and p != "id"]
                    if body_params:
                        synthetic_body = _json.dumps(
                            {p: f"test_{p}" for p in body_params[:20]}
                        ).encode("utf-8")
                        auth_headers.setdefault("content-type", "application/json")

            synthetic_id = f"syn-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}"
            target_entry = ProxyEntry(
                id=synthetic_id,
                method=probe_method,
                url=f"https://{resolved_host}{concrete_path}",
                host=resolved_host,
                path=concrete_path,
                request_headers=auth_headers,
                request_body=synthetic_body,
                source="imported",
            )
            with ctx.store._lock:
                ctx.store._entries[synthetic_id] = target_entry
                ctx.store._order.append(synthetic_id)
            ctx.store._notify(target_entry)

        # ── Inject hypothesis context as scan hint ───────────────────────
        attack_type = _vuln_type_to_attack(vuln_type)
        combined_notes = notes
        if suggested_payload:
            combined_notes = f"{notes}\n\nSuggested payload: {suggested_payload}".strip()
        hint = {"parameter": "", "payload": combined_notes, "attack_type": attack_type}
        target_entry.import_hints = list(target_entry.import_hints or []) + [hint]
        target_entry.queued_for_scan = True
        target_entry.scan_result = None
        # Explicit user action ("Validate All" / "Validate") — bypass the scan-worker
        # dedup so each hypothesis actually runs. Two different hypotheses on the same
        # endpoint (e.g. open_redirect + ssrf on /start-consent) must both be tested,
        # and re-validation must not be skipped as a duplicate.
        target_entry.skip_dedup = True

        if ctx.scan_queue_state:
            ctx.scan_queue_state.enqueue(
                target_entry.id, target_entry.method, target_entry.url, target_entry.host
            )
        await ctx.scan_queue.put(target_entry.id)

        # Write scan_entry_id and scan_status back to the hypothesis so the Code tab
        # can show live validation status without polling a separate endpoint.
        queued_entry_ids = [target_entry.id]
        if analysis_id:
            from dast.code_analysis import _analyses as _ca
            _ar = _ca.get(analysis_id)
            if _ar:
                for _h in _ar.hypotheses:
                    if _h.endpoint_path == path and _h.vuln_type == vuln_type:
                        _h.scan_entry_id = target_entry.id
                        _h.scan_status = "queued"
                        break

                # Also queue against every extra_target_url — when multiple repos map to
                # multiple services, the hypothesis is valid across all of them.
                from urllib.parse import urlparse as _urlp_extra
                for extra_url in (_ar.extra_target_urls or []):
                    extra_url = extra_url.strip().rstrip("/")
                    if not extra_url:
                        continue
                    _extra_host = _urlp_extra(extra_url).netloc
                    if not _extra_host or _extra_host == resolved_host:
                        continue  # skip if same host as primary
                    extra_id = f"syn-{int(time.time()*1000)}-{uuid.uuid4().hex[:6]}"
                    extra_body: bytes | None = None
                    if probe_method in ("POST", "PUT", "PATCH") and target_entry.request_body:
                        extra_body = target_entry.request_body
                    extra_entry = ProxyEntry(
                        id=extra_id,
                        method=probe_method,
                        url=f"{extra_url}{concrete_path}",
                        host=_extra_host,
                        path=concrete_path,
                        request_headers=dict(target_entry.request_headers or {}),
                        request_body=extra_body,
                        source="imported",
                    )
                    extra_entry.import_hints = [hint]
                    extra_entry.queued_for_scan = True
                    extra_entry.scan_result = None
                    extra_entry.skip_dedup = True  # explicit user action — bypass dedup
                    with ctx.store._lock:
                        ctx.store._entries[extra_id] = extra_entry
                        ctx.store._order.append(extra_id)
                    ctx.store._notify(extra_entry)
                    if ctx.scan_queue_state:
                        ctx.scan_queue_state.enqueue(
                            extra_entry.id, extra_entry.method, extra_entry.url, extra_entry.host
                        )
                    await ctx.scan_queue.put(extra_entry.id)
                    queued_entry_ids.append(extra_id)
                    log_event(
                        "code", "info",
                        f"Code hypothesis queued (extra URL): {vuln_type} on {probe_method} {extra_entry.url}",
                        url=extra_entry.url, source="agent",
                    )

        downgraded = method in _DESTRUCTIVE
        log_event(
            "code", "info",
            f"Code hypothesis queued: {vuln_type} on {probe_method} {target_entry.url}"
            + (" [method downgraded from " + method + " — destructive probe blocked]" if downgraded else ""),
            url=target_entry.url, source="agent",
        )

        return {
            "ok": True,
            "entry_id": target_entry.id,
            "queued_entry_ids": queued_entry_ids,
            "method": probe_method,
            "path": target_entry.path,
            "host": resolved_host,
            "attack_type": attack_type,
            "method_downgraded": downgraded,
            "message": (
                f"Queued for AI validation on {len(queued_entry_ids)} target(s): "
                f"{resolved_host}{target_entry.path}"
                + (" (method downgraded to GET for safety)" if downgraded else "")
            ),
        }

    @router.get("/api/code/{analysis_id}/scan-status")
    async def get_hypothesis_scan_status(analysis_id: str) -> dict:
        """
        Return live scan status for every hypothesis in this analysis.
        Reads current entry state from the proxy store and syncs it back.
        """
        from dast.code_analysis import _analyses
        result = _analyses.get(analysis_id)
        if not result:
            return JSONResponse({"error": "analysis not found"}, status_code=404)

        statuses = []
        for h in result.hypotheses:
            entry_id = h.scan_entry_id
            scan_status = h.scan_status or ""
            findings = []

            if entry_id:
                entry = ctx.store.get_entry(entry_id)
                if entry:
                    # Sync live status from entry — check scan_result first because
                    # queued_for_scan is never reset to False after scan completion,
                    # so scan_result is the authoritative terminal state.
                    if entry.scan_result == "vulnerable":
                        scan_status = "confirmed"
                    elif entry.scan_result == "safe":
                        scan_status = "safe"
                    elif entry.scan_result == "error":
                        scan_status = "error"
                    elif entry.queued_for_scan and entry.scan_result is None:
                        scan_status = "scanning"
                    h.scan_status = scan_status
                    # Collect real findings (not stubs)
                    for f in entry.findings:
                        if f.get("title") and f.get("import_status") != "queued":
                            findings.append({
                                "title": f.get("title", ""),
                                "severity": f.get("severity", ""),
                                "validated_by": f.get("validated_by") or [],
                                "reasoning": f.get("reasoning", ""),
                                "confirmed": f.get("confirmed", False),
                                "import_status": f.get("import_status", ""),
                            })

            statuses.append({
                "endpoint_path": h.endpoint_path,
                "vuln_type": h.vuln_type,
                "severity": h.severity,
                "scan_entry_id": entry_id,
                "scan_status": scan_status,
                "findings": findings,
            })

        return {"analysis_id": analysis_id, "hypotheses": statuses}

    @router.patch("/api/code/{analysis_id}/target")
    async def set_analysis_target(analysis_id: str, body: dict) -> dict:
        """Set or update the live target URL(s) for an analysis job.
        Accepts target_url (primary) and extra_target_urls (list of additional URLs).
        Can be called any time — before or after importing findings."""
        from dast.code_analysis import _analyses
        result = _analyses.get(analysis_id)
        if not result:
            return JSONResponse({"error": "analysis not found"}, status_code=404)
        url = str(body.get("target_url", "")).strip().rstrip("/")
        result.target_url = url
        extra = body.get("extra_target_urls", [])
        if isinstance(extra, list):
            result.extra_target_urls = [str(u).strip().rstrip("/") for u in extra if u]
        return {"ok": True, "target_url": url, "extra_target_urls": result.extra_target_urls}

    @router.delete("/api/code/{analysis_id}")
    async def delete_analysis(analysis_id: str) -> dict:
        from dast.code_analysis import _analyses
        if analysis_id not in _analyses:
            return JSONResponse({"error": "analysis not found"}, status_code=404)
        _analyses.pop(analysis_id)
        return {"ok": True}

    return router


import re as _host_re

# A resolvable hostname: labels of letters/digits/hyphens separated by dots, or a
# bare host[:port]. Rejects placeholders ("<...>"), whitespace, and empty strings.
_VALID_HOST_RE = _host_re.compile(
    r"^(?=.{1,253}$)"                       # overall length
    r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})?\.)*"  # optional sub-labels
    r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})?"         # final label
    r"(?::\d{1,5})?$"                       # optional :port
)


def _is_valid_host(host: str) -> bool:
    """True if host is a syntactically valid hostname[:port] (not a placeholder)."""
    if not host or any(c in host for c in "<>{} \t"):
        return False
    return bool(_VALID_HOST_RE.match(host))


def _vuln_type_to_attack(vuln_type: str) -> str:
    """Map a hypothesis vuln_type string to the closest agent attack_type."""
    vl = vuln_type.lower()
    if any(x in vl for x in ("sql", "inject", "sqli")):
        return "sqli"
    if any(x in vl for x in ("xss", "cross-site script")):
        return "xss"
    if any(x in vl for x in ("ssrf", "server-side request")):
        return "ssrf"
    if any(x in vl for x in ("lfi", "path traversal", "file read", "directory traversal")):
        return "file_read"
    if any(x in vl for x in ("auth", "bypass", "unauthori", "privilege")):
        return "auth_bypass"
    if any(x in vl for x in ("idor", "object reference", "access control")):
        return "idor"
    if any(x in vl for x in ("csrf",)):
        return "csrf"
    if any(x in vl for x in ("ssti", "template inject")):
        return "ssti"
    if any(x in vl for x in ("business", "logic", "workflow", "mass assign")):
        return "business_logic"
    if any(x in vl for x in ("redirect", "open redirect", "unvalidated redirect")):
        return "open_redirect"
    if any(x in vl for x in ("prototype", "pollution", "proto pollution")):
        return "prototype_pollution"
    if any(x in vl for x in ("host header", "host injection", "http host")):
        return "host_header_injection"
    return "discovery"

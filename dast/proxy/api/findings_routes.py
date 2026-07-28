"""
Findings routes: import (AI-powered), SARIF export.
"""

from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    store = ctx.store
    scan_queue = ctx.scan_queue
    scan_queue_state = ctx.scan_queue_state
    import_jobs = ctx.import_findings_jobs

    @router.post("/api/findings/import")
    async def import_findings_api(request: Request):
        body = await request.json()
        content = str(body.get("content", "")).strip()
        target_hosts: list = body.get("target_hosts") or []
        base_url = str(body.get("base_url", "")).strip()

        if not content:
            return JSONResponse({"error": "content is required"}, status_code=400)

        job_id = str(uuid.uuid4())
        import_jobs[job_id] = {"status": "parsing", "progress": None, "result": None, "error": None}
        asyncio.ensure_future(_run_import_job(job_id, content, target_hosts, base_url))
        return {"job_id": job_id}

    @router.get("/api/findings/import/{job_id}")
    async def import_findings_status(job_id: str):
        job = import_jobs.get(job_id)
        if not job:
            return JSONResponse({"error": "unknown job_id"}, status_code=404)
        if job["status"] == "error":
            return JSONResponse({"error": job["error"]}, status_code=500)
        if job["status"] == "done":
            return job["result"]
        return {"status": job["status"], "progress": job.get("progress")}

    async def _run_import_job(job_id: str, content: str, target_hosts: list, base_url: str) -> None:
        import re as _re
        import json as _json
        import time as _time
        from dast.importers.dast_importer import (
            build_request_body,
            build_request_headers,
            build_stub_finding,
            parse_findings,
        )
        from dast.proxy.session_store import ProxyEntry
        from urllib.parse import urlparse

        job = import_jobs[job_id]
        try:
            loop = asyncio.get_running_loop()

            schemas = dict(store.graphql_schemas) if store.graphql_schemas else None
            findings = await loop.run_in_executor(
                None, lambda: parse_findings(content, graphql_schemas=schemas)
            )
        except Exception as exc:
            logger.error("Import findings parse failed", job_id=job_id, error=str(exc))
            job["status"] = "error"
            job["error"] = str(exc)
            return

        if not findings:
            job["status"] = "done"
            job["result"] = {
                "ok": True,
                "parsed": 0,
                "scan_queued": 0,
                "message": "No findings could be parsed from the provided content",
            }
            return

        job["status"] = "storing"
        job["progress"] = {"done": 0, "total": len(findings)}

        def _extract_operation_from_body(body_bytes):
            if not body_bytes:
                return ""
            try:
                data = _json.loads(body_bytes)
                if isinstance(data, dict) and "query" in data:
                    op = data.get("operationName")
                    if op:
                        return str(op)
                    m = _re.search(r'\b(query|mutation|subscription)\s+(\w+)', data.get("query", ""))
                    if m:
                        return f"{m.group(1)} {m.group(2)}"
            except Exception:
                pass
            return ""

        _AUTH_HEADERS = frozenset({
            "cookie", "authorization", "x-csrf-token", "x-xsrf-token",
            "x-requested-with", "x-auth-token", "x-api-key",
        })

        def _best_auth_headers_for_host(host: str) -> dict:
            best: dict = {}
            with store._lock:
                for eid in reversed(store._order):
                    e = store._entries.get(eid)
                    if not e or e.host != host:
                        continue
                    if e.source in ("imported", "agent"):
                        continue
                    for k, v in e.request_headers.items():
                        if k.lower() in _AUTH_HEADERS:
                            best[k.lower()] = v
                    if best:
                        return best

            session_cookies = store.get_cookies_for_host(host)
            if session_cookies:
                cookie_header = "; ".join(
                    f"{c['name']}={c['value']}" for c in session_cookies if c.get("name")
                )
                if cookie_header:
                    best["cookie"] = cookie_header
            return best

        async def _store_and_queue(url_to_use, nf, req_headers, req_body, stub_finding, hints=None):
            parsed_url = urlparse(url_to_use)
            host = parsed_url.netloc or nf.host_hint or ""
            path = parsed_url.path or nf.path or "/"
            # No resolvable host yet — park as a pending finding.
            # When a real proxy entry with a matching path arrives, it will be tested.
            if not host or host == "unknown":
                pending = {
                    "path": nf.path or path or "/",
                    "method": nf.method or "GET",
                    "hints": hints or [],
                    "stub": stub_finding,
                }
                store.pending_import_findings.append(pending)
                logger.info(
                    "Import finding parked — waiting for matching proxy entry",
                    path=pending["path"], method=pending["method"],
                )
                return None, False

            headers_with_auth = dict(req_headers)
            headers_with_auth.update(_best_auth_headers_for_host(host))

            entry_id = f"import-{int(_time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
            entry = ProxyEntry(
                id=entry_id,
                method=nf.method,
                url=url_to_use,
                host=host,
                path=path,
                request_headers=headers_with_auth,
                request_body=req_body,
                response_status=None,
                source="imported",
                import_hints=hints or [],
            )
            if stub_finding:
                # Always add the stub so _update_import_stubs() can update it after scan.
                # The stub has import_status="queued" and confirmed=False — it will be
                # updated to confirmed/unconfirmed once the active scan completes.
                entry.findings.append(stub_finding)

            with store._lock:
                store._entries[entry_id] = entry
                store._order.append(entry_id)

            await ctx.broadcast(entry)

            if scan_queue and url_to_use.startswith("http"):
                entry.queued_for_scan = True
                operation = _extract_operation_from_body(req_body)
                if scan_queue_state:
                    scan_queue_state.enqueue(entry_id, entry.method, entry.url, entry.host, operation=operation)
                await scan_queue.put(entry_id)
                return entry_id, True

            return entry_id, False

        def _is_real_url(u):
            if not u or not u.startswith("http"):
                return False
            return not _re.search(r'[|<>{}%]\w+[|<>{}%]', u)

        def _candidate_bases():
            from collections import Counter
            from urllib.parse import urlparse as _up

            if target_hosts:
                return [h.rstrip("/") for h in target_hosts if h.startswith("http")]

            counts: Counter = Counter()
            for e in store.in_scope_entries():
                if e.source == "imported":
                    continue
                p = _up(e.url)
                if p.scheme and p.netloc:
                    counts[f"{p.scheme}://{p.netloc}"] += 1
            known = [h for h, _ in counts.most_common()]
            if base_url:
                base = base_url.rstrip("/")
                if base not in known:
                    known.insert(0, base)
            return known

        candidate_bases = _candidate_bases()

        def _candidate_paths_for(inferred_path: str, method: str) -> list:
            from urllib.parse import urlparse as _up

            path_tail = inferred_path.lstrip("/")
            is_generic = "/" not in path_tail

            if not is_generic:
                return [inferred_path]

            matched: list = []
            seen_paths: set = set()
            for e in store.in_scope_entries():
                if e.source in ("imported", "agent"):
                    continue
                if e.method != method:
                    continue
                ep = _up(e.url).path
                if ep and (ep == inferred_path or ep.endswith("/" + path_tail)):
                    if ep not in seen_paths:
                        seen_paths.add(ep)
                        matched.append(ep)

            return matched if matched else [inferred_path]

        stored_ids = []
        scan_queued = 0

        try:
            for i, nf in enumerate(findings):
                req_headers = build_request_headers(nf)
                req_body = build_request_body(nf)
                stub = build_stub_finding(nf)

                import_hints = []
                if nf.parameter or nf.payload:
                    import_hints.append({
                        "parameter": nf.parameter,
                        "payload": nf.payload,
                        "attack_type": nf.attack_type,
                    })

                inferred_path = nf.path or "/"
                if not inferred_path.startswith("/"):
                    inferred_path = "/" + inferred_path

                doc_url = nf.url if _is_real_url(nf.url) else ""

                urls_to_test: list = []
                seen_urls: set = set()

                def _add(u):
                    if u and u not in seen_urls:
                        seen_urls.add(u)
                        urls_to_test.append(u)

                real_paths = _candidate_paths_for(inferred_path, nf.method)
                for base in candidate_bases:
                    for rpath in real_paths:
                        _add(base.rstrip("/") + rpath)

                _add(doc_url)

                if not urls_to_test:
                    # No known host yet — park the finding to be tested when a matching entry appears
                    store.pending_import_findings.append({
                        "path": inferred_path,
                        "method": nf.method or "GET",
                        "hints": import_hints,
                        "stub": stub,
                    })
                    logger.info(
                        "Import finding parked — no matching proxy host yet",
                        path=inferred_path, method=nf.method,
                    )
                    job["progress"]["done"] = i + 1
                    continue

                for url_to_use in urls_to_test:
                    eid, queued = await _store_and_queue(url_to_use, nf, req_headers, req_body, stub, hints=import_hints)
                    if eid is None:
                        continue
                    stored_ids.append(eid)
                    if queued:
                        scan_queued += 1
                job["progress"]["done"] = i + 1
        except Exception as exc:
            logger.error("Import findings storing failed", job_id=job_id, error=str(exc))
            job["status"] = "error"
            job["error"] = str(exc)
            return

        pending_count = len(store.pending_import_findings)
        job["status"] = "done"
        job["result"] = {
            "ok": True,
            "parsed": len(findings),
            "scan_queued": scan_queued,
            "scan_pending": pending_count,
            "entry_ids": stored_ids,
            "message": (
                f"{scan_queued} queued for scan."
                + (f" {pending_count} parked — will test automatically when matching URLs appear in proxy." if pending_count else "")
            ),
        }

    @router.delete("/api/findings/{entry_id}/{finding_index}")
    async def delete_finding(entry_id: str, finding_index: int):
        ok = store.remove_finding(entry_id, finding_index)
        if not ok:
            return JSONResponse({"error": "not found"}, status_code=404)
        return {"ok": True}

    @router.post("/api/findings/{entry_id}/{finding_index}/dismiss")
    async def dismiss_finding(entry_id: str, finding_index: int):
        entry = store.get_entry(entry_id)
        if not entry:
            return JSONResponse({"error": "entry not found"}, status_code=404)
        findings = entry.findings or []
        if finding_index < 0 or finding_index >= len(findings):
            return JSONResponse({"error": "finding not found"}, status_code=404)
        findings[finding_index]["dismissed"] = True
        store._notify(entry)
        return {"ok": True}

    @router.post("/api/findings/{entry_id}/{finding_index}/restore")
    async def restore_finding(entry_id: str, finding_index: int):
        entry = store.get_entry(entry_id)
        if not entry:
            return JSONResponse({"error": "entry not found"}, status_code=404)
        findings = entry.findings or []
        if finding_index < 0 or finding_index >= len(findings):
            return JSONResponse({"error": "finding not found"}, status_code=404)
        findings[finding_index]["dismissed"] = False
        store._notify(entry)
        return {"ok": True}

    @router.get("/api/export/sarif")
    async def export_sarif():
        from dast.report.sarif import build_sarif
        import json as _json
        sarif_doc = build_sarif(store.in_scope_entries())
        content = _json.dumps(sarif_doc, indent=2, ensure_ascii=False)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=dast-ai-findings.sarif"},
        )

    return router

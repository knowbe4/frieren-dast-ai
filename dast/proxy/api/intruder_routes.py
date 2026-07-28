"""
Intruder routes: run, results, stop.
"""

from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    # _intruder_jobs lives on ctx.intruder_jobs (shared with other routers if needed)
    intruder_jobs = ctx.intruder_jobs
    scan_config = ctx._scan_cfg

    @router.post("/api/intruder/run")
    async def intruder_run(request: Request):
        import re as _re
        import httpx as _httpx

        data = await request.json()
        method        = str(data.get("method", "GET")).upper()
        url           = str(data.get("url", "")).strip()
        headers_raw   = str(data.get("headers_raw") or "")
        body_template = str(data.get("body") or "")
        attack_types  = list(data.get("attack_types") or [])
        ai_mode       = str(data.get("ai_mode", "full"))
        payload_src   = str(data.get("payload_source", "yaml"))
        custom_raw    = str(data.get("custom_payloads") or "")

        if not url:
            return JSONResponse({"error": "url is required"}, status_code=400)

        marker_match = _re.search(r'§([^§]*)§', body_template)
        param_name    = "injection_point"
        param_value   = ""
        if marker_match:
            param_value = marker_match.group(1)
            before_marker = body_template[:marker_match.start()]
            json_key = _re.search(r'"([^"]+)"\s*:\s*"?$', before_marker)
            if json_key:
                param_name = json_key.group(1)

        payloads: list[str] = []
        if payload_src == "custom":
            payloads = [line.strip() for line in custom_raw.splitlines() if line.strip()]
        elif payload_src == "yaml":
            from dast.payloads.loader import get_all_payloads as _gap
            _seen: set = set()
            for atype in attack_types:
                try:
                    for p in _gap(atype):
                        if p not in _seen:
                            _seen.add(p)
                            payloads.append(p)
                except Exception:
                    pass
        elif payload_src == "llm":
            try:
                from dast.ai import bedrock_client as _bc
                _llm_prompt = (
                    f"Generate 30 varied attack payloads targeting: {', '.join(attack_types)}. "
                    f"The injection parameter is '{param_name}' with baseline value '{param_value}'. "
                    "Output a JSON array of strings only, no explanation."
                )
                import re as _re2
                import json as _json
                _raw = await asyncio.to_thread(
                    _bc.invoke,
                    system="You are a security testing payload generator.",
                    user=_llm_prompt,
                )
                _arr_match = _re2.search(r'\[[\s\S]*\]', _raw)
                if _arr_match:
                    payloads = _json.loads(_arr_match.group(0))
                if not payloads:
                    payloads = ["<script>alert(1)</script>", "' OR 1=1--", "../../../etc/passwd"]
            except Exception:
                from dast.payloads.loader import get_all_payloads as _gap2
                _seen2: set = set()
                for atype in attack_types:
                    try:
                        for p in _gap2(atype):
                            if p not in _seen2:
                                _seen2.add(p)
                                payloads.append(p)
                    except Exception:
                        pass

        if not payloads:
            return JSONResponse({"error": "No payloads available for the selected configuration."}, status_code=400)

        job_id = str(uuid.uuid4())
        job: dict = {
            "status": "running",
            "progress": {"done": 0, "total": len(payloads)},
            "results": [],
            "cancel": False,
        }
        intruder_jobs[job_id] = job

        headers: dict = {}
        for line in headers_raw.splitlines():
            idx = line.find(":")
            if idx > 0:
                headers[line[:idx].strip()] = line[idx + 1:].strip()
        for hop in ("host", "content-length", "transfer-encoding", "connection", "accept-encoding"):
            headers.pop(hop, None)
            headers.pop(hop.title(), None)

        _error_sigs = [
            r"sql syntax",
            r"you have an error in your sql",
            r"ORA-\d+",
            r"mysql_fetch",
            r"unclosed quotation",
            r"syntax error.*near",
            r"Warning.*mysql",
            r"stack trace",
            r"Traceback \(most recent call last\)",
            r"<b>Fatal error</b>",
            r"System\.Exception",
            r"eval\(\) error",
        ]

        async def _run_job() -> None:
            import re as _re3
            from dast.scanners.active_checks import CheckTarget as _CT, run_active_checks as _rac

            if ai_mode in ("full", "fuzzing"):
                try:
                    import json as _json2
                    _json2.loads(body_template.replace(f"§{param_value}§", param_value))
                    _loc = "body_graphql" if '"query"' in body_template else "body"
                except Exception:
                    _loc = "body"

                _model_id = scan_config.get("model_id")
                _conf_thr = scan_config.get("confidence_threshold", 0.5)
                if ai_mode == "fuzzing":
                    _conf_thr = 1.0

            async with _httpx.AsyncClient(
                follow_redirects=False,
                timeout=_httpx.Timeout(30.0),
                verify=False,
            ) as _client:
                for idx, payload in enumerate(payloads):
                    if job["cancel"]:
                        job["status"] = "stopped"
                        return

                    if marker_match:
                        body_with_payload = body_template.replace(f"§{param_value}§", payload, 1)
                    else:
                        body_with_payload = payload if not body_template else body_template

                    import time as _time2
                    t0 = _time2.monotonic()
                    status_code = 0
                    length_bytes = 0
                    resp_text = ""
                    hit = False
                    finding_title = None

                    try:
                        resp = await _client.request(
                            method, url,
                            headers=headers,
                            content=body_with_payload.encode("utf-8") if body_with_payload else None,
                        )
                        elapsed_ms = int((_time2.monotonic() - t0) * 1000)
                        status_code  = resp.status_code
                        length_bytes = len(resp.content)
                        try:
                            resp_text = resp.text[:4000]
                        except Exception:
                            resp_text = ""

                        if status_code >= 500:
                            hit = True
                        elif elapsed_ms >= 4500:
                            hit = True
                        else:
                            for sig in _error_sigs:
                                if _re3.search(sig, resp_text, _re3.IGNORECASE):
                                    hit = True
                                    break

                    except Exception as exc:
                        elapsed_ms = int((_time2.monotonic() - t0) * 1000)
                        resp_text  = str(exc)

                    if ai_mode in ("full", "fuzzing") and hit:
                        try:
                            _target = _CT(
                                method=method,
                                url=url,
                                headers=dict(headers),
                                body=body_with_payload or None,
                                params=[{
                                    "name": param_name,
                                    "location": _loc,
                                    "value": payload,
                                }],
                            )
                            _findings = await _rac(
                                _target,
                                model_id=_model_id,
                                confidence_threshold=_conf_thr,
                            )
                            if _findings:
                                finding_title = _findings[0].title
                                hit = True
                        except Exception:
                            pass

                    job["results"].append({
                        "n":            idx + 1,
                        "payload":      payload,
                        "status_code":  status_code,
                        "duration_ms":  elapsed_ms,
                        "length_bytes": length_bytes,
                        "hit":          hit,
                        "finding_title": finding_title,
                    })
                    job["progress"]["done"] = idx + 1

            job["status"] = "done"

        asyncio.ensure_future(_run_job())
        return {"job_id": job_id, "total": len(payloads)}

    @router.get("/api/intruder/results/{job_id}")
    async def intruder_results(job_id: str):
        job = intruder_jobs.get(job_id)
        if not job:
            return JSONResponse({"error": "unknown job_id"}, status_code=404)
        return {
            "status":   job["status"],
            "progress": job["progress"],
            "results":  job["results"],
        }

    @router.post("/api/intruder/stop/{job_id}")
    async def intruder_stop(job_id: str):
        job = intruder_jobs.get(job_id)
        if not job:
            return JSONResponse({"error": "unknown job_id"}, status_code=404)
        job["cancel"] = True
        return {"ok": True}

    return router

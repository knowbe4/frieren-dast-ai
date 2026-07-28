"""
HackerOne report validation routes.

POST /api/h1/validate           — submit a report (text + optional images); returns job_id
GET  /api/h1/status/{job_id}    — poll validation status
POST /api/h1/open-browser/{job_id} — open an auth browser; user logs in manually
POST /api/h1/browser-ready/{job_id} — signal login done; provides collected cookies
POST /api/h1/cancel/{job_id}    — cancel a running job
"""

from __future__ import annotations

import asyncio
import base64
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# In-memory job store (rolling 50 jobs)
_MAX_JOBS = 50

def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    _jobs: Dict[str, dict] = {}

    def _gc_jobs() -> None:
        if len(_jobs) > _MAX_JOBS:
            oldest = sorted(_jobs.keys(), key=lambda k: _jobs[k].get("created_at", 0))
            for k in oldest[:len(_jobs) - _MAX_JOBS]:
                _jobs.pop(k, None)

    def _job_dict(job_id: str) -> dict:
        j = _jobs.get(job_id)
        if not j:
            return {}
        result = j.get("result")
        return {
            "job_id":      job_id,
            "status":      j.get("status", "pending"),
            "vuln_type":   j.get("vuln_type", ""),
            "proof_url":   j.get("proof_url", ""),
            "payload":     j.get("payload", ""),
            "target_url":  j.get("target_url", ""),
            "summary":     j.get("summary", ""),
            "created_at":  j.get("created_at", 0),
            "finished_at": j.get("finished_at"),
            "result": {
                "status":        result.status if result else None,
                "evidence":      result.evidence if result else None,
                "reasoning":     result.reasoning if result else None,
                "raw_request":   result.raw_request if result else None,
                "raw_response":  result.raw_response if result else None,
                "checks_run":    result.checks_run if result else [],
                "duration_ms":   result.duration_ms if result else 0,
                "screenshot_b64": result.screenshot_b64 if result else "",
            } if result else None,
        }

    @router.post("/api/h1/validate")
    async def submit_report(body: dict):
        """
        Submit a HackerOne report for validation.

        Body fields:
          report_text  — raw report content (required)
          images       — list of base64-encoded image strings (optional)
          override_url — override proof URL if AI extraction is wrong (optional)
          override_domain — override target domain for DNS checks (optional)
        """
        report_text = (body.get("report_text") or "").strip()
        if not report_text:
            return JSONResponse({"error": "report_text required"}, status_code=400)
        if len(report_text) > 50_000:
            return JSONResponse({"error": "report_text too large (max 50 000 chars)"}, status_code=400)

        override_url = (body.get("override_url") or "").strip()
        if override_url:
            from dast.hackerone.validator import _is_safe_url
            if not _is_safe_url(override_url):
                return JSONResponse(
                    {"error": "override_url must be a public http/https URL"},
                    status_code=400,
                )

        override_domain = (body.get("override_domain") or "").strip()
        if override_domain:
            import re as _re
            if not _re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{1,251}[a-zA-Z0-9]$', override_domain):
                return JSONResponse(
                    {"error": "override_domain must be a valid hostname"},
                    status_code=400,
                )

        raw_images: list = body.get("images") or []
        if not isinstance(raw_images, list):
            return JSONResponse({"error": "images must be a list"}, status_code=400)
        _MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB per image
        images_b64: list[str] = []
        for img in raw_images[:4]:
            if not isinstance(img, str):
                continue
            if len(img) > (_MAX_IMAGE_BYTES * 4 // 3 + 16):
                continue  # silently skip oversized images
            images_b64.append(img)

        job_id = str(uuid.uuid4())[:12]
        _jobs[job_id] = {
            "status": "parsing",
            "created_at": time.time(),
            "vuln_type": "",
            "proof_url": "",
            "payload": "",
            "target_url": "",
            "summary": "",
            "result": None,
            "_browser_event": None,
            "_browser_cookies": None,
        }
        _gc_jobs()

        asyncio.create_task(
            _run_validation(
                job_id, report_text, override_url, override_domain,
                images_b64, ctx.proxy_port, _jobs,
            )
        )

        return {"job_id": job_id, "status": "parsing"}

    @router.get("/api/h1/status/{job_id}")
    async def get_status(job_id: str):
        if job_id not in _jobs:
            return JSONResponse({"error": "job not found"}, status_code=404)
        return _job_dict(job_id)

    @router.post("/api/h1/open-browser/{job_id}")
    async def open_browser(job_id: str):
        """Open a browser window so the user can authenticate manually."""
        if job_id not in _jobs:
            return JSONResponse({"error": "job not found"}, status_code=404)
        job = _jobs[job_id]
        if job.get("status") != "needs_auth":
            return JSONResponse(
                {"error": "job is not in needs_auth state, current: " + job.get("status", "?")},
                status_code=400,
            )

        target_url = job.get("proof_url") or job.get("target_url") or ""

        if not ctx.browse_queue:
            return JSONResponse({"error": "browse not available"}, status_code=503)

        from dast.hackerone.validator import _is_safe_url
        if not _is_safe_url(target_url):
            return JSONResponse({"error": "No valid public URL to open"}, status_code=400)

        result: dict = {}
        done = asyncio.Event()

        def result_cb(session_id: str) -> None:
            result["session_id"] = session_id
            done.set()

        await ctx.browse_queue.put({
            "action": "start",
            "url": target_url,
            "result_cb": result_cb,
        })
        try:
            await asyncio.wait_for(done.wait(), timeout=15)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "browser failed to open"}, status_code=500)

        job["status"] = "awaiting_auth"
        return {"ok": True, "session_id": result.get("session_id"), "target_url": target_url}

    @router.post("/api/h1/browser-ready/{job_id}")
    async def browser_ready(job_id: str, body: dict):
        """
        Signal that the user has authenticated. Provide cookies so the
        validator can replay the proof URL with a valid session.

        Body: {"cookies": {"name": "value", ...}}
        """
        if job_id not in _jobs:
            return JSONResponse({"error": "job not found"}, status_code=404)
        job = _jobs[job_id]

        raw_cookies = body.get("cookies") or {}
        if not isinstance(raw_cookies, dict):
            return JSONResponse({"error": "cookies must be an object"}, status_code=400)
        from dast.hackerone.validator import _sanitise_cookies
        cookies = _sanitise_cookies(raw_cookies)
        job["_browser_cookies"] = cookies
        job["status"] = "validating"

        event: asyncio.Event = job.get("_browser_event")
        if event:
            event.set()

        return {"ok": True}

    @router.post("/api/h1/cancel/{job_id}")
    async def cancel_job(job_id: str):
        if job_id not in _jobs:
            return JSONResponse({"error": "job not found"}, status_code=404)
        task: Optional[asyncio.Task] = _jobs[job_id].get("_task")
        if task and not task.done():
            task.cancel()
        _jobs[job_id]["status"] = "cancelled"
        return {"ok": True}

    @router.get("/api/h1/jobs")
    async def list_jobs():
        return [_job_dict(jid) for jid in sorted(_jobs.keys(), key=lambda k: -_jobs[k].get("created_at", 0))]

    return router


async def _run_validation(
    job_id: str,
    report_text: str,
    override_url: str,
    override_domain: str,
    images_b64: list[str],
    proxy_port: int,
    jobs: Dict[str, Any],
) -> None:
    from dast.proxy.plugin_manager import log_event
    job = jobs[job_id]

    try:
        # ── Parse ────────────────────────────────────────────────────────
        job["status"] = "parsing"
        log_event("h1-validator", "info", f"Parsing H1 report [{job_id}]", source="agent")
        loop = asyncio.get_running_loop()
        from dast.hackerone.parser import parse_report
        report = await loop.run_in_executor(None, lambda: parse_report(report_text))

        # Apply overrides
        if override_url:
            report.proof_url = override_url
            from urllib.parse import urlparse as _up
            p = _up(override_url)
            report.target_url = f"{p.scheme}://{p.netloc}{p.path}"
        if override_domain:
            report.target_url = override_domain

        # LLM may have detected dns_takeover from body even without a URL
        if not report.vuln_type or report.vuln_type == "unknown":
            report.vuln_type = _infer_vuln_type_from_text(report_text)

        job.update({
            "vuln_type":  report.vuln_type,
            "proof_url":  report.proof_url,
            "payload":    report.payload,
            "target_url": report.target_url,
            "summary":    report.summary or _first_line(report_text),
        })

        log_event(
            "h1-validator", "info",
            f"Report parsed: type={report.vuln_type}, url={report.proof_url or '(none)'}",
            url=report.proof_url, source="agent",
        )

        # ── Analyse images with LLM if provided ──────────────────────────
        if images_b64:
            job["status"] = "analysing_images"
            image_summary = await _analyse_images(images_b64, report_text)
            if image_summary:
                report.summary = (report.summary or "") + " | Image evidence: " + image_summary
                job["summary"] = report.summary

        # ── Validate ─────────────────────────────────────────────────────
        job["status"] = "validating"
        from dast.hackerone.validator import validate
        result = await validate(report, proxy_port=proxy_port)

        job["result"] = result

        if result.status == "needs_auth":
            job["status"] = "needs_auth"
            log_event(
                "h1-validator", "warn",
                f"Auth required to validate {report.vuln_type} — open browser to authenticate",
                url=report.proof_url, source="agent",
            )

            # Set up an event the browser-ready endpoint will fire
            auth_event = asyncio.Event()
            job["_browser_event"] = auth_event

            # Wait up to 5 minutes for the user to authenticate
            try:
                await asyncio.wait_for(auth_event.wait(), timeout=300)
            except asyncio.TimeoutError:
                job["status"] = "error"
                result.evidence = "Timed out waiting for authentication (5 min limit)"
                job["result"] = result
                job["finished_at"] = time.time()
                return

            # Re-validate with collected cookies
            cookies = job.get("_browser_cookies") or {}
            job["status"] = "validating"
            log_event(
                "h1-validator", "info",
                f"Re-validating with authenticated session ({len(cookies)} cookies)",
                url=report.proof_url, source="agent",
            )
            result = await validate(report, proxy_port=proxy_port, cookies=cookies)
            job["result"] = result

        job["status"] = result.status
        job["finished_at"] = time.time()

        log_event(
            "h1-validator",
            "finding" if result.status == "confirmed" else "info",
            f"H1 validation {result.status}: {report.vuln_type} — {(result.evidence or '')[:120]}",
            url=report.proof_url, source="agent",
        )

    except asyncio.CancelledError:
        job["status"] = "cancelled"
    except Exception as exc:
        logger.error("H1 validation job error", job_id=job_id, error=str(exc))
        job["status"] = "error"
        job["finished_at"] = time.time()
        from dast.hackerone.validator import ValidationResult
        job["result"] = ValidationResult(
            job_id=job_id, status="error",
            vuln_type=job.get("vuln_type", "unknown"),
            proof_url=job.get("proof_url", ""),
            payload=job.get("payload", ""),
            evidence=f"Internal error: {str(exc)[:300]}",
        )


async def _analyse_images(images_b64: list[str], report_text: str) -> str:
    """
    Send images to the LLM to extract additional context from screenshots.
    Returns a summary string or empty string on failure.
    """
    try:
        import json as _json
        from dast.ai import bedrock_client

        system = (
            "You are a security researcher. These are screenshots attached to a HackerOne bug report. "
            "Describe what you see that is relevant to the vulnerability: "
            "any browser alerts, error messages, server responses, DNS output, or other proof of exploitation. "
            "Be concise — one paragraph maximum."
        )
        messages: list[dict] = []
        content_parts: list[dict] = []

        for img_b64 in images_b64[:4]:  # max 4 images
            try:
                # Detect image type from base64 header
                raw = base64.b64decode(img_b64[:16])
                if raw[:8] == b'\x89PNG\r\n\x1a\n':
                    media_type = "image/png"
                elif raw[:2] == b'\xff\xd8':
                    media_type = "image/jpeg"
                else:
                    media_type = "image/png"

                content_parts.append({
                    "type": "image",
                    "source": {"type": "base64", "media_type": media_type, "data": img_b64},
                })
            except Exception:
                continue

        if not content_parts:
            return ""

        content_parts.append({"type": "text", "text": f"Report context: {report_text[:500]}"})
        messages.append({"role": "user", "content": content_parts})

        model = bedrock_client.get_fast_model()
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 512,
            "system": system,
            "messages": messages,
        }

        loop = asyncio.get_running_loop()
        client = bedrock_client.get_client()
        response = await loop.run_in_executor(
            None,
            lambda: client.invoke_model(modelId=model, body=_json.dumps(body)),
        )
        result = _json.loads(response["body"].read())
        return result["content"][0]["text"]
    except Exception as exc:
        logger.debug("H1 image analysis failed", error=str(exc))
        return ""


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line and len(line) > 10:
            return line[:200]
    return text[:200]


def _infer_vuln_type_from_text(text: str) -> str:
    """Quick keyword scan to infer vuln type when parser returned unknown."""
    text_lower = text.lower()
    if "dns" in text_lower and ("takeover" in text_lower or "ns record" in text_lower or "dangling" in text_lower):
        return "dns_takeover"
    if "ssrf" in text_lower:
        return "ssrf"
    if "xss" in text_lower or "cross-site script" in text_lower:
        return "xss"
    if "sql" in text_lower and "inject" in text_lower:
        return "sqli"
    return "unknown"

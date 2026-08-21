"""
Vuln Validator (agentic triage) routes — the AI-driven reproduction surface.

Where ``hackerone_routes.py`` does a single-shot ``validate()``, this drives the
in-process agentic loop (``dast/ai/triage_agent.py``): an LLM iterates over
Frieren's tool layer to reproduce a reported vulnerability, pausing for a human on
three walls — an out-of-scope host (approve), an auth wall/captcha (browser
handoff), or a value it cannot derive (free-form question).

  POST /api/vuln-validator/validate         — submit a report; returns job_id
  GET  /api/vuln-validator/status/{job_id}  — poll status + live trace + pause
  POST /api/vuln-validator/resume/{job_id}  — answer a pause (approve/auth/question)
  POST /api/vuln-validator/open-browser/{job_id} — open a browser for the auth pause
  POST /api/vuln-validator/cancel/{job_id}  — cancel a running job
  GET  /api/vuln-validator/jobs             — list recent jobs
  WS   /ws/agent-triage                     — stream trace/pause/verdict events

The manual single-shot path (``/api/h1/*``) is intentionally left untouched; the
UI toggle picks which surface to call.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_JOBS = 50

# Human-in-the-loop pause budgets. Approve/question bound a quick operator
# decision; auth allows time to open a browser and log in.
_APPROVE_TIMEOUT_SECONDS = 120.0
_QUESTION_TIMEOUT_SECONDS = 120.0
_AUTH_TIMEOUT_SECONDS = 300.0


class AgentToolContext(ToolContext):
    """ToolContext whose scope gate also honors a per-job approved-host set.

    Scope relaxation is confined to this agent run: a host the operator approves
    at an approve-pause becomes in-scope for the tools without touching the
    process-wide scan scope or any other job.
    """

    def __init__(self, *, approved_hosts: Optional[set] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.approved_hosts: set = approved_hosts if approved_hosts is not None else set()

    def is_in_scope(self, url: str) -> bool:
        if super().is_in_scope(url):
            return True
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        return bool(host) and host in self.approved_hosts


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
            "trace":       j.get("trace", []),
            "pause":       j.get("pause"),
            "verdict":     j.get("verdict"),
        }

    @router.post("/api/vuln-validator/validate")
    async def submit(body: dict):
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
                    {"error": "override_url must be a public http/https URL"}, status_code=400
                )

        job_id = str(uuid.uuid4())[:12]
        _jobs[job_id] = {
            "status": "parsing",
            "created_at": time.time(),
            "vuln_type": "",
            "proof_url": "",
            "payload": "",
            "target_url": "",
            "summary": "",
            "trace": [],
            "pause": None,
            "verdict": None,
            "finished_at": None,
            "_pause_event": asyncio.Event(),
            "_pause_result": None,
            "approved_hosts": set(),
        }
        _gc_jobs()

        task = asyncio.create_task(_run_agent(job_id, report_text, override_url))
        _jobs[job_id]["_task"] = task
        return {"job_id": job_id, "status": "parsing"}

    @router.get("/api/vuln-validator/status/{job_id}")
    async def status(job_id: str):
        if job_id not in _jobs:
            return JSONResponse({"error": "job not found"}, status_code=404)
        return _job_dict(job_id)

    @router.post("/api/vuln-validator/resume/{job_id}")
    async def resume(job_id: str, body: dict):
        """Answer the current pause. Body: {kind, value}.

        approve  -> value.decision in allow_once|always_host|deny
        auth     -> value.cookies {name: value}
        question -> value.text
        """
        if job_id not in _jobs:
            return JSONResponse({"error": "job not found"}, status_code=404)
        job = _jobs[job_id]
        pause = job.get("pause")
        if not pause:
            return JSONResponse({"error": "job is not paused"}, status_code=400)

        kind = str(body.get("kind", pause.get("kind", ""))).strip()
        value = body.get("value") or {}
        if not isinstance(value, dict):
            return JSONResponse({"error": "value must be an object"}, status_code=400)

        if kind == "approve":
            decision = str(value.get("decision", "deny")).strip().lower()
            if decision not in ("allow_once", "always_host", "deny"):
                return JSONResponse({"error": "decision must be allow_once|always_host|deny"},
                                    status_code=400)
            job["_pause_result"] = {"decision": decision}
        elif kind == "auth":
            from dast.hackerone.validator import _sanitise_cookies
            raw = value.get("cookies") or {}
            if not isinstance(raw, dict):
                return JSONResponse({"error": "cookies must be an object"}, status_code=400)
            job["_pause_result"] = {"cookies": _sanitise_cookies(raw)}
        elif kind == "question":
            job["_pause_result"] = {"text": str(value.get("text", "")).strip()}
        else:
            return JSONResponse({"error": "kind must be approve|auth|question"}, status_code=400)

        event: asyncio.Event = job.get("_pause_event")
        if event:
            event.set()
        return {"ok": True}

    @router.post("/api/vuln-validator/open-browser/{job_id}")
    async def open_browser(job_id: str):
        """Open a browser window so the operator can authenticate during an auth pause."""
        if job_id not in _jobs:
            return JSONResponse({"error": "job not found"}, status_code=404)
        job = _jobs[job_id]
        pause = job.get("pause") or {}
        if pause.get("kind") != "auth":
            return JSONResponse({"error": "job is not in an auth pause"}, status_code=400)

        target_url = (pause.get("payload") or {}).get("url", "")
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

        await ctx.browse_queue.put({"action": "start", "url": target_url, "result_cb": result_cb})
        try:
            await asyncio.wait_for(done.wait(), timeout=15)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "browser failed to open"}, status_code=500)
        return {"ok": True, "session_id": result.get("session_id"), "target_url": target_url}

    @router.post("/api/vuln-validator/cancel/{job_id}")
    async def cancel(job_id: str):
        if job_id not in _jobs:
            return JSONResponse({"error": "job not found"}, status_code=404)
        task: Optional[asyncio.Task] = _jobs[job_id].get("_task")
        if task and not task.done():
            task.cancel()
        _jobs[job_id]["status"] = "cancelled"
        return {"ok": True}

    @router.get("/api/vuln-validator/jobs")
    async def list_jobs():
        return [_job_dict(jid) for jid in sorted(_jobs.keys(), key=lambda k: -_jobs[k].get("created_at", 0))]

    @router.websocket("/ws/agent-triage")
    async def agent_ws(ws: WebSocket):
        await ws.accept()
        ctx.agent_triage_ws_clients.add(ws)
        # Re-push in-flight pauses so a late-connecting UI still sees them.
        for jid, job in list(_jobs.items()):
            pause = job.get("pause")
            if pause:
                try:
                    await ws.send_json({"type": "pause", "job_id": jid, **pause})
                except Exception:
                    pass
        try:
            while True:
                await ws.receive_text()
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            ctx.agent_triage_ws_clients.discard(ws)

    # ── Job runner ─────────────────────────────────────────────────────────────
    async def _run_agent(job_id: str, report_text: str, override_url: str) -> None:
        from dast.proxy.plugin_manager import log_event

        job = _jobs[job_id]

        async def on_event(payload: dict) -> None:
            event = {"job_id": job_id, **payload}
            job["trace"].append(event)
            await ctx.broadcast_agent(event)

        async def wait_for_human(kind: str, payload: dict) -> dict:
            timeout = {
                "approve": _APPROVE_TIMEOUT_SECONDS,
                "question": _QUESTION_TIMEOUT_SECONDS,
                "auth": _AUTH_TIMEOUT_SECONDS,
            }.get(kind, _APPROVE_TIMEOUT_SECONDS)
            defaults = {
                "approve": {"decision": "deny"},
                "auth": {"cookies": {}},
                "question": {"text": "(no response)"},
            }
            event: asyncio.Event = job["_pause_event"]
            event.clear()
            job["_pause_result"] = None
            job["status"] = f"paused_{kind}"
            job["pause"] = {"kind": kind, "payload": payload}
            await ctx.broadcast_agent({"type": "pause", "job_id": job_id,
                                       "kind": kind, "payload": payload})
            try:
                await asyncio.wait_for(event.wait(), timeout=timeout)
                result = job.get("_pause_result") or defaults.get(kind, {})
            except asyncio.TimeoutError:
                logger.warning("Vuln Validator pause timed out", job_id=job_id, kind=kind)
                result = defaults.get(kind, {})
            job["pause"] = None
            job["status"] = "running"
            await ctx.broadcast_agent({"type": "resumed", "job_id": job_id, "kind": kind})
            return result

        try:
            job["status"] = "parsing"
            log_event("vuln-validator", "info", f"Parsing report [{job_id}]", source="agent")
            loop = asyncio.get_running_loop()
            from dast.hackerone.parser import parse_report
            report = await loop.run_in_executor(None, lambda: parse_report(report_text))

            if override_url:
                report.proof_url = override_url
                p = urlparse(override_url)
                report.target_url = f"{p.scheme}://{p.netloc}{p.path}"

            job.update({
                "vuln_type":  report.vuln_type,
                "proof_url":  report.proof_url,
                "payload":    report.payload,
                "target_url": report.target_url,
                "summary":    report.summary,
            })

            tool_ctx = AgentToolContext(
                proxy_port=ctx.proxy_port,
                dashboard_port=getattr(ctx, "dashboard_port", 8088),
                store=ctx.store,
                settings=ctx.settings,
                approved_hosts=job["approved_hosts"],
            )

            job["status"] = "running"
            from dast.ai.triage_agent import run_triage_agent
            verdict = await run_triage_agent(
                report, report_text, tool_ctx,
                on_event=on_event, wait_for_human=wait_for_human,
            )

            job["verdict"] = {
                "status": verdict.status,
                "severity": verdict.severity,
                "evidence": verdict.evidence,
                "reasoning": verdict.reasoning,
                "proof_url": verdict.proof_url,
            }
            job["status"] = verdict.status
            job["finished_at"] = time.time()

            if verdict.status == "confirmed" and ctx.store is not None:
                from dast.hackerone.persistence import persist_confirmed_finding
                persist_confirmed_finding(
                    ctx.store,
                    method=verdict.method,
                    url=verdict.proof_url,
                    request_headers=verdict.request_headers,
                    request_body=verdict.request_body,
                    vuln_type=report.vuln_type,
                    severity=verdict.severity or "high",
                    evidence=verdict.evidence,
                    reasoning=verdict.reasoning,
                    payload=verdict.payload,
                    source="vuln-agent",
                )

            log_event(
                "vuln-validator",
                "finding" if verdict.status == "confirmed" else "info",
                f"Vuln Validator {verdict.status}: {report.vuln_type} — {(verdict.evidence or '')[:120]}",
                url=verdict.proof_url, source="agent",
            )

        except asyncio.CancelledError:
            job["status"] = "cancelled"
        except Exception as exc:
            logger.error("Vuln Validator job error", job_id=job_id, error=str(exc))
            job["status"] = "error"
            job["finished_at"] = time.time()
            job["verdict"] = {"status": "error", "reasoning": f"Internal error: {str(exc)[:300]}"}

    return router

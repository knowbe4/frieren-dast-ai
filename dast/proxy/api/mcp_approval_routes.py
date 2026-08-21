"""
MCP request-approval routes — Burp-style interactive per-target approval.

When the MCP server (a separate process) tries to send to a target that is NOT in
the configured scan scope, it long-polls ``POST /api/mcp/approval-request``. This
arms a shared ``asyncio.Event``, broadcasts a prompt to the dashboard over
``/ws/mcp-approval``, and blocks until the operator answers via
``POST /api/mcp/approval-resume`` (Allow Once / Always Allow Host / Deny) or the
request times out (deny). "Always Allow Host" persists the host on the context for
the process lifetime, so subsequent requests to it are auto-approved.

This reuses the exact pause/resume pattern the login-flow captcha human-in-loop
uses (see login_flow_routes.py + flow_replayer.py): event + broadcast + resume
route. Single in-flight approval at a time (mirrors the login shared event).
"""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# How long the MCP caller blocks waiting for a human decision. Must comfortably
# exceed a human reaction time but bound the send_request call so it never hangs.
_APPROVAL_TIMEOUT_SECONDS = 120.0

_VALID_DECISIONS = {"allow_once", "always_host", "deny"}


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()

    @router.post("/api/mcp/approval-request")
    async def approval_request(request: Request):
        """Block until a human approves/denies a send to an out-of-scope target."""
        body = await request.json()
        url = str(body.get("url", "")).strip()
        method = str(body.get("method", "GET")).strip().upper()
        host = str(body.get("host", "")).strip()
        port = body.get("port")

        if not url or not host:
            return JSONResponse({"error": "url and host are required"}, status_code=400)

        # Fast path: host already trusted for this session.
        if host in ctx.mcp_approved_hosts:
            return {"decision": "allow", "reason": "host previously allowed"}

        pending = {"url": url, "method": method, "host": host, "port": port}
        ctx.mcp_approval_pending[0] = pending
        ctx.mcp_approval_decision[0] = None
        ctx.mcp_approval_event.clear()
        await ctx.broadcast_approval({"type": "approval_needed", **pending})
        logger.info("MCP approval requested", host=host, method=method)

        try:
            await asyncio.wait_for(ctx.mcp_approval_event.wait(), timeout=_APPROVAL_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            ctx.mcp_approval_pending[0] = None
            await ctx.broadcast_approval({"type": "approval_resolved", "decision": "deny", "reason": "timeout"})
            logger.warning("MCP approval timed out", host=host)
            return {"decision": "deny", "reason": "timeout"}

        decision = ctx.mcp_approval_decision[0] or "deny"
        ctx.mcp_approval_pending[0] = None
        return {"decision": decision}

    @router.post("/api/mcp/approval-resume")
    async def approval_resume(request: Request):
        """Record the operator's decision and release the blocked request."""
        body = await request.json()
        choice = str(body.get("decision", "")).strip().lower()
        if choice not in _VALID_DECISIONS:
            return JSONResponse(
                {"error": f"decision must be one of {sorted(_VALID_DECISIONS)}"}, status_code=400
            )

        pending = ctx.mcp_approval_pending[0]
        if choice == "always_host" and pending and pending.get("host"):
            ctx.mcp_approved_hosts.add(pending["host"])

        # Normalise to the send-side verdict: allow_once/always_host -> allow.
        decision = "deny" if choice == "deny" else "allow"
        ctx.mcp_approval_decision[0] = decision
        ctx.mcp_approval_event.set()
        await ctx.broadcast_approval({"type": "approval_resolved", "decision": decision, "choice": choice})
        logger.info("MCP approval resolved", choice=choice, decision=decision)
        return {"ok": True, "decision": decision}

    @router.get("/api/mcp/approval-pending")
    async def approval_pending():
        """Return the currently pending approval (for UI initial render), or null."""
        return {"pending": ctx.mcp_approval_pending[0]}

    @router.websocket("/ws/mcp-approval")
    async def approval_ws_endpoint(ws: WebSocket):
        await ws.accept()
        ctx.mcp_approval_ws_clients.add(ws)
        # Push any in-flight prompt so a late-connecting UI still shows it.
        pending: Optional[dict] = ctx.mcp_approval_pending[0]
        if pending:
            try:
                await ws.send_json({"type": "approval_needed", **pending})
            except Exception:
                pass
        try:
            while True:
                await ws.receive_text()
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            ctx.mcp_approval_ws_clients.discard(ws)

    return router

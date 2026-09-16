"""
copilot_ask tool — drive the Exploration Copilot from another agent or an MCP client.

The copilot's conversation state lives in the dashboard process (see
``dast/proxy/api/copilot_routes.py``), so this tool always talks to it over the
dashboard HTTP API: it posts one operator message, waits for the turn to finish
(or to pause for a human), and returns the copilot's reply. That lets an external
MCP client — or another internal agent — hold a conversation with the copilot as
a single primitive, without reimplementing the loop.

This tool is tagged ``copilot`` so the copilot engine excludes it from its own tool
menu: the copilot must never be able to call itself.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# How long to wait for one turn to complete before returning a "still running"
# status, and how often to poll the session. A turn that pauses for a human
# returns as soon as the pause is detected.
_TURN_WAIT_SECONDS = 90.0
_POLL_INTERVAL_SECONDS = 1.5

_COPILOT_ASK_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "message": {
            "type": "string",
            "description": "The message to send the copilot: a goal, a question, or an answer to a previous reply.",
        },
        "session_id": {
            "type": "string",
            "description": "Optional: continue an existing conversation. Omit to start a new session; the returned session_id continues it.",
        },
    },
    "required": ["message"],
}


async def _copilot_ask(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    message = str(args.get("message", "")).strip()
    if not message:
        return {"ok": False, "error": "message is required"}
    session_id = str(args.get("session_id", "")).strip()

    base = ctx.dashboard_base_url
    try:
        import httpx

        async with httpx.AsyncClient(timeout=15) as client:
            body: Dict[str, Any] = {"message": message}
            if session_id:
                body["session_id"] = session_id
            resp = await client.post(f"{base}/api/copilot/message", json=body)
            if resp.status_code == 409:
                return {"ok": False, "error": "a turn is already in progress for this session"}
            resp.raise_for_status()
            started = resp.json()
            sid = str(started.get("session_id", "") or session_id)
            if not sid:
                return {"ok": False, "error": "copilot did not return a session_id"}

            # Poll until the turn finishes (idle/blocked/error) or pauses for a human.
            deadline = asyncio.get_running_loop().time() + _TURN_WAIT_SECONDS
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(_POLL_INTERVAL_SECONDS)
                state = await client.get(f"{base}/api/copilot/session/{sid}")
                state.raise_for_status()
                data = state.json()
                status = str(data.get("status", ""))
                if status.startswith("paused_"):
                    return {
                        "ok": True, "session_id": sid, "status": status,
                        "pause": data.get("pause"),
                        "note": "The copilot paused and needs a human decision "
                                "(approve an out-of-scope host, or provide a login). "
                                "Resolve it in the dashboard, then send again.",
                    }
                if status in ("idle", "blocked", "error"):
                    reply = data.get("last_reply") or {}
                    return {
                        "ok": True, "session_id": sid, "status": status,
                        "reply": reply.get("message", ""),
                        "blocked_reason": reply.get("blocked_reason", ""),
                    }
            return {"ok": True, "session_id": sid, "status": "running",
                    "note": "The copilot is still working; poll the session or send again shortly."}
    except Exception as exc:
        return {"ok": False, "error": f"copilot request failed: {str(exc)[:200]}"}


register(Tool(
    name="copilot_ask",
    description=(
        "Hold a conversation with Frieren's Exploration Copilot: send it a goal, a "
        "question, or an answer, and get its reply after it works the target with its "
        "tools. Returns a session_id — pass it back to continue the same conversation.\n"
        "Use this when: you want the copilot to drive an exploration/exploitation thread "
        "for you and report back, including when it is blocked and needs a human.\n"
        "Do NOT use this to: send a single raw request (use send_request) or read history "
        "(use get_history). If the reply says it paused, a human must resolve the pause in "
        "the dashboard before you continue."
    ),
    input_schema=_COPILOT_ASK_SCHEMA,
    handler=_copilot_ask,
    tags=["copilot"],
))

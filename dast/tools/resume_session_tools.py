"""resume_copilot_session tool — continue a session across a restart (6-A-1).

Copilot sessions are persisted as JSON snapshots under
``~/.dast-ai/copilot_sessions/`` at every turn boundary; a restarted dashboard
restores them at boot (running ones come back as status ``interrupted``). This
tool continues one: autonomous sessions are re-driven with their original
objective, mission todolist and counters; interactive sessions are marked idle
so the next ``copilot_ask`` continues the conversation with full history.

Like ``copilot_ask``, it talks to the dashboard process over HTTP (the session
state lives there) and is tagged ``copilot`` so the copilot can never call it
on itself.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_RESUME_COPILOT_SESSION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "session_id": {
            "type": "string",
            "description": (
                "The session to continue — from copilot_ask's returned session_id or "
                "the dashboard session list (restored sessions show status 'interrupted')."
            ),
        },
    },
    "required": ["session_id"],
}


async def _resume_copilot_session(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    sid = str(args.get("session_id", "")).strip()
    if not sid:
        return {"ok": False, "error": "session_id is required"}
    base = ctx.dashboard_base_url
    try:
        import httpx

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(f"{base}/api/copilot/session/{sid}/continue")
            if resp.status_code == 404:
                return {"ok": False, "error": "session not found (not in memory and not persisted)"}
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:  # noqa: BLE001 — tool convention: never raise
        return {"ok": False, "error": f"resume failed: {str(exc)[:200]}"}


register(Tool(
    name="resume_copilot_session",
    description=(
        "Continue a copilot session that outlived the process: autonomous runs are "
        "re-driven with their ORIGINAL objective, mission todolist and counters "
        "(already-done phases are not repeated); interactive conversations come back "
        "with full history — the next copilot_ask on the same session_id continues "
        "them. Sessions restored from disk show status 'interrupted' in the session "
        "list until continued.\n"
        "Use this after a dashboard/proxy restart, or whenever a previous run was "
        "interrupted and you want it to pick up where it stopped. Do NOT use on a "
        "session that is actively running (the tool refuses)."
    ),
    input_schema=_RESUME_COPILOT_SESSION_SCHEMA,
    handler=_resume_copilot_session,
    tags=["copilot", "session"],
))

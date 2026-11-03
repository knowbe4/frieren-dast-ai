"""run_multiuser_idor tool — cross-session (cross-tenant / privilege-escalation) IDOR.

Thin wrapper: it does NOT reimplement anything. The cross-session IDOR agent
(``dast/agents/cross_session_idor_agent.py``, registered on the Coordinator) already
runs inside the normal active scan whenever the target carries >=2 named sessions
(injected from the store by ``check_target_adapter``). This tool just enforces the
">=2 named sessions" precondition and launches the existing scan focused on the
``cross_session_idor`` attack type, by delegating to the ``run_scan`` handler.

Setup: save each identity with ``save_login_session`` first. Agents only run when AI
mode is on (or the entry was imported) — the result's ``agents_ran`` reflects that.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "In-scope endpoint URL to test for cross-session IDOR. "
                                                 "Must already be in history (proxy it with send_request or crawl first)."},
        "method": {"type": "string", "description": "Optional HTTP method to disambiguate GET vs POST for the url."},
        "entry_id": {"type": "string", "description": "Optional exact history entry id to test instead of matching by url."},
    },
    "required": ["url"],
}


async def _run_multiuser_idor(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    store = getattr(ctx, "store", None)
    if store is None:
        return {"ok": False, "error": "run_multiuser_idor is not available in this context"}
    try:
        sessions = store.get_named_sessions()
    except Exception as exc:
        return {"ok": False, "error": f"named-session lookup failed: {str(exc)[:160]}"}
    if len(sessions) < 2:
        return {
            "ok": False,
            "error": f"cross-session IDOR needs >=2 saved named sessions (have {len(sessions)}); "
                     "save each identity with save_login_session first",
            "named_sessions": [s.name for s in sessions],
        }
    # Delegate to the real scan handler, forcing the cross_session_idor focus. The
    # scan worker injects the store's named sessions onto the CheckTarget, and the
    # already-registered CrossSessionIdorAgent replays across them.
    from dast.tools.scan_tools import _run_scan
    scan_args = dict(args)
    scan_args["attack_types"] = ["cross_session_idor"]
    result = await _run_scan(ctx, scan_args)
    if isinstance(result, dict):
        result["named_sessions_used"] = [{"name": s.name, "role": s.role} for s in sessions]
        if result.get("ok") and not result.get("agents_ran", True):
            result["note"] = ("agents did not run (AI mode off and entry not imported) — enable AI mode "
                              "so the cross-session IDOR agent executes")
    return result


register(Tool(
    name="run_multiuser_idor", input_schema=_SCHEMA, handler=_run_multiuser_idor,
    tags=["active"],
    description="Run Frieren's cross-session (multi-user) IDOR scan on ONE in-scope endpoint: it replays the "
                "request under each saved named session (different tenants/roles) and flags responses that leak "
                "another account's data or allow privilege escalation. Requires >=2 saved named sessions "
                "(set them up with save_login_session). This is the correct tool for cross-account/cross-tenant "
                "authorization testing. Blocks until the scan finishes; returns confirmed findings."))

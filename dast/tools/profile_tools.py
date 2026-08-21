"""
Login-profile tools — list configured per-site login profiles (redacted).

Read-only and secret-free: uses ``LoginProfile.to_public_dict`` which exposes only
``*_set`` booleans, never credential secrets or saved-session cookies. Activation
(loading a session into the live store) mutates running state and is intentionally
NOT exposed here — it stays behind the authenticated dashboard route.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_LIST_PROFILES_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": {"type": "string", "description": "Optional host/URL to resolve the single matching profile."},
    },
    "required": [],
}


async def _list_login_profiles(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        host = str(args.get("host", "")).strip()
        if host:
            from dast.profiles.store import resolve_for_host
            profile = resolve_for_host(host)
            return {"ok": True, "profiles": [profile.to_public_dict()] if profile else []}
        from dast.profiles.store import list_profiles
        return {"ok": True, "profiles": [p.to_public_dict() for p in list_profiles()]}
    except Exception as exc:
        return {"ok": False, "error": f"listing profiles failed: {str(exc)[:200]}"}


register(Tool(
    name="list_login_profiles",
    description=(
        "List configured login profiles (usernames/hosts/labels only — secrets are never "
        "returned), optionally resolving one by host. Read-only.\n"
        "Use this when: you need to know whether authenticated access is available for a "
        "target host before triaging or probing something behind a login.\n"
        "Do NOT use this to: activate a profile or perform a login (intentionally NOT "
        "exposed — that stays in the dashboard); or retrieve credentials (never returned)."
    ),
    input_schema=_LIST_PROFILES_SCHEMA,
    handler=_list_login_profiles,
    tags=["profiles"],
))

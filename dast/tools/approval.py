"""
Interactive request-approval client (MCP side).

When an MCP caller (no in-process store) tries to send to an out-of-scope target,
``send_request`` asks the dashboard for a human decision instead of hard-denying.
This module is the thin client: it long-polls ``/api/mcp/approval-request`` and
returns True only if the operator allowed the target (Allow Once / Always Allow
Host). Any failure — dashboard unreachable, timeout, deny — returns False, so the
caller falls back to the existing safe deny. Internal in-process callers do NOT go
through here; they keep strict scope-deny.
"""

from __future__ import annotations

from urllib.parse import urlparse

from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Slightly longer than the server-side approval timeout so the server, not the
# client, owns the timeout semantics (client just waits for the answer).
_CLIENT_TIMEOUT_SECONDS = 130.0


async def request_approval(ctx: ToolContext, url: str, method: str) -> bool:
    """Ask the dashboard for a human decision on sending to an out-of-scope target.

    Returns True if approved, False otherwise (deny / timeout / dashboard down).
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    try:
        import httpx

        async with httpx.AsyncClient(timeout=_CLIENT_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                f"{ctx.dashboard_base_url}/api/mcp/approval-request",
                json={"url": url, "method": method, "host": host, "port": port},
            )
            resp.raise_for_status()
            data = resp.json()
        approved = str(data.get("decision", "deny")).lower() == "allow"
        logger.info("MCP approval decision received", host=host, approved=approved)
        return approved
    except Exception as exc:
        # No dashboard / no operator -> stay safe (deny). Keeps headless/CI from hanging.
        logger.warning("MCP approval request failed; denying", host=host, error=str(exc))
        return False

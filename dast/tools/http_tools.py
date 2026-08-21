"""
send_request tool — a scope-gated, payload-safety-gated HTTP sender.

Routes the request through the running proxy (so it is captured, rate-limited and
circuit-broken like every other Frieren request), enforces ``is_in_scope`` BEFORE
sending, and refuses destructive payloads (SQL writes/DDL, ``rm -rf``, shutdown,
...) in the URL or body — offering the detection-equivalent safe variant instead.
This is the repeater primitive exposed to agents and MCP clients.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_SEND_REQUEST_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "method": {
            "type": "string",
            "description": "HTTP method (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS). Default GET.",
        },
        "url": {"type": "string", "description": "Absolute target URL. Must be in scope."},
        "headers": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "description": "Optional request headers.",
        },
        "body": {"type": "string", "description": "Optional request body for methods that take one."},
    },
    "required": ["url"],
}


def _destructive_reason(text: str) -> Dict[str, str] | None:
    """Return {reason, safe_variant} if the text is destructive, else None."""
    if not text:
        return None
    from dast.hackerone import payload_safety
    verdict = payload_safety.classify(text)
    if verdict.is_destructive:
        return {"reason": verdict.reason, "safe_variant": verdict.safe_variant or ""}
    return None


async def _send_request(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url:
        return {"ok": False, "error": "url is required"}
    method = str(args.get("method", "GET")).upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return {"ok": False, "error": f"unsupported method: {method}"}

    # Scope gate BEFORE anything is sent. Out-of-scope is denied by default, but an
    # MCP caller (no in-process store) can ask the dashboard operator for an
    # interactive per-target approval (Burp-style) — useful for validating an
    # externally-reported vuln whose target is not in the configured scan scope.
    if not ctx.is_in_scope(url):
        approved = False
        if ctx.store is None:
            from dast.tools import approval
            approved = await approval.request_approval(ctx, url, method)
        if not approved:
            return {"ok": False, "error": "url is out of scope", "url": url}

    headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
    body = args.get("body") or ""

    # Payload-safety gate: refuse destructive URL/body, surfacing the safe variant.
    for where, text in (("url", url), ("body", body)):
        destructive = _destructive_reason(text)
        if destructive:
            logger.warning("send_request refused destructive payload", where=where,
                           reason=destructive["reason"])
            return {
                "ok": False,
                "error": f"refused: destructive payload in {where} ({destructive['reason']})",
                "safe_variant": destructive["safe_variant"],
                "hint": "Re-send with the safe_variant substituted; detection-only policy.",
            }

    try:
        import httpx

        request_body = body if method in ("POST", "PUT", "PATCH", "DELETE") else ""
        async with httpx.AsyncClient(
            proxy=ctx.proxy_url, verify=False, follow_redirects=True, timeout=15,
        ) as client:
            resp = await client.request(
                method, url, headers=headers or None,
                content=request_body.encode("utf-8") if request_body else None,
            )
        return {
            "ok": True,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:8000],
            "length": len(resp.text),
            "final_url": str(resp.url),
        }
    except Exception as exc:
        return {"ok": False, "error": f"request failed: {str(exc)[:200]}"}


register(Tool(
    name="send_request",
    description=(
        "Send a single HTTP request through the Frieren proxy and return the response "
        "(status, headers, body). This is the repeater primitive: it routes through the "
        "proxy so the request is captured, rate-limited and circuit-broken, enforces scope, "
        "and refuses destructive payloads (offering a safe detection-only variant).\n"
        "Use this when: reproducing or probing a specific endpoint, testing whether a "
        "payload reflects/changes behavior, replaying a captured request with a tweak, or "
        "delivering an SSRF/XXE payload that embeds an OOB URL from oob_generate.\n"
        "Do NOT use this to: read requests you already captured (use get_history); "
        "enumerate unknown paths (use content_discovery) or hidden params (use param_mining); "
        "encode a value before sending (use the url_/base64_/html_ encode tools); or run a "
        "destructive write — it will be refused."
    ),
    input_schema=_SEND_REQUEST_SCHEMA,
    handler=_send_request,
    tags=["http"],
))

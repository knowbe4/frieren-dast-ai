"""
send_request tool — a scope-gated, payload-safety-gated HTTP sender.

Routes the request through the running proxy (so it is captured, rate-limited and
circuit-broken like every other Frieren request), enforces ``is_in_scope`` BEFORE
sending, and refuses destructive payloads (SQL writes/DDL, ``rm -rf``, shutdown,
...) in the URL or body — offering the detection-equivalent safe variant instead.
This is the repeater primitive exposed to agents and MCP clients.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlparse

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Reflection detection: an injected value shorter than this is too noisy to be a
# reliable reflection signal (e.g. "1", "ok"), so it is skipped.
_MIN_REFLECTION_VALUE_LEN = 4
# Caps so the reflection summary stays a compact signal, never a second body dump.
_MAX_REFLECTIONS = 6
_REFLECTION_CONTEXT_CHARS = 80


def _all_set_cookies(resp: Any) -> List[str]:
    """Every Set-Cookie value from the response and any redirect hop.

    ``dict(resp.headers)`` collapses repeated headers to a single value, hiding
    multi-cookie issuance (e.g. three CloudFront signed cookies); ``follow_redirects``
    also hides cookies set on an intermediate 3xx hop. This gathers them all.
    Tolerant of non-httpx response shapes (a plain-dict ``headers``, no ``history``)
    so the handler never raises.
    """
    cookies: List[str] = []
    hops = list(getattr(resp, "history", None) or [])
    hops.append(resp)
    for hop in hops:
        headers = getattr(hop, "headers", None)
        if headers is None:
            continue
        if hasattr(headers, "get_list"):
            cookies.extend(headers.get_list("set-cookie"))
        else:
            value = headers.get("set-cookie") if hasattr(headers, "get") else None
            if value:
                cookies.append(value)
    return cookies


def _reflection_context(text: str, needle: str) -> str:
    """A short snippet of ``text`` around the first occurrence of ``needle``."""
    idx = text.find(needle)
    if idx < 0:
        return ""
    start = max(0, idx - _REFLECTION_CONTEXT_CHARS)
    end = min(len(text), idx + len(needle) + _REFLECTION_CONTEXT_CHARS)
    return text[start:end]


def _detect_reflections(url: str, body: str, response_text: str) -> List[Dict[str, Any]]:
    """Report which request-supplied values echo back in the response body.

    The observation fed to an agent is truncated well below the full body, so a
    reflection deep in a large page is invisible to the caller. This surfaces a
    decisive, compact signal instead: for each injected value that echoes back,
    whether it reflected RAW (unencoded — the XSS-relevant case) and whether an
    HTML-escaped copy is also present, with a short context snippet.
    """
    candidates: List[tuple[str, str, str]] = []  # (location, name, value)
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=False):
        candidates.append(("query", name, value))
    for name, value in parse_qsl(body or "", keep_blank_values=False):
        candidates.append(("body", name, value))

    reflections: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for location, name, value in candidates:
        if len(value) < _MIN_REFLECTION_VALUE_LEN or value in seen:
            continue
        seen.add(value)
        raw_reflected = value in response_text
        escaped = html.escape(value, quote=True)
        escaped_reflected = escaped != value and escaped in response_text
        if not raw_reflected and not escaped_reflected:
            continue
        reflections.append({
            "parameter": name,
            "location": location,
            "reflected_raw": raw_reflected,
            "html_escaped_also_present": escaped_reflected,
            "context": _reflection_context(response_text, value if raw_reflected else escaped),
        })
        if len(reflections) >= _MAX_REFLECTIONS:
            break
    return reflections

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
        full_text = resp.text
        # dict(resp.headers) collapses repeated headers to a single value, which
        # hides multi-cookie issuance (e.g. CloudFront signed cookies set as three
        # separate Set-Cookie headers). Surface EVERY Set-Cookie value explicitly,
        # including cookies set on any redirect hop (follow_redirects is on, so those
        # would otherwise be invisible on the final response), so a caller can observe
        # and reuse them.
        set_cookies = _all_set_cookies(resp)
        history = list(getattr(resp, "history", None) or [])
        result: Dict[str, Any] = {
            "ok": True,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": full_text[:8000],
            "length": len(full_text),
            "final_url": str(resp.url),
        }
        if set_cookies:
            result["set_cookies"] = set_cookies
        if history:
            result["redirects"] = [
                {"status": hop.status_code, "url": str(hop.url)} for hop in history
            ]
        # Reflection signal computed on the FULL body (before truncation) so a
        # reflected value deep in a large page is still reported to the caller.
        reflections = _detect_reflections(url, request_body, full_text)
        if reflections:
            result["reflections"] = reflections
        return result
    except Exception as exc:
        return {"ok": False, "error": f"request failed: {str(exc)[:200]}"}


register(Tool(
    name="send_request",
    description=(
        "Send a single HTTP request through the Frieren proxy and return the response "
        "(status, headers, body). This is the repeater primitive: it routes through the "
        "proxy so the request is captured, rate-limited and circuit-broken, enforces scope, "
        "and refuses destructive payloads (offering a safe detection-only variant). Every "
        "Set-Cookie the server issued is returned as the 'set_cookies' list (including cookies "
        "set on any redirect hop) -- read that, not 'headers', to observe issued cookies, since "
        "'headers' collapses repeated Set-Cookie to one value.\n"
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

"""
verify_reflection tool — check whether a submitted payload survived sanitization
in a rendered page.

Built for the copilot's XSS retest loop: after a payload is stored (e.g. an email
body), fetch the page that renders it (e.g. ``/p/<id>``) and classify how the
payload comes back — rendered raw (likely exploitable), HTML-encoded (neutralized),
or stripped. Read-only: a single scope-gated GET/POST through the proxy, no mutation.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Dangerous substrings that, if they survive VERBATIM in HTML, indicate the
# payload was not neutralized. Matched case-insensitively against the response.
_DANGEROUS_TOKENS = (
    "<script", "</script", "javascript:", "onerror=", "onerror ", "onload=",
    "ontoggle=", "onmouseover=", "onfocus=", "onclick=", "<svg", "<img",
    "<iframe", "<details", "srcdoc=", "<body", "<xss",
)

_VERIFY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "In-scope URL of the page that renders the stored payload "
                           "(e.g. https://host/p/<id>). Fetched through the proxy.",
        },
        "payload": {
            "type": "string",
            "description": "The exact payload string that was submitted earlier (e.g. the "
                           "XSS vector). Used to detect whether it survived sanitization.",
        },
        "method": {
            "type": "string",
            "description": "HTTP method to fetch the page (default GET).",
        },
        "headers": {"type": "object", "description": "Optional extra request headers."},
        "body": {"type": "string", "description": "Optional request body (for non-GET fetches)."},
    },
    "required": ["url", "payload"],
}


def _snippet(body: str, needle: str, radius: int = 80) -> str:
    idx = body.lower().find(needle.lower())
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(body), idx + len(needle) + radius)
    return ("..." if start > 0 else "") + body[start:end] + ("..." if end < len(body) else "")


def _classify(body: str, payload: str) -> Dict[str, Any]:
    body_lower = body.lower()
    raw_present = payload.lower() in body_lower
    encoded_present = html.escape(payload, quote=True).lower() in body_lower

    # Which dangerous tokens derived from the payload survived verbatim?
    payload_lower = payload.lower()
    dangerous_raw: List[str] = [
        token for token in _DANGEROUS_TOKENS
        if token in payload_lower and token in body_lower
    ]

    if raw_present or dangerous_raw:
        classification = "rendered_raw"
        verdict = "Payload survived unmodified — likely exploitable."
        evidence = _snippet(body, payload if raw_present else dangerous_raw[0])
    elif encoded_present:
        classification = "encoded"
        verdict = "Payload was HTML-encoded — neutralized."
        evidence = _snippet(body, html.escape(payload, quote=True))
    else:
        classification = "stripped"
        verdict = "Payload not found in the rendered output — stripped or not reflected here."
        evidence = ""

    return {
        "classification": classification,
        "verdict": verdict,
        "raw_payload_present": raw_present,
        "html_encoded_present": encoded_present,
        "dangerous_tokens_raw": dangerous_raw,
        "evidence": evidence,
    }


async def _verify_reflection(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", "")).strip()
    payload = str(args.get("payload", ""))
    if not url:
        return {"ok": False, "error": "url is required"}
    if not payload:
        return {"ok": False, "error": "payload is required"}
    if not ctx.is_in_scope(url):
        return {"ok": False, "error": "url is out of scope", "url": url}

    method = str(args.get("method", "GET")).upper()
    headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
    body = str(args.get("body") or "")
    source_label = getattr(ctx, "source_label", None)
    if source_label and "x-dast-source" not in {k.lower() for k in headers}:
        headers["x-dast-source"] = str(source_label)

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
    except Exception as exc:
        return {"ok": False, "error": f"fetch failed: {str(exc)[:200]}", "url": url}

    result = _classify(full_text, payload)
    result.update({"ok": True, "status": resp.status_code, "final_url": str(resp.url),
                   "length": len(full_text)})
    logger.info("verify_reflection", url=url, classification=result["classification"],
                status=resp.status_code)
    return result


register(Tool(
    name="verify_reflection",
    description=(
        "Fetch a rendered page and report whether a previously submitted payload survived "
        "sanitization: 'rendered_raw' (present verbatim / dangerous tokens intact — likely "
        "exploitable), 'encoded' (HTML-escaped — neutralized), or 'stripped' (absent). "
        "Returns the classification, a verdict, the surviving dangerous tokens, and an "
        "evidence snippet. Read-only — one scope-gated fetch through the proxy.\n"
        "Use this when: you stored an XSS/HTML payload and need to confirm whether it is "
        "reflected dangerously in the output page. For a clean comparison, call it once with "
        "a benign baseline value and once with the payload.\n"
        "Do NOT use this to: send the payload in the first place (use send_request or drive "
        "the browser); or scan a whole app (use run_scan)."
    ),
    input_schema=_VERIFY_SCHEMA,
    handler=_verify_reflection,
    tags=["read"],
))

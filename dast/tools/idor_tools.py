"""
idor_probe tool — deterministic BOLA/IDOR authorization-differential runner.

A broken-object-level-authorization proof is inherently multi-request: write data
under an object id you do not own, read it back (exact value match), confirm a
never-written id errors (control, rules out echo/public), then optionally delete
and confirm destruction. Driving that through an LLM one send_request at a time is
unreliable (the model drops arguments mid-chain). This tool runs the whole
differential itself in ONE call, classifies the result deterministically, and —
when confirmed — records a finding carrying the full request chain as evidence
``steps``. The LLM (or operator) only has to supply the URLs once.

Auth is self-contained: cookies for the target host are read from the proxy jar
(same source the copilot uses) and attached to every sub-request, which is routed
through the proxy so each step is recorded in history in-scope.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "write_url": {
            "type": "string",
            "description": "URL that STORES data under an object id you do not own "
                           "(e.g. .../save/<test-id>). The id must be one you created, never a "
                           "real user's.",
        },
        "read_url": {
            "type": "string",
            "description": "URL that READS the object back (e.g. .../load/<test-id>).",
        },
        "marker": {
            "type": "string",
            "description": "A unique value present in write_body that MUST appear in the read "
                           "response to prove a cross-object read (not an echo).",
        },
        "write_body": {
            "type": "string",
            "description": "Request body to store. Must contain the marker. For JSON keep it valid.",
        },
        "control_read_url": {
            "type": "string",
            "description": "URL that reads a NEVER-written id (e.g. .../load/<random>@x.com). "
                           "Expected to error — rules out the endpoint echoing input or serving a "
                           "public resource. Strongly recommended.",
        },
        "delete_url": {
            "type": "string",
            "description": "Optional URL that DELETES the object (e.g. .../delete/<test-id>). When "
                           "given, the probe deletes then re-reads to confirm destruction (and to "
                           "clean up the test data it wrote).",
        },
        "write_method": {"type": "string", "description": "Method for write_url (default POST)."},
        "content_type": {"type": "string", "description": "Content-Type for the write (default application/json)."},
        "record": {"type": "boolean", "description": "Record a finding when CONFIRMED (default true)."},
        "title": {"type": "string", "description": "Finding title (optional; a sensible default is used)."},
        "severity": {"type": "string", "description": "critical|high|medium|low|info (default high)."},
        "cwe": {"type": "string", "description": "CWE id (default CWE-639)."},
        "parameter": {"type": "string", "description": "Injection point (default 'object id (URL path)')."},
    },
    "required": ["write_url", "read_url", "marker", "write_body"],
}


def _cookie_header(ctx: ToolContext, host: str) -> Optional[str]:
    """Build a Cookie header from the proxy jar for the host (same source the
    copilot engine uses to authenticate send_request)."""
    store = getattr(ctx, "store", None)
    if store is None:
        return None
    try:
        cookies = store.get_cookies_for_host(host) or []
    except Exception as exc:
        logger.warning("idor_probe: cookie lookup failed", host=host, error=str(exc))
        return None
    pairs = [f'{c["name"]}={c.get("value", "")}' for c in cookies if c.get("name")]
    return "; ".join(pairs) if pairs else None


def _is_2xx(status: Optional[int]) -> bool:
    return isinstance(status, int) and 200 <= status < 300


async def _idor_probe(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    write_url = str(args.get("write_url", "")).strip()
    read_url = str(args.get("read_url", "")).strip()
    marker = str(args.get("marker", ""))
    write_body = str(args.get("write_body", ""))
    if not write_url or not read_url:
        return {"ok": False, "error": "write_url and read_url are required"}
    if not marker:
        return {"ok": False, "error": "marker is required (a unique value present in write_body)"}

    control_url = str(args.get("control_read_url", "")).strip()
    delete_url = str(args.get("delete_url", "")).strip()
    write_method = str(args.get("write_method", "POST")).strip().upper() or "POST"
    content_type = str(args.get("content_type", "application/json")).strip() or "application/json"

    # Scope-gate every URL before sending anything.
    for url in (write_url, read_url, control_url, delete_url):
        if url and not ctx.is_in_scope(url):
            return {"ok": False, "error": "url is out of scope", "url": url}

    host = urlparse(write_url).hostname or ""
    cookie = _cookie_header(ctx, host)
    source_label = getattr(ctx, "source_label", None)

    def _headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {}
        if cookie:
            h["cookie"] = cookie
        if source_label:
            h["x-dast-source"] = str(source_label)
        if extra:
            h.update(extra)
        return h

    steps: List[Dict[str, Any]] = []
    try:
        import httpx

        async with httpx.AsyncClient(
            proxy=ctx.proxy_url, verify=False, follow_redirects=False, timeout=15,
        ) as client:
            # (a) foreign-write
            w = await client.request(write_method, write_url,
                                     headers=_headers({"content-type": content_type}),
                                     content=write_body.encode("utf-8"))
            steps.append({"label": "foreign-write", "method": write_method, "url": write_url,
                          "status": w.status_code,
                          "note": "stored data under an id not owned by the session"})

            # (b) foreign-read — exact value match
            r = await client.request("GET", read_url, headers=_headers())
            read_text = r.text
            marker_in_read = marker in read_text
            steps.append({"label": "foreign-read", "method": "GET", "url": read_url,
                          "status": r.status_code,
                          "note": ("returned the exact value written (marker matched)"
                                   if marker_in_read else "marker NOT found in response")})

            # (c) control — never-written id should error
            control_ok_for_safety = True  # True = control behaves as expected (errors)
            if control_url:
                c = await client.request("GET", control_url, headers=_headers())
                marker_in_control = marker in c.text
                control_ok_for_safety = not (_is_2xx(c.status_code) and marker_in_control)
                steps.append({"label": "control", "method": "GET", "url": control_url,
                              "status": c.status_code,
                              "note": ("never-written id errors — rules out echo/public resource"
                                       if control_ok_for_safety
                                       else "control ALSO returned data — likely echo/public, NOT a differential")})

            # (d/e) delete then confirm destruction (also cleans up our test write)
            if delete_url:
                d = await client.request("DELETE", delete_url, headers=_headers())
                steps.append({"label": "delete", "method": "DELETE", "url": delete_url,
                              "status": d.status_code, "note": "foreign delete accepted"
                              if _is_2xx(d.status_code) else "foreign delete rejected"})
                r2 = await client.request("GET", read_url, headers=_headers())
                steps.append({"label": "post-delete read", "method": "GET", "url": read_url,
                              "status": r2.status_code,
                              "note": "destruction confirmed; test data cleaned up"
                              if not _is_2xx(r2.status_code) else "object still readable after delete"})
    except Exception as exc:
        return {"ok": False, "error": f"probe failed: {str(exc)[:200]}", "steps": steps}

    write_status = steps[0]["status"]
    confirmed = bool(_is_2xx(write_status) and _is_2xx(r.status_code)
                     and marker_in_read and control_ok_for_safety)

    if confirmed:
        verdict = ("CONFIRMED — authenticated session wrote and read back an object id it does "
                   "not own (exact value match); control rules out echo/public resource.")
    elif not marker_in_read:
        verdict = "NOT CONFIRMED — the written value did not come back on read."
    elif not control_ok_for_safety:
        verdict = "NOT CONFIRMED — control id also returned the data; likely an echo or public resource."
    else:
        verdict = "NOT CONFIRMED — write or read did not return a success status (session may be unauthenticated)."

    result: Dict[str, Any] = {"ok": True, "confirmed": confirmed, "verdict": verdict, "steps": steps}

    if confirmed and bool(args.get("record", True)) and getattr(ctx, "store", None) is not None:
        severity = str(args.get("severity", "high")).strip().lower()
        if severity not in _VALID_SEVERITIES:
            severity = "high"
        finding = {
            "title": str(args.get("title", "")).strip()
            or "Broken object-level authorization (BOLA/IDOR) — object id from URL, no authz check",
            "severity": severity,
            "attack_type": "broken-access-control",
            "cwe": str(args.get("cwe", "CWE-639")).strip() or "CWE-639",
            "parameter": str(args.get("parameter", "object id (URL path)")).strip() or "object id (URL path)",
            "evidence": verdict,
            "steps": steps,
            "confirmed": True,
            "confidence": 1.0,
            "validated_by": ["idor_probe"],
            "source": "copilot",
        }
        try:
            entry_id = ctx.store.record_manual_finding(finding, write_url, write_method)
            result["recorded_entry_id"] = entry_id
            logger.info("idor_probe recorded finding", entry_id=entry_id, severity=severity)
        except Exception as exc:
            result["record_error"] = str(exc)[:200]

    return result


register(Tool(
    name="idor_probe",
    description=(
        "Run a deterministic BOLA/IDOR authorization differential in ONE call: write data under "
        "an object id you do not own, read it back (exact value match via 'marker'), check a "
        "never-written control id errors, and optionally delete + confirm destruction. Classifies "
        "CONFIRMED/NOT CONFIRMED deterministically and records a finding with the full request "
        "chain as evidence steps. Cookies are taken from the proxy jar automatically.\n"
        "Use this to prove a stored-object IDOR reliably instead of issuing the chain by hand. "
        "SAFETY: only ever target an object id YOU created (e.g. a probe-<epoch> value), never a "
        "real user's id.\n"
        "Do NOT use this for single-request issues (use send_request) or to read existing findings "
        "(use get_findings)."
    ),
    input_schema=_SCHEMA,
    handler=_idor_probe,
    tags=["active", "write"],
))

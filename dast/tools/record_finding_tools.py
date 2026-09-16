"""record_finding tool — persist a vulnerability the copilot/agent confirmed.

The Exploration Copilot (and any MCP client) explores a target and reaches a
verdict, but a verdict that only lives in the chat transcript never reaches the
Findings tab, the report, or the SARIF export. This tool turns a CONFIRMED issue
into a real, tracked finding: it wraps ``SessionStore.record_manual_finding``, so
the finding is linked to the most recent proxied request for its url and carries
the real request/response evidence it was confirmed on.

Dual data path (see ``findings_tools.get_findings``): an internal caller writes the
live SessionStore directly; the MCP process has no store, so it posts to the running
dashboard's ``/api/findings/manual`` endpoint. One tool, both callers.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

_RECORD_FINDING_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "title": {
            "type": "string",
            "description": "Short, specific finding title, e.g. 'Missing field-level "
                           "access control on Account.ldapToken (GraphQL)'.",
        },
        "severity": {
            "type": "string",
            "description": "One of: critical, high, medium, low, info.",
        },
        "url": {
            "type": "string",
            "description": "The request URL the issue was confirmed on. The finding is "
                           "linked to the most recent proxied request for this url so it "
                           "carries the real request/response evidence.",
        },
        "evidence": {
            "type": "string",
            "description": "Concrete evidence you OBSERVED (status codes, response shape, "
                           "diffs) that proves the issue. Do NOT include raw secrets or "
                           "token values — redact them (report PRESENT/REDACTED).",
        },
        "attack_type": {
            "type": "string",
            "description": "Optional machine-readable class, e.g. broken-access-control, "
                           "sqli, xss, ssrf, sensitive-param.",
        },
        "cwe": {"type": "string", "description": "Optional CWE id, e.g. CWE-284."},
        "method": {"type": "string", "description": "HTTP method of the request (default GET)."},
        "parameter": {
            "type": "string",
            "description": "Optional injection point / field the issue affects.",
        },
        "reasoning": {
            "type": "string",
            "description": "Optional short rationale tying the evidence to the verdict.",
        },
    },
    "required": ["title", "severity", "url", "evidence"],
}


def _build_finding(args: Dict[str, Any]) -> Dict[str, Any]:
    severity = str(args.get("severity", "")).strip().lower()
    if severity not in _VALID_SEVERITIES:
        severity = "medium"
    return {
        "title": str(args.get("title", "")).strip(),
        "severity": severity,
        "evidence": str(args.get("evidence", "")).strip(),
        "attack_type": str(args.get("attack_type", "")).strip(),
        "cwe": str(args.get("cwe", "")).strip(),
        "parameter": str(args.get("parameter", "")).strip(),
        "reasoning": str(args.get("reasoning", "")).strip(),
        "confirmed": True,
        "confidence": 1.0,
        "validated_by": ["copilot"],
        "source": "copilot",
    }


async def _record_finding(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    title = str(args.get("title", "")).strip()
    url = str(args.get("url", "")).strip()
    evidence = str(args.get("evidence", "")).strip()
    if not title:
        return {"ok": False, "error": "title is required"}
    if not url:
        return {"ok": False, "error": "url is required"}
    if not evidence:
        return {"ok": False, "error": "evidence is required"}

    method = str(args.get("method", "GET")).strip().upper() or "GET"
    finding = _build_finding(args)

    # In-process path: write the live store directly.
    if ctx.store is not None:
        try:
            entry_id = ctx.store.record_manual_finding(finding, url, method)
            if not entry_id:
                return {"ok": False, "error": "could not record finding (missing url)"}
            logger.info("record_finding: recorded", entry_id=entry_id,
                        title=title, severity=finding["severity"])
            return {"ok": True, "entry_id": entry_id, "title": title,
                    "severity": finding["severity"]}
        except Exception as exc:
            return {"ok": False, "error": f"record failed: {str(exc)[:200]}"}

    # External (MCP) path: post to the running dashboard.
    try:
        import httpx

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{ctx.dashboard_base_url}/api/findings/manual",
                json={"finding": finding, "url": url, "method": method},
            )
            resp.raise_for_status()
            data = resp.json()
        return {"ok": True, **(data if isinstance(data, dict) else {})}
    except Exception as exc:
        return {"ok": False, "error": f"dashboard post failed: {str(exc)[:200]}"}


register(Tool(
    name="record_finding",
    description=(
        "Record a CONFIRMED vulnerability as a tracked finding in Frieren's Findings tab "
        "(and report/SARIF export). Use this the moment you have confirmed a real, "
        "exploitable issue on evidence you actually observed through the tools (status "
        "codes, response bodies, diffs) — it turns your conclusion into a tracked finding "
        "linked to the request it was found on, not just a chat message. Provide a clear "
        "title, severity (critical/high/medium/low/info), the url it was confirmed on, and "
        "concrete evidence; redact any raw secret/token values.\n"
        "Only record CONFIRMED issues — a false positive that wastes the operator's time is "
        "a failure. Use get_findings first to avoid recording a duplicate.\n"
        "Do NOT use this to: send or re-test a request (use send_request) or read existing "
        "findings (use get_findings)."
    ),
    input_schema=_RECORD_FINDING_SCHEMA,
    handler=_record_finding,
    tags=["write"],
))

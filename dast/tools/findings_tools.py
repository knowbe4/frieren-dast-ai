"""
get_findings tool — read the vulnerability findings produced by the scan.

Findings are not a standalone collection: each one lives on its parent
``ProxyEntry.findings`` list, so reading them means flattening entries and joining
every finding with its entry-level context (url/host/method/...). ``flatten_findings``
is a pure helper reused by the dashboard's ``GET /api/findings`` endpoint so the
in-process and HTTP paths return the exact same row shape.

Dual data path (see ToolContext): an internal caller passes the live SessionStore
and flattens it directly; the MCP process has no store, so it fetches
``/api/findings`` from the running dashboard over HTTP. One tool, both callers.
Read-only — no scope gate, no outbound request.
"""

from __future__ import annotations

from typing import Any, Dict, List

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_GET_FINDINGS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": {"type": "string", "description": "Optional host substring filter."},
        "severity": {
            "type": "string",
            "description": "Optional severity filter (critical/high/medium/low/info).",
        },
        "limit": {"type": "integer", "description": "Max findings to return (default 50, max 500)."},
    },
    "required": [],
}

# Finding-level fields worth surfacing to an LLM validating/deduplicating results.
_FINDING_FIELDS = (
    "title", "severity", "cwe", "attack_type", "evidence", "confidence",
    "confirmed", "validated_by", "validated_at", "parameter", "payload",
    "reasoning", "rule_id", "dismissed",
)


def flatten_findings(entry_dicts: List[dict]) -> List[dict]:
    """Flatten a list of ``ProxyEntry.to_dict()`` dicts into per-finding rows.

    Each row carries the finding-level fields plus the parent entry's context
    (``entry_id``, ``url``, ``host``, ``path``, ``method``, ``status``, ``source``,
    ``scan_result``) — mirroring how ``/api/overview`` joins findings to entries.
    Dismissed findings are kept but flagged; callers filter if they wish.
    """
    rows: List[dict] = []
    for entry in entry_dicts:
        findings = entry.get("findings") or []
        for finding in findings:
            if not finding.get("title"):
                continue
            row = {key: finding.get(key) for key in _FINDING_FIELDS}
            row.update({
                "entry_id":    entry.get("id"),
                "url":         entry.get("url"),
                "host":        entry.get("host"),
                "path":        entry.get("path"),
                "method":      entry.get("method"),
                "status":      entry.get("status"),
                "source":      entry.get("source"),
                "scan_result": entry.get("scan_result"),
            })
            rows.append(row)
    return rows


def _filter_and_limit(rows: List[dict], host: str, severity: str, limit: int) -> List[dict]:
    if host:
        host_l = host.lower()
        rows = [r for r in rows if host_l in str(r.get("host", "")).lower()]
    if severity:
        sev_l = severity.lower()
        rows = [r for r in rows if str(r.get("severity", "")).lower() == sev_l]
    return rows[:limit] if limit > 0 else rows


async def _get_findings(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    host = str(args.get("host", "")).strip()
    severity = str(args.get("severity", "")).strip()
    try:
        limit = int(args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 500))

    # In-process path: flatten the live store directly. Use in_scope_entries to
    # match the /api/overview and SARIF convention (out-of-scope excluded).
    if ctx.store is not None:
        try:
            entry_dicts = [e.to_dict() for e in ctx.store.in_scope_entries()]
            rows = _filter_and_limit(flatten_findings(entry_dicts), host, severity, limit)
            return {"ok": True, "count": len(rows), "findings": rows}
        except Exception as exc:
            return {"ok": False, "error": f"store read failed: {str(exc)[:200]}"}

    # External (MCP) path: query the running dashboard's flattened endpoint.
    try:
        import httpx

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{ctx.dashboard_base_url}/api/findings")
            resp.raise_for_status()
            rows = resp.json()
        if not isinstance(rows, list):
            return {"ok": False, "error": "unexpected /api/findings response shape"}
        rows = _filter_and_limit(rows, host, severity, limit)
        return {"ok": True, "count": len(rows), "findings": rows}
    except Exception as exc:
        return {"ok": False, "error": f"dashboard fetch failed: {str(exc)[:200]}"}


register(Tool(
    name="get_findings",
    description=(
        "Return the vulnerability findings the scan has already produced, each with its "
        "severity, evidence, confidence and the request URL it was found on. Optionally "
        "filter by host or severity. Read-only.\n"
        "Use this when: you need to review what has been found so far, deduplicate before "
        "reporting a new issue, or check whether a specific vuln was already confirmed on a host.\n"
        "Do NOT use this to: capture raw HTTP traffic (use get_history), send or re-test a "
        "request (use send_request), or triage an external report (use triage_report)."
    ),
    input_schema=_GET_FINDINGS_SCHEMA,
    handler=_get_findings,
    tags=["read"],
))

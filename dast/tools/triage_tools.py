"""
triage_report tool — parse a pasted vulnerability report and reproduce it.

Wraps the Phase-3 AI triage engine (``dast/hackerone/``): parse the report
(schema-forced LLM enrichment), then reproduce it against the live target through
the proxy. The verdict is the same schema-forced, payload-safety-gated path the
Extras > H1 tab uses — so an MCP client and the dashboard triage identically.
"""

from __future__ import annotations

from typing import Any, Dict

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_TRIAGE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "report_text": {"type": "string", "description": "Full vulnerability report text (HackerOne or free-form)."},
        "override_url": {"type": "string", "description": "Optional proof URL override when the report's is wrong/missing."},
    },
    "required": ["report_text"],
}


async def _triage_report(ctx: ToolContext, args: Dict[str, Any]) -> Dict[str, Any]:
    report_text = str(args.get("report_text", "")).strip()
    if not report_text:
        return {"ok": False, "error": "report_text is required"}
    try:
        import asyncio

        from dast.hackerone.parser import parse_report
        from dast.hackerone.validator import validate

        loop = asyncio.get_running_loop()
        report = await loop.run_in_executor(None, lambda: parse_report(report_text))

        override_url = str(args.get("override_url", "")).strip()
        if override_url:
            from urllib.parse import urlparse
            report.proof_url = override_url
            p = urlparse(override_url)
            report.target_url = f"{p.scheme}://{p.netloc}{p.path}"

        # Scope gate: never reproduce against an out-of-scope host.
        target = report.proof_url or report.target_url
        if target and not ctx.is_in_scope(target):
            return {"ok": False, "error": "report target is out of scope", "url": target}

        result = await validate(report, proxy_port=ctx.proxy_port)
        return {
            "ok": True,
            "status": result.status,
            "vuln_type": result.vuln_type,
            "proof_url": result.proof_url,
            "severity": result.severity,
            "evidence": (result.evidence or "")[:4000],
            "confirmed": result.status == "confirmed",
        }
    except Exception as exc:
        return {"ok": False, "error": f"triage failed: {str(exc)[:200]}"}


register(Tool(
    name="triage_report",
    description=(
        "Triage an externally-reported vulnerability: parse a free-text report (e.g. a "
        "HackerOne submission), reproduce the described request against the target, and "
        "return an LLM-backed verdict (confirmed/not, severity, evidence). Wraps the full "
        "HackerOne triage engine.\n"
        "Use this when: you have a written vulnerability report and want to confirm whether "
        "it actually reproduces — the primary tool for validating incoming external reports.\n"
        "Do NOT use this to: run a raw request yourself (use send_request); scan for new "
        "vulns from scratch (that is the scanner's job, not a tool); or list vulns already "
        "found (use get_findings)."
    ),
    input_schema=_TRIAGE_SCHEMA,
    handler=_triage_report,
    tags=["triage"],
))

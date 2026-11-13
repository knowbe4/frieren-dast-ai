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

import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from dast.tools.base import Tool, register
from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Stand-in hosts the model uses when it does not know the real target. A finding URL with one of
# these (or no host) is defaulted from recent in-scope traffic rather than recorded as-is.
_PLACEHOLDER_HOSTS = frozenset({
    "unknown", "example.com", "www.example.com", "localhost", "127.0.0.1", "host",
})


def _is_placeholder_url(url: str) -> bool:
    u = (url or "").strip()
    if not u:
        return True
    host = (urlparse(u).hostname or "").lower().strip("<>")
    if not host:
        return True
    return host in _PLACEHOLDER_HOSTS or host.startswith("unknown")


def _default_url_from_history(ctx: ToolContext) -> Optional[str]:
    """Most recent in-scope request URL from history — a safety-net default for a finding whose
    url the caller omitted or left as a placeholder host. In-process store only. Never raises."""
    store = getattr(ctx, "store", None)
    if store is None:
        return None
    try:
        entries = list(store.all_entries())
    except Exception:
        return None
    for entry in reversed(entries):
        url = getattr(entry, "url", "") or ""
        if not (urlparse(url).hostname or ""):
            continue
        try:
            if ctx.is_in_scope(url):
                return url
        except Exception:
            continue
    return None

# Deterministic FP guard (record-path twin of dast/ai/fp_filter.py, which record_finding
# bypasses). A finding whose evidence shows an auth-layer REJECTION or an infrastructure
# error must not be recorded as a positive — the copilot once recorded a CRITICAL
# "JWT alg:none Accepted" whose own evidence said "Response: 403".
_INFRA_ERROR_SIGNATURES = (
    "invalid key=value pair", "aws4-hmac", "missing equal-sign",
    "signaturedoesnotmatch", "x-amzn-errortype",
)
_SUCCESS_CLAIM_MARKERS = (
    "accepted", "bypass", "alg:none", "alg: none", "algorithm confusion",
    "unsigned token", "no signature",
)
_REJECTION_STATUS_RE = re.compile(
    r"(?:response|status|http|returned|got|code)\D{0,16}\b(?:401|403)\b", re.IGNORECASE)


def _reject_reason(title: str, evidence: str, reasoning: str) -> Optional[str]:
    """Refuse a self-contradicting finding: evidence showing an infra error, or a
    401/403 rejection paired with an acceptance/bypass claim. Returns the reason or None."""
    text = f"{title}\n{evidence}\n{reasoning}".lower()
    if any(sig in text for sig in _INFRA_ERROR_SIGNATURES):
        return ("the evidence is an AWS SigV4 / API-gateway infrastructure error (a malformed "
                "Authorization parsed as a signature), not application behavior — this is not a "
                "vulnerability. Re-send with NO Authorization/headers (auth auto-injects) and "
                "re-read the response body.")
    if _REJECTION_STATUS_RE.search(text) and any(m in text for m in _SUCCESS_CLAIM_MARKERS):
        return ("the evidence shows a 401/403 (an auth-layer rejection) but the finding claims "
                "acceptance/bypass — a rejection is not acceptance. Read the response BODY and "
                "re-verify before recording.")
    return None

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
                           "token values — redact them (report PRESENT/REDACTED). For a "
                           "multi-request proof keep this a SHORT mechanism summary and put "
                           "the per-request detail in 'steps'.",
        },
        "steps": {
            "type": "array",
            "description": "The ordered request chain that proves the finding, when it "
                           "takes more than one request (e.g. a BOLA differential: "
                           "foreign-write, foreign-read, control, delete). Rendered as a "
                           "clean numbered evidence table so the proof is not pinned to a "
                           "single request. Omit for a single-request finding.",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string", "description": "What this step proves, e.g. 'foreign-read'."},
                    "method": {"type": "string", "description": "HTTP method."},
                    "url": {"type": "string", "description": "Full request URL."},
                    "status": {"type": "integer", "description": "Observed response status code."},
                    "note": {"type": "string", "description": "Short observed result, e.g. 'returned the value written in step 1'."},
                },
                "required": ["method", "url"],
            },
        },
        "attack_type": {
            "type": "string",
            "description": "Optional machine-readable class, e.g. sqli, xss, ssrf, "
                           "sensitive-param. For access control, pick precisely: 'idor' "
                           "(object-level/BOLA — reaching ANOTHER tenant's/user's object, "
                           "CWE-639) vs 'bfla' (function-level — a SAME-tenant action your "
                           "role should not allow / vertical privilege escalation, CWE-862).",
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
    steps_raw = args.get("steps")
    steps = []
    if isinstance(steps_raw, list):
        for step in steps_raw:
            if not isinstance(step, dict) or not str(step.get("url", "")).strip():
                continue
            steps.append({
                "label": str(step.get("label", "")).strip(),
                "method": str(step.get("method", "GET")).strip().upper() or "GET",
                "url": str(step.get("url", "")).strip(),
                "status": step.get("status"),
                "note": str(step.get("note", "")).strip(),
            })
    return {
        "title": str(args.get("title", "")).strip(),
        "severity": severity,
        "evidence": str(args.get("evidence", "")).strip(),
        "steps": steps,
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
    # Safety net (the copilot's dispatch backfills first): default a missing / placeholder-host
    # url from the most recent in-scope request so a confirmed finding is not lost to a bad host.
    # If it is a placeholder and nothing in-scope is available, reject rather than record under a
    # stand-in host.
    if _is_placeholder_url(url):
        backfill = _default_url_from_history(ctx)
        if backfill:
            logger.info("record_finding: defaulted url from last in-scope request", url=backfill)
            url = backfill
        else:
            return {"ok": False, "error": "url is required (the url given has no real target host "
                    "and no in-scope request was found to default from)"}
    if not evidence:
        return {"ok": False, "error": "evidence is required"}

    # Deterministic FP guard: refuse a finding that contradicts its own evidence
    # (infra error, or a 401/403 rejection claimed as an acceptance/bypass).
    _reject = _reject_reason(title, evidence, str(args.get("reasoning", "")))
    if _reject:
        logger.info("record_finding refused self-contradicting finding",
                    title=title[:80], reason=_reject[:80])
        return {"ok": False, "error": _reject}

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

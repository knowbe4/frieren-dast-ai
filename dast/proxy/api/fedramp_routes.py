"""
FedRAMP Penetration Test Guidance v4.0 — compliance checklist and automated assessment.

Tracks the 6 mandatory Attack Vectors and maps automated Frieren DAST-AI coverage
to MITRE ATT&CK techniques required by the guidance document.

Routes:
  GET  /api/fedramp/status       — full checklist state
  POST /api/fedramp/run          — trigger automated assessment (AV-2/AV-3)
  POST /api/fedramp/toggle       — manually mark an item as done/not done
  POST /api/fedramp/note         — add evidence note to a checklist item
  GET  /api/fedramp/report       — generate assessment report JSON
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)


# ── Checklist data model ────────────────────────────────────────────────────

@dataclass
class CheckItem:
    id: str
    title: str
    description: str
    attack_vector: str       # AV-1 .. AV-6
    mitre_id: str            # e.g. T1190
    mitre_name: str
    coverage: str            # "auto" | "manual" | "partial"
    agent_types: List[str] = field(default_factory=list)
    status: str = "pending"  # pending | running | passed | failed | skipped | na
    findings_count: int = 0
    evidence: str = ""
    note: str = ""
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "attack_vector": self.attack_vector,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "coverage": self.coverage,
            "agent_types": self.agent_types,
            "status": self.status,
            "findings_count": self.findings_count,
            "evidence": self.evidence,
            "note": self.note,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


# ── Checklist definition ────────────────────────────────────────────────────

_CHECKLIST: List[dict] = [
    # AV-1: External to Corporate (phishing — manual)
    {"id": "av1-phishing-campaign", "title": "Phishing Campaign Execution",
     "description": "Email campaign with landing page, credential capture, and pixel tracking. Min 1 week duration.",
     "attack_vector": "AV-1", "mitre_id": "T1566", "mitre_name": "Phishing",
     "coverage": "manual", "agent_types": []},
    {"id": "av1-credential-harvest", "title": "Credential Harvesting",
     "description": "Landing page captures username and password. Track submission rate.",
     "attack_vector": "AV-1", "mitre_id": "T1056", "mitre_name": "Input Capture",
     "coverage": "manual", "agent_types": []},
    {"id": "av1-rce-payload", "title": "Remote Code Execution via Payload",
     "description": "Test if user can execute untrusted script (macro/script attachment).",
     "attack_vector": "AV-1", "mitre_id": "T1204", "mitre_name": "User Execution",
     "coverage": "manual", "agent_types": []},

    # AV-2: External to CSP Target System (automated)
    {"id": "av2-sqli", "title": "SQL Injection",
     "description": "Test all input parameters for SQL injection (error-based, blind, time-based).",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["sqli"]},
    {"id": "av2-xss", "title": "Cross-Site Scripting (XSS)",
     "description": "Test reflected, stored, and DOM-based XSS on all input vectors.",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["xss"]},
    {"id": "av2-ssrf", "title": "Server-Side Request Forgery",
     "description": "Test URL parameters and request bodies for SSRF to internal services/metadata.",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["ssrf"]},
    {"id": "av2-lfi", "title": "Local File Inclusion / Path Traversal",
     "description": "Test file path parameters for directory traversal and arbitrary file read.",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["lfi"]},
    {"id": "av2-ssti", "title": "Server-Side Template Injection",
     "description": "Test string parameters for template injection (Jinja2, Twig, Freemarker, etc.).",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["ssti"]},
    {"id": "av2-open-redirect", "title": "Open Redirect",
     "description": "Test redirect/callback parameters for unvalidated redirect to attacker domain.",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["open_redirect"]},
    {"id": "av2-auth-bypass", "title": "Authentication Bypass",
     "description": "Test for broken authentication: header removal, path traversal, privilege escalation.",
     "attack_vector": "AV-2", "mitre_id": "T1078", "mitre_name": "Valid Accounts",
     "coverage": "auto", "agent_types": ["auth_bypass"]},
    {"id": "av2-idor", "title": "Insecure Direct Object Reference (IDOR)",
     "description": "Test numeric IDs and UUIDs for horizontal/vertical privilege escalation.",
     "attack_vector": "AV-2", "mitre_id": "T1078", "mitre_name": "Valid Accounts",
     "coverage": "auto", "agent_types": ["idor", "cross_session_idor"]},
    {"id": "av2-mfa-bypass", "title": "MFA/OTP Bypass",
     "description": "Test MFA endpoints for rate limiting, OTP reuse, backup code enumeration.",
     "attack_vector": "AV-2", "mitre_id": "T1110", "mitre_name": "Brute Force",
     "coverage": "auto", "agent_types": ["mfa_bypass"]},
    {"id": "av2-jwt", "title": "JWT Token Manipulation",
     "description": "Test for alg:none, key confusion, signature bypass, claim tampering.",
     "attack_vector": "AV-2", "mitre_id": "T1134", "mitre_name": "Access Token Manipulation",
     "coverage": "auto", "agent_types": ["jwt"]},
    {"id": "av2-csrf", "title": "Cross-Site Request Forgery",
     "description": "Test state-changing endpoints for missing CSRF tokens and SameSite cookie flags.",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["csrf"]},
    {"id": "av2-business-logic", "title": "Business Logic Abuse",
     "description": "Test for mass assignment, price manipulation, workflow bypass, privilege escalation.",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["business_logic"]},
    {"id": "av2-graphql", "title": "GraphQL Security",
     "description": "Test for introspection exposure, batching abuse, depth limits, and injection.",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["graphql_idor"]},
    {"id": "av2-security-headers", "title": "Security Headers Assessment",
     "description": "Verify presence of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.",
     "attack_vector": "AV-2", "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
     "coverage": "auto", "agent_types": ["passive"]},
    {"id": "av2-secrets-exposure", "title": "Sensitive Data Exposure",
     "description": "Detect API keys, tokens, credentials, and PII in responses.",
     "attack_vector": "AV-2", "mitre_id": "T1552", "mitre_name": "Unsecured Credentials",
     "coverage": "auto", "agent_types": ["sensitive_data"]},
    {"id": "av2-http2", "title": "HTTP/2 Protocol Vulnerabilities",
     "description": "Test for CONTINUATION Flood (CVE-2024-27316) and Rapid Reset (CVE-2023-44487).",
     "attack_vector": "AV-2", "mitre_id": "T1499", "mitre_name": "Endpoint Denial of Service",
     "coverage": "manual", "agent_types": []},

    # AV-3: Tenant to CSP Management (partial)
    {"id": "av3-priv-escalation", "title": "Privilege Escalation to Admin",
     "description": "Test with highest customer permissions for escalation to CSP admin functions.",
     "attack_vector": "AV-3", "mitre_id": "T1068", "mitre_name": "Exploitation for Privilege Escalation",
     "coverage": "partial", "agent_types": ["auth_bypass", "idor"]},
    {"id": "av3-misconfig", "title": "Management Interface Misconfiguration",
     "description": "Test management endpoints for default creds, exposed admin panels, debug modes.",
     "attack_vector": "AV-3", "mitre_id": "T1078", "mitre_name": "Valid Accounts",
     "coverage": "partial", "agent_types": ["auth_bypass", "discovery"]},

    # AV-4: Tenant-to-Tenant (manual)
    {"id": "av4-cross-tenant-data", "title": "Cross-Tenant Data Access",
     "description": "Using two provisioned tenants, attempt to access data across tenant boundaries.",
     "attack_vector": "AV-4", "mitre_id": "T1078", "mitre_name": "Valid Accounts",
     "coverage": "manual", "agent_types": []},
    {"id": "av4-session-isolation", "title": "Session Isolation",
     "description": "Verify sessions cannot be hijacked or reused across tenant boundaries.",
     "attack_vector": "AV-4", "mitre_id": "T1563", "mitre_name": "Remote Service Session Hijacking",
     "coverage": "manual", "agent_types": []},

    # AV-5: Mobile (manual / N/A)
    {"id": "av5-mobile-app", "title": "Mobile Application Testing",
     "description": "Test mobile app for insecure storage, certificate pinning, API abuse. Mark N/A if no mobile app.",
     "attack_vector": "AV-5", "mitre_id": "T1474", "mitre_name": "Supply Chain Compromise",
     "coverage": "manual", "agent_types": []},

    # AV-6: Client-side (manual)
    {"id": "av6-client-app", "title": "Client-Side Application Security",
     "description": "Test browser extensions, thick clients, agents for encryption and tampering.",
     "attack_vector": "AV-6", "mitre_id": "T1059", "mitre_name": "Command and Scripting Interpreter",
     "coverage": "manual", "agent_types": []},
]


class FedRAMPState:
    """In-memory state for the FedRAMP assessment checklist."""

    def __init__(self) -> None:
        self.items: Dict[str, CheckItem] = {}
        self.assessment_started: Optional[float] = None
        self.assessment_finished: Optional[float] = None
        self._init_checklist()

    def _init_checklist(self) -> None:
        for item_def in _CHECKLIST:
            item = CheckItem(**item_def)
            self.items[item.id] = item

    def reset(self) -> None:
        self._init_checklist()
        self.assessment_started = None
        self.assessment_finished = None

    def to_dict(self) -> dict:
        by_av: Dict[str, list] = {}
        for item in self.items.values():
            by_av.setdefault(item.attack_vector, []).append(item.to_dict())
        total = len(self.items)
        done = sum(1 for i in self.items.values() if i.status in ("passed", "failed", "skipped", "na"))
        return {
            "attack_vectors": by_av,
            "progress": {"total": total, "done": done, "percent": round(done / total * 100) if total else 0},
            "assessment_started": self.assessment_started,
            "assessment_finished": self.assessment_finished,
        }


# Module-level singleton
_state = FedRAMPState()


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    store = ctx.store

    @router.get("/api/fedramp/status")
    async def get_status():
        result = _state.to_dict()

        # Enrich each item with real scan data from the store
        # Build lookup: all scanned entries with their findings by attack_type
        scanned_entries = [e for e in store.all_entries()
                          if e.scan_result and e.source != "agent"]
        all_scanned_count = len(scanned_entries)

        for av_items in result["attack_vectors"].values():
            for item_dict in av_items:
                agent_types = set(item_dict.get("agent_types", []))
                if not agent_types or item_dict["coverage"] == "manual":
                    continue

                # Find findings matching this item's attack types
                tested_urls: list = []
                findings_count = 0
                for e in scanned_entries:
                    entry_matched = False
                    for f in e.findings:
                        if f.get("attack_type") in agent_types:
                            findings_count += 1
                            entry_matched = True
                            if len(tested_urls) < 20:
                                tested_urls.append({
                                    "url": e.url, "method": e.method,
                                    "finding": f.get("title", ""),
                                    "confirmed": f.get("confirmed", False),
                                })
                    if not entry_matched and len(tested_urls) < 20:
                        # Also show safe entries that were scanned
                        pass

                item_dict["tested_urls"] = tested_urls
                item_dict["scanned_count"] = all_scanned_count
                item_dict["findings_count"] = findings_count

                # Auto-update status based on real scan progress
                item_obj = _state.items.get(item_dict["id"])
                if item_obj and item_obj.status == "running":
                    if findings_count > 0:
                        item_obj.status = "failed"
                        item_obj.findings_count = findings_count
                        item_obj.finished_at = time.time()
                        item_obj.evidence = f"{findings_count} finding(s) detected"
                    elif all_scanned_count > 0:
                        # All queued entries have been scanned — mark as passed
                        queued_still_running = any(
                            e.queued_for_scan and not e.scan_result
                            for e in store.all_entries()
                            if e.source != "agent"
                        )
                        if not queued_still_running:
                            item_obj.status = "passed"
                            item_obj.findings_count = 0
                            item_obj.finished_at = time.time()
                            item_obj.evidence = f"No {'/'.join(agent_types)} vulnerabilities found across {all_scanned_count} scanned URLs"
                    item_dict["status"] = item_obj.status
                    item_dict["findings_count"] = item_obj.findings_count
                    item_dict["evidence"] = item_obj.evidence

        # Check if all running items finished
        all_done = all(i.status != "running" for i in _state.items.values())
        if _state.assessment_started and not _state.assessment_finished and all_done:
            _state.assessment_finished = time.time()
            result["assessment_finished"] = _state.assessment_finished

        return result

    @router.post("/api/fedramp/run")
    async def run_assessment(request: Request):
        """Trigger automated FedRAMP assessment — queues scans for all AV-2/AV-3 items."""
        body = await request.json() if request.headers.get("content-type") == "application/json" else {}
        attack_vectors = body.get("attack_vectors", ["AV-2", "AV-3"])
        target_hosts = [h.strip().lower() for h in body.get("target_hosts", []) if h.strip()]

        logger.info("FedRAMP assessment starting",
                    attack_vectors=attack_vectors,
                    target_hosts=target_hosts or "all in-scope")
        _state.assessment_started = time.time()
        _state.assessment_finished = None
        queued = 0

        # Get all in-scope entries — optionally filtered by target hosts
        in_scope = [
            e for e in store.all_entries()
            if e.source not in ("agent", "out-of-scope", "imported")
            and e.host
            and e.response_status
            and (not target_hosts or e.host.lower() in target_hosts)
        ]

        if not in_scope:
            logger.warning("FedRAMP run: no in-scope entries", target_hosts=target_hosts)
            return JSONResponse(
                {"error": "No in-scope traffic captured. Browse the target first."},
                status_code=400,
            )

        # For each automated item, queue scans with the appropriate attack types
        for item in _state.items.values():
            if item.attack_vector not in attack_vectors:
                continue
            if item.coverage == "manual":
                continue
            if not item.agent_types:
                continue

            item.status = "running"
            item.started_at = time.time()
            item.findings_count = 0

            # Queue a representative sample of entries for each attack type
            for entry in in_scope[:50]:
                if entry.queued_for_scan:
                    continue
                for attack_type in item.agent_types:
                    if attack_type == "passive":
                        continue
                    hint = {"parameter": "", "payload": "", "attack_type": attack_type}
                    existing = list(entry.import_hints or [])
                    if hint not in existing:
                        entry.import_hints = existing + [hint]

                if not entry.queued_for_scan:
                    entry.queued_for_scan = True
                    entry.ai_queued = True
                    if ctx.scan_queue_state:
                        ctx.scan_queue_state.enqueue(entry.id, entry.method, entry.url, entry.host)
                    await ctx.scan_queue.put(entry.id)
                    queued += 1

        # Mark passive items as passed (they run on every request already)
        for item in _state.items.values():
            if "passive" in item.agent_types:
                passive_findings = sum(
                    1 for e in store.all_entries()
                    for f in e.findings
                    if f.get("validated_by") in ("passive", "passive+ai")
                )
                item.findings_count = passive_findings
                item.status = "passed"
                item.finished_at = time.time()
                item.evidence = f"{passive_findings} passive findings detected across all traffic"

        from dast.proxy.plugin_manager import log_event
        log_event("fedramp", "info",
                  f"FedRAMP assessment started — queued {queued} scan(s) for {len(attack_vectors)} attack vectors",
                  source="agent")

        return {"ok": True, "queued": queued, "message": f"Assessment started — {queued} scans queued"}

    @router.post("/api/fedramp/toggle")
    async def toggle_item(request: Request):
        body = await request.json()
        item_id = str(body.get("id", ""))
        status = str(body.get("status", ""))

        if item_id not in _state.items:
            return JSONResponse({"error": "Unknown item"}, status_code=400)
        if status not in ("pending", "passed", "failed", "skipped", "na"):
            return JSONResponse({"error": "Invalid status"}, status_code=400)

        item = _state.items[item_id]
        item.status = status
        if status in ("passed", "failed", "skipped", "na"):
            item.finished_at = time.time()
        else:
            item.finished_at = None
        return {"ok": True}

    @router.post("/api/fedramp/note")
    async def add_note(request: Request):
        body = await request.json()
        item_id = str(body.get("id", ""))
        note = str(body.get("note", ""))

        if item_id not in _state.items:
            return JSONResponse({"error": "Unknown item"}, status_code=400)

        _state.items[item_id].note = note[:2000]
        return {"ok": True}

    @router.post("/api/fedramp/reset")
    async def reset_assessment():
        _state.reset()
        return {"ok": True}

    @router.get("/api/fedramp/report")
    async def get_report():
        """Generate FedRAMP penetration test report as HTML."""
        from html import escape as _esc
        from datetime import datetime

        settings = getattr(store, "_settings", None)
        scope_hosts: List[str] = []
        if settings:
            rules = getattr(settings, "scope_rules", None) or []
            scope_hosts = [r.get("host", "*") for r in rules if r.get("enabled") and r.get("kind") == "include"]

        # Gather all real findings with evidence
        all_findings: List[dict] = []
        for e in store.all_entries():
            for f in e.findings:
                if f.get("dismissed"):
                    continue
                all_findings.append({
                    "title": f.get("title", ""),
                    "severity": f.get("severity", "info"),
                    "cwe": f.get("cwe", ""),
                    "attack_type": f.get("attack_type", ""),
                    "evidence": f.get("evidence", ""),
                    "payload": f.get("payload", ""),
                    "parameter": f.get("parameter", ""),
                    "confirmed": f.get("confirmed", False),
                    "validated_by": f.get("validated_by", []),
                    "url": e.url,
                    "method": e.method,
                    "host": e.host,
                    "raw_request": f.get("raw_request", ""),
                    "raw_response": f.get("raw_response", ""),
                })

        # Build timeline
        started = datetime.fromtimestamp(_state.assessment_started).strftime("%Y-%m-%d %H:%M:%S") if _state.assessment_started else "Not started"
        finished = datetime.fromtimestamp(_state.assessment_finished).strftime("%Y-%m-%d %H:%M:%S") if _state.assessment_finished else "In progress"

        # Severity ordering
        _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda f: _sev_rank.get(f["severity"], 5))

        _sev_color = {"critical": "#ff4081", "high": "#f44747", "medium": "#ce9178", "low": "#4ec9b0", "info": "#569cd6"}
        _status_label = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP", "na": "N/A", "pending": "PENDING", "running": "RUNNING"}
        _status_color = {"passed": "#4ec9b0", "failed": "#f44747", "skipped": "#9d9d9d", "na": "#6d6d6d", "pending": "#dcdcaa", "running": "#569cd6"}

        _AV_LABELS = {
            "AV-1": "External to Corporate (Phishing)",
            "AV-2": "External to Target System (Application Testing)",
            "AV-3": "Tenant to CSP Management System",
            "AV-4": "Tenant-to-Tenant Isolation",
            "AV-5": "Mobile Application",
            "AV-6": "Client-Side Application",
        }

        # Build HTML
        html_parts = [f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>FedRAMP Penetration Test Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1100px; margin: 0 auto; padding: 40px 24px; background: #fff; color: #1a1a1a; font-size: 13px; line-height: 1.6; }}
h1 {{ font-size: 22px; border-bottom: 2px solid #007acc; padding-bottom: 8px; margin-bottom: 24px; }}
h2 {{ font-size: 16px; color: #007acc; margin-top: 32px; margin-bottom: 12px; border-bottom: 1px solid #e0e0e0; padding-bottom: 4px; }}
h3 {{ font-size: 14px; margin-top: 20px; margin-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 12px; }}
th {{ background: #f5f5f5; padding: 8px 10px; text-align: left; border: 1px solid #ddd; font-weight: 600; }}
td {{ padding: 6px 10px; border: 1px solid #ddd; vertical-align: top; }}
.sev {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; color: #fff; }}
.finding-box {{ border: 1px solid #ddd; border-radius: 4px; padding: 12px 16px; margin: 10px 0; background: #fafafa; }}
.finding-box h4 {{ margin: 0 0 6px 0; font-size: 13px; }}
.evidence {{ background: #1e1e1e; color: #d4d4d4; padding: 10px 12px; border-radius: 3px; font-family: monospace; font-size: 11px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 8px 0; max-height: 300px; overflow-y: auto; }}
.meta {{ font-size: 11px; color: #666; margin: 4px 0; }}
.status {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; }}
.checklist-row {{ display: flex; align-items: center; gap: 8px; padding: 4px 0; border-bottom: 1px solid #f0f0f0; }}
.summary-box {{ background: #f0f8ff; border: 1px solid #b8daff; border-radius: 4px; padding: 14px 18px; margin: 16px 0; }}
@media print {{ body {{ font-size: 11px; }} .evidence {{ max-height: none; }} }}
</style></head><body>
<h1>FedRAMP Penetration Test Report</h1>
<div class="summary-box">
<strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
<strong>Assessment period:</strong> {started} — {finished}<br>
<strong>Scope:</strong> {_esc(', '.join(scope_hosts) if scope_hosts else 'All captured hosts')}<br>
<strong>Total findings:</strong> {len(all_findings)} ({sum(1 for f in all_findings if f['severity']=='critical')} critical, {sum(1 for f in all_findings if f['severity']=='high')} high, {sum(1 for f in all_findings if f['severity']=='medium')} medium)
</div>
"""]

        # Section 6.1 — Scope
        html_parts.append("""<h2>6.1 Scope of Target System</h2>
<table><tr><th>Host Pattern</th><th>Protocol</th></tr>""")
        if settings:
            rules = getattr(settings, "scope_rules", None) or []
            for r in rules:
                if r.get("enabled") and r.get("kind") == "include":
                    html_parts.append(f"<tr><td>{_esc(r.get('host','*'))}</td><td>{_esc(r.get('protocol','*'))}</td></tr>")
        html_parts.append("</table>")

        # Section 6.2 — Attack Vectors
        html_parts.append("<h2>6.2 Attack Vectors Assessed</h2><table><tr><th>Vector</th><th>Description</th><th>Coverage</th><th>Status</th></tr>")
        for av, label in _AV_LABELS.items():
            items = [i for i in _state.items.values() if i.attack_vector == av]
            done = sum(1 for i in items if i.status in ("passed", "failed", "skipped", "na"))
            total = len(items)
            has_failed = any(i.status == "failed" for i in items)
            coverage_types = set(i.coverage for i in items)
            cov_label = "Automated" if coverage_types == {"auto"} else "Partial" if "auto" in coverage_types else "Manual"
            status = "FAIL" if has_failed else ("PASS" if done == total else "IN PROGRESS")
            html_parts.append(f"<tr><td><strong>{av}</strong></td><td>{_esc(label)}</td><td>{cov_label}</td><td>{status}</td></tr>")
        html_parts.append("</table>")

        # Section 6.3 — Timeline
        html_parts.append(f"<h2>6.3 Timeline</h2><p>Assessment started: {started}<br>Assessment completed: {finished}</p>")

        # Section 6.4 — Tests Performed and Results
        html_parts.append("<h2>6.4 Tests Performed and Results</h2>")
        for av, label in _AV_LABELS.items():
            items = [i for i in _state.items.values() if i.attack_vector == av]
            html_parts.append(f"<h3>{av} — {_esc(label)}</h3>")
            for item in items:
                s_color = _status_color.get(item.status, "#999")
                s_label = _status_label.get(item.status, item.status.upper())
                html_parts.append(f"""<div class="checklist-row">
                    <span class="status" style="background:{s_color};color:#fff">{s_label}</span>
                    <span><strong>{_esc(item.title)}</strong></span>
                    <span style="color:#666;font-size:11px">{_esc(item.mitre_id)} {_esc(item.mitre_name)}</span>
                </div>""")
                if item.evidence:
                    html_parts.append(f'<div class="meta">Evidence: {_esc(item.evidence)}</div>')
                if item.note:
                    html_parts.append(f'<div class="meta">Note: {_esc(item.note)}</div>')

        # Section 6.5 — Findings and Evidence
        html_parts.append("<h2>6.5 Findings and Evidence</h2>")
        if not all_findings:
            html_parts.append("<p>No confirmed findings.</p>")
        for i, f in enumerate(all_findings, 1):
            sev = f["severity"]
            s_color = _sev_color.get(sev, "#999")
            html_parts.append(f"""<div class="finding-box">
                <h4><span class="sev" style="background:{s_color}">{sev.upper()}</span> {_esc(f['title'])}</h4>
                <div class="meta">
                    <strong>URL:</strong> {_esc(f['method'])} {_esc(f['url'])}<br>
                    <strong>CWE:</strong> {_esc(f['cwe'])} | <strong>Type:</strong> {_esc(f['attack_type'])} | <strong>Parameter:</strong> {_esc(f['parameter'] or 'N/A')}<br>
                    <strong>Confirmed:</strong> {'Yes' if f['confirmed'] else 'No'} | <strong>Validated by:</strong> {_esc(str(f['validated_by']))}
                </div>""")
            if f.get("evidence"):
                html_parts.append(f'<div class="evidence">{_esc(f["evidence"][:3000])}</div>')
            if f.get("raw_request"):
                html_parts.append(f'<details><summary>HTTP Request</summary><div class="evidence">{_esc(f["raw_request"][:2000])}</div></details>')
            if f.get("raw_response"):
                html_parts.append(f'<details><summary>HTTP Response</summary><div class="evidence">{_esc(f["raw_response"][:2000])}</div></details>')
            html_parts.append("</div>")

        # Section 6.6 — Access Paths
        html_parts.append("<h2>6.6 Access Paths</h2>")
        confirmed_findings = [f for f in all_findings if f["confirmed"]]
        if confirmed_findings:
            html_parts.append("<p>The following confirmed vulnerabilities represent exploitable access paths:</p><ol>")
            for f in confirmed_findings:
                html_parts.append(f"<li><strong>{_esc(f['title'])}</strong> on {_esc(f['method'])} {_esc(f['url'])} — {_esc(f['attack_type'])}</li>")
            html_parts.append("</ol>")
        else:
            html_parts.append("<p>No confirmed exploitable access paths identified during this assessment.</p>")

        html_parts.append("</body></html>")

        from fastapi.responses import HTMLResponse
        logger.info("FedRAMP report generated", findings=len(all_findings), confirmed=len(confirmed_findings))
        return HTMLResponse(content="".join(html_parts), media_type="text/html")

    return router

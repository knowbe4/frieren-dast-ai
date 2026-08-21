"""
Confirmed-triage persistence — turn a reproduced vulnerability into a dashboard
finding (which also flows to SARIF export).

Both triage surfaces persist through here so a confirmed verdict looks identical
in the dashboard and SARIF regardless of which one produced it:
  - the single-shot H1 validator (``dast/proxy/api/hackerone_routes.py``), and
  - the agentic Vuln Validator loop (``dast/ai/triage_agent.py``).

A confirmed triage is written as a synthetic ``source=<source>`` entry for the
proof URL plus a finding dict in the shape the dashboard and ``report/sarif.py``
already read (title/severity/attack_type/cwe/evidence/reasoning/payload). This is
best-effort — a persistence failure must never fail the triage job.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# CWE mapping for the H1 vuln-type vocabulary (H1_PARSE_SCHEMA), used when a
# confirmed triage is persisted as a dashboard finding / SARIF result.
H1_CWE_MAP: Dict[str, str] = {
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
    "csrf": "CWE-352",
    "open_redirect": "CWE-601",
    "ssti": "CWE-1336",
    "rce": "CWE-94",
    "lfi": "CWE-22",
    "xxe": "CWE-611",
    "auth_bypass": "CWE-287",
    "business_logic": "CWE-840",
    "privilege_escalation": "CWE-269",
    "info_disclosure": "CWE-200",
    "dns_takeover": "CWE-350",
}


def persist_confirmed_finding(
    store: Any,
    *,
    method: str,
    url: str,
    request_headers: Optional[Dict[str, str]] = None,
    request_body: str = "",
    vuln_type: str,
    severity: str = "high",
    evidence: str = "",
    reasoning: str = "",
    payload: str = "",
    source: str = "h1-triage",
) -> None:
    """Persist a confirmed triage as a dashboard finding (also flows to SARIF).

    ``source`` labels the finding's origin (``h1-triage`` for the single-shot
    validator, ``vuln-agent`` for the agentic loop). Best-effort: any failure is
    logged at warning and swallowed so it never fails the triage job.
    """
    try:
        if store is None or not url:
            return
        method_norm = (method or "GET").upper()
        body = request_body or ""
        entry_id = store.new_entry(
            method=method_norm,
            url=url,
            request_headers=dict(request_headers or {}),
            request_body=body.encode("utf-8") if body else None,
            source="agent",
        )
        if not entry_id:
            return
        severity_norm = (severity or "high").lower()
        finding = {
            "title": f"HackerOne triage confirmed: {vuln_type}",
            "severity": severity_norm,
            "attack_type": vuln_type,
            "cwe": H1_CWE_MAP.get(vuln_type, ""),
            "evidence": evidence or "",
            "reasoning": reasoning or "",
            "payload": payload or "",
            "parameter": "",
            "source": source,
        }
        store.add_finding(entry_id, finding, "vulnerable")
    except Exception as exc:
        logger.warning("Confirmed-triage persistence failed", error=str(exc))

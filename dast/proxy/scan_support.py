"""
Scan bookkeeping helpers used by the scan worker: dedup-path normalisation,
imported-finding stub updates, and detection-method labels for findings.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dast.ai.agent_base import AgentFinding
    from dast.proxy.session_store import ProxyEntry


def detection_method(f: "AgentFinding") -> list:
    """
    Derive all detection-method labels from an AgentFinding.
    Returns a list because a finding can be confirmed by multiple methods
    (e.g. error_pattern + ai, or pattern + browser).
    """
    attack = getattr(f, "attack_type", "")
    bypass = getattr(f, "bypass_validation", False)
    browser_ok = getattr(f, "browser_confirmed", None)
    title = (getattr(f, "title", "") or "").lower()

    methods = []

    # Deterministic evidence is always the primary signal
    if bypass:
        if attack == "sqli":
            methods.append("time_based" if ("time" in title or "blind" in title) else "error_pattern")
        elif attack == "ssrf":
            methods.append("oob_callback" if ("oob" in title or "callback" in title) else "response_diff")
        elif attack in ("lfi", "file_read"):
            methods.append("file_match")
        elif attack == "sensitive_data":
            methods.append("secret_pattern")
        elif attack == "auth_bypass":
            methods.append("response_diff")
        else:
            methods.append("pattern")

    # Browser confirmation is additive
    if browser_ok is True:
        methods.append("browser")

    # LLM red-team validation — only when not bypass (bypass skips the validator)
    # AND the AI validator actually ran and returned a verdict. When the LLM call
    # was skipped (AI offline) or failed, red_team.validate() confirms via pattern
    # confidence instead — so the finding is labeled "pattern", never "ai". This
    # prevents an "AI validated" badge on a finding the AI never reviewed.
    ai_validated = getattr(f, "ai_validated", False)
    if not bypass:
        methods.append("ai" if ai_validated else "pattern")

    # Every finding needs at least one label. If nothing above applied, fall back
    # to "pattern" rather than implying an AI verdict that never happened.
    return methods if methods else ["pattern"]


# Path segments that would destroy session state or application data.
# Checked against the last URL path segment (lowercased) before scanning.


_ID_RE = re.compile(
    r"(?<=/)"                                     # preceded by /
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
    r"|[0-9]{2,}"                                 # numeric ID (2+ digits)
    r"|[0-9a-f]{24,})"                            # hex ID (MongoDB ObjectId etc)
    r"(?=/|$)",                                   # followed by / or end
    re.IGNORECASE,
)


def normalise_dedup_path(path: str) -> str:
    """Replace variable path segments (IDs, UUIDs) with {id} for dedup."""
    return _ID_RE.sub("{id}", path.split("?")[0])


def update_import_stubs(entry: "ProxyEntry", found_vulnerabilities: bool, error: bool = False) -> None:
    """
    After an active scan completes on an imported/code-hypothesis entry, update any
    stub findings (import_status='queued') to reflect whether the scan confirmed
    the hypothesis or ruled it safe.

    When the scan finds no vulnerability:
      - import_status → "unconfirmed"
      - confirmed → False  (removes it from the Issues panel and dashboard counts)

    When the scan confirms a vulnerability:
      - import_status → "confirmed"
      - confirmed stays True (new AgentFinding already added by the scan)

    On error: import_status → "error", confirmed stays True (benefit of the doubt).
    """
    for f in entry.findings:
        if f.get("import_status") == "queued":
            base = f.get("reasoning", "").split(" — active")[0]
            if error:
                f["import_status"] = "error"
                f["reasoning"] = base + " — Active DAST scan errored before completing."
                # Leave confirmed=True on error — benefit of the doubt
            elif found_vulnerabilities:
                f["import_status"] = "confirmed"
                f["reasoning"] = base + " — Active DAST scan confirmed a finding on this endpoint."
            else:
                f["import_status"] = "unconfirmed"
                f["confirmed"] = False   # demote — no longer treated as a real finding
                f["reasoning"] = base + " — Active DAST scan found no exploitable vulnerability on this endpoint."

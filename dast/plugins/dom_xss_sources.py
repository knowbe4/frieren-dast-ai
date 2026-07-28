"""
DOM XSS Source Detector plugin — scans HTML and JavaScript responses for
dangerous DOM patterns that indicate potential DOM XSS sinks.

This is a passive signal: it flags files worth manually reviewing or sending
to the XSS agent for active probing. Does not confirm exploitability.

Detects:
  - document.write / document.writeln fed by user-controlled sources
  - innerHTML / outerHTML assignments
  - eval() with dynamic content
  - location.hash / location.search flowing into sinks
  - jQuery html() / append() / prepend() patterns
  - window.location assignments to untrusted input
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

# Each entry: (pattern, label, severity)
_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r'document\.write\s*\(.*(?:location|hash|search|param|input|data)', re.IGNORECASE),
        "document.write() with user-controlled source",
        "high",
    ),
    (
        re.compile(r'\.innerHTML\s*[+]?=\s*.*(?:location|hash|search|param|input|data|decode)', re.IGNORECASE),
        "innerHTML assignment with user-controlled source",
        "high",
    ),
    (
        re.compile(r'\.outerHTML\s*[+]?=\s*.*(?:location|hash|search|param|input)', re.IGNORECASE),
        "outerHTML assignment with user-controlled source",
        "high",
    ),
    (
        re.compile(r'eval\s*\(.*(?:location|hash|search|param|input|decode|atob)', re.IGNORECASE),
        "eval() with user-controlled source",
        "high",
    ),
    (
        re.compile(r'location\.hash', re.IGNORECASE),
        "location.hash used (common DOM XSS source)",
        "medium",
    ),
    (
        re.compile(r'\$\(.*\)\.html\s*\(.*(?:location|hash|search|param|input)', re.IGNORECASE),
        "jQuery .html() with user-controlled source",
        "high",
    ),
    (
        re.compile(r'window\.location\s*=.*(?:param|input|data|decode)', re.IGNORECASE),
        "window.location assignment with user-controlled source",
        "medium",
    ),
    (
        re.compile(r'document\.location\s*=.*(?:param|input|data)', re.IGNORECASE),
        "document.location assignment with user-controlled source",
        "medium",
    ),
]

_MAX_BODY = 500_000  # only scan first 500 KB


class DomXssSourcesPlugin(ProxyPlugin):
    name        = "dom-xss-sources"
    description = "Detects DOM XSS source/sink patterns in HTML and JavaScript responses"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        ct = (entry.content_type or "").lower()
        if "html" not in ct and "javascript" not in ct and not entry.path.endswith((".js", ".html")):
            return
        if not entry.response_body:
            return

        try:
            body = entry.response_body[:_MAX_BODY].decode("utf-8", errors="replace")
        except Exception:
            return

        hits: list[tuple[str, str, int]] = []  # (label, severity, line_no)
        lines = body.splitlines()

        for i, line in enumerate(lines, start=1):
            for pattern, label, severity in _PATTERNS:
                if pattern.search(line):
                    hits.append((label, severity, i))

        if not hits:
            return

        # Deduplicate by label, keep highest-severity and first line number
        seen: dict[str, tuple[str, int]] = {}
        for label, severity, line_no in hits:
            if label not in seen:
                seen[label] = (severity, line_no)

        top_severity = "high" if any(s == "high" for s, _ in seen.values()) else "medium"
        evidence_lines = [f"Line {ln}: {lbl}" for lbl, (_, ln) in seen.items()]

        store.add_finding(
            entry.id,
            {
                "title": f"Potential DOM XSS Sinks Detected ({len(seen)} pattern{'s' if len(seen) > 1 else ''})",
                "severity": top_severity,
                "cwe": "CWE-79",
                "attack_type": "dom-xss-sources",
                "evidence": "\n".join(evidence_lines[:10]),
                "confirmed": False,
                "validated_by": ["pattern"],
                "needs_active_validation": True,
            },
            "safe",
        )

        # Queue for active XSS agent scan to confirm exploitability. The active
        # agent IS the AI feature, so the scan worker only runs this when AI mode
        # is on; with AI off the passive finding above still surfaces on its own.
        # ai_queued only lets the deliberate re-scan bypass dedup, not the ai_mode
        # gate or scope.
        if not entry.queued_for_scan and not entry.scan_result:
            entry.ai_queued = True
            entry.queued_for_scan = True
            entry.import_hints = list(entry.import_hints or []) + [
                {"parameter": "", "payload": "", "attack_type": "xss"}
            ]
            store.enqueue_for_scan(entry.id)

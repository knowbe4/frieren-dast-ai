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

from dast.proxy.plugin_base import SYNTHETIC_SOURCES, ProxyPlugin
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

# Real DOM XSS sources: attacker-influenced values the page reads itself.
_SOURCE = (
    r"(?:location\.(?:hash|search|href)|document\.(?:URL|documentURI|baseURI|referrer|cookie)"
    r"|window\.name|URLSearchParams|\.searchParams)"
)
# A source only counts when it feeds the sink in the SAME statement and close
# by: no ';' in between and at most 120 chars. Minified bundles are one huge
# line, so an unbounded `.*` matched any sink plus any source anywhere after it.
_NEAR = r"[^;\n]{0,120}?"

# Each entry: (pattern, label, severity). Every hit is a review hint (low):
# a source reaching a sink is not proof the value is unsanitised.
_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"document\.write(?:ln)?\s*\(" + _NEAR + _SOURCE),
     "document.write() fed by a DOM source", "low"),
    (re.compile(r"\.(?:inner|outer)HTML\s*\+?=" + _NEAR + _SOURCE),
     "innerHTML/outerHTML assignment fed by a DOM source", "low"),
    (re.compile(r"\.insertAdjacentHTML\s*\(" + _NEAR + _SOURCE),
     "insertAdjacentHTML() fed by a DOM source", "low"),
    (re.compile(r"\beval\s*\(" + _NEAR + _SOURCE),
     "eval() fed by a DOM source", "low"),
    (re.compile(r"\.(?:html|append|prepend)\s*\(" + _NEAR + _SOURCE),
     "jQuery .html()/.append()/.prepend() fed by a DOM source", "low"),
    (re.compile(r"(?:window\.|document\.)?location(?:\.href)?\s*=(?!=)" + _NEAR + _SOURCE),
     "location assignment fed by a DOM source", "low"),
]

_MAX_BODY = 500_000  # only scan first 500 KB


class DomXssSourcesPlugin(ProxyPlugin):
    name        = "dom-xss-sources"
    description = "Detects DOM XSS source/sink patterns in HTML and JavaScript responses"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        # Our own probe responses are not the app's code, and re-enqueueing them
        # would feed the scan queue with its own probes.
        if getattr(entry, "source", "proxy") in SYNTHETIC_SOURCES:
            return
        ct = (entry.content_type or "").lower()
        if "html" not in ct and "javascript" not in ct and not entry.path.endswith((".js", ".html")):
            return
        if not entry.response_body:
            return

        try:
            body = entry.response_body[:_MAX_BODY].decode("utf-8", errors="replace")
        except Exception as exc:
            logger.debug("DOM XSS sources: response decode failed", url=entry.url, error=str(exc))
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

        # Every pattern is a review hint, so the finding keeps the lowest band.
        top_severity = "low"
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
        # Only an HTML page can be re-scanned meaningfully: a static .js asset has
        # no injectable parameters for the XSS agent.
        if "html" in ct and not entry.queued_for_scan and not entry.scan_result:
            entry.ai_queued = True
            entry.queued_for_scan = True
            entry.import_hints = list(entry.import_hints or []) + [
                {"parameter": "", "payload": "", "attack_type": "xss"}
            ]
            store.enqueue_for_scan(entry.id)

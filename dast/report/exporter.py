"""
Report exporter — writes scan results to JSON, Markdown, and HTML.
"""

import json
import time
from pathlib import Path
from typing import List

from dast.models import Finding, ScanResult, Severity
from dast.utils.logger import get_logger

logger = get_logger(__name__)


def export_all(result: ScanResult, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    target_slug = _slugify(result.config.target_url)
    ts = time.strftime("%Y%m%d-%H%M%S")

    _export_json(result, output_dir / f"dast-findings_{target_slug}_{ts}.json")
    _export_markdown(result, output_dir / f"dast-report_{target_slug}_{ts}.md")


def _export_json(result: ScanResult, path: Path) -> None:
    data = {
        "target": result.config.target_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": result.status.value,
        "summary": {
            "endpoints_discovered": len(result.endpoints_discovered),
            "attack_attempts": len(result.attack_attempts),
            "findings": len(result.findings),
            "pages_crawled": result.pages_crawled,
            "scan_duration_s": round(result.scan_duration_s, 1),
            "by_severity": _count_by_severity(result.findings),
        },
        "findings": [_finding_to_dict(f) for f in result.findings],
        "errors": result.errors,
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("JSON report written", path=str(path))


def _export_markdown(result: ScanResult, path: Path) -> None:
    lines = [
        f"# Frieren DAST-AI Security Report — {result.config.target_url}",
        f"",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Status:** {result.status.value}",
        f"**Duration:** {result.scan_duration_s:.1f}s",
        f"**Pages crawled:** {result.pages_crawled}",
        f"**Endpoints discovered:** {len(result.endpoints_discovered)}",
        f"**Attack attempts:** {len(result.attack_attempts)}",
        f"",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev, count in _count_by_severity(result.findings).items():
        lines.append(f"| {sev} | {count} |")

    lines += ["", f"**Total Findings:** {len(result.findings)}", ""]

    if result.findings:
        lines.append("## Findings")
        lines.append("")
        for i, finding in enumerate(result.findings, 1):
            lines += [
                f"### {i}. [{finding.severity.value}] {finding.title}",
                f"",
                f"**CWE:** {finding.cwe or 'N/A'}  ",
                f"**Confidence:** {finding.confidence:.0%}  ",
                f"**Attack type:** {finding.attack_type}  ",
                f"**Endpoint:** `{finding.endpoint.method} {finding.endpoint.url}`",
                f"",
                f"**Evidence:**",
                f"```",
                finding.evidence,
                f"```",
                f"",
                f"**AI Reasoning:** {finding.ai_reasoning}",
                f"",
                "---",
                "",
            ]
    else:
        lines += ["## Findings", "", "No confirmed vulnerabilities found.", ""]

    path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Markdown report written", path=str(path))


def _finding_to_dict(f: Finding) -> dict:
    return {
        "title": f.title,
        "severity": f.severity.value,
        "attack_type": f.attack_type,
        "cwe": f.cwe,
        "confidence": round(f.confidence, 3),
        "endpoint": {
            "url": f.endpoint.url,
            "method": f.endpoint.method,
        },
        "evidence": f.evidence,
        "ai_reasoning": f.ai_reasoning,
        "iterations": len(f.confirmed_attempts),
    }


def _count_by_severity(findings: List[Finding]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _slugify(url: str) -> str:
    import re
    url = url.replace("https://", "").replace("http://", "")
    return re.sub(r"[^a-zA-Z0-9]", "-", url).strip("-")[:60]

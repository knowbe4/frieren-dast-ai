"""
Read orchestrator-ai output files and return normalized finding dicts.

Supports:
  - scanner-findings_*.json  — structured JSON produced by result_exporter.py
  - security-report_*.md     — markdown report (fallback, less data)

Each returned dict has the keys the endpoint inferrer expects:
  title, description, file, line, severity, status, attack_type_hint,
  claude_code (raw Stage 2 reasoning string or None)
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any


def read_findings(path: str | Path, status_filter: str = "confirmed") -> List[Dict[str, Any]]:
    """
    Load findings from a JSON or Markdown report file.

    status_filter:
      "confirmed"  — only Stage-2 confirmed findings (default)
      "all"        — every finding regardless of status
      "high+"      — confirmed or severity in (CRITICAL, HIGH)
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Findings file not found: {p}")

    if p.suffix == ".json":
        raw = _read_json(p)
    elif p.suffix == ".md":
        raw = _read_markdown(p)
    else:
        raise ValueError(f"Unsupported file type: {p.suffix} (expected .json or .md)")

    return _apply_filter(raw, status_filter)


def _read_json(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))

    # Top-level list of findings
    if isinstance(data, list):
        raw_findings = data
    # Orchestrator-ai format: {"project": ..., "findings": [...]}
    elif isinstance(data, dict) and "findings" in data:
        raw_findings = data["findings"]
    else:
        raise ValueError("Unrecognised JSON format — expected a list or {findings: [...]}")

    results = []
    for f in raw_findings:
        if not isinstance(f, dict):
            continue

        cc = f.get("claude_code")
        cc_text = cc if isinstance(cc, str) else (
            json.dumps(cc, ensure_ascii=False) if isinstance(cc, dict) else None
        )

        desc = f.get("description") or ""
        # Stage 2 reasoning sometimes prepended to description
        if cc_text and len(cc_text) > len(desc):
            full_context = desc + "\n\n" + cc_text
        else:
            full_context = desc

        results.append({
            "title": f.get("title", ""),
            "description": full_context.strip(),
            "file": f.get("file", ""),
            "line": f.get("line"),
            "severity": (f.get("severity") or "MEDIUM").upper(),
            "status": f.get("status", ""),
            "attack_type_hint": _infer_attack_type(f),
            "cwe": f.get("cwe") or "",
            "owasp": f.get("owasp") or "",
            "claude_code": cc_text,
            "raw": f,
        })
    return results


def _read_markdown(path: Path) -> List[Dict[str, Any]]:
    """
    Parse the markdown report format produced by report_generator.py.

    Each finding block looks like:
        ### [HIGH] Some Vulnerability Title
        **File:** path/to/file.py:42
        **Description:** ...
    """
    text = path.read_text(encoding="utf-8")
    results = []

    # Split on finding headers: ### [SEVERITY] Title
    blocks = re.split(r'\n(?=###\s+\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\])', text)

    for block in blocks:
        header = re.match(r'###\s+\[([A-Z]+)\]\s+(.+)', block)
        if not header:
            continue

        severity = header.group(1)
        title = header.group(2).strip()

        file_match = re.search(r'\*\*File:\*\*\s*(.+?)(?:\n|$)', block)
        file_str = file_match.group(1).strip() if file_match else ""
        file_path, line = (file_str.rsplit(":", 1) if ":" in file_str else (file_str, None))

        desc_match = re.search(r'\*\*Description:\*\*\s*([\s\S]+?)(?=\n\*\*|\Z)', block)
        description = desc_match.group(1).strip() if desc_match else block[:500]

        status_match = re.search(r'\*\*Status:\*\*\s*(\S+)', block)
        status = status_match.group(1).lower() if status_match else "unknown"

        results.append({
            "title": title,
            "description": description,
            "file": file_path.strip(),
            "line": int(line) if line and line.isdigit() else None,
            "severity": severity,
            "status": status,
            "attack_type_hint": _infer_attack_type_from_text(title + " " + description),
            "cwe": "",
            "owasp": "",
            "claude_code": None,
            "raw": {"title": title, "severity": severity, "file": file_path},
        })

    return results


def _apply_filter(findings: List[Dict], status_filter: str) -> List[Dict]:
    if status_filter == "all":
        return findings

    if status_filter == "confirmed":
        return [f for f in findings if "confirmed" in f.get("status", "").lower()]

    if status_filter == "high+":
        return [
            f for f in findings
            if "confirmed" in f.get("status", "").lower()
            or f.get("severity") in ("CRITICAL", "HIGH")
        ]

    return findings


def _infer_attack_type(finding: dict) -> str:
    text = " ".join([
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("cwe", ""),
    ]).lower()
    return _infer_attack_type_from_text(text)


def _infer_attack_type_from_text(text: str) -> str:
    text = text.lower()
    if any(k in text for k in ("xss", "cross-site script", "sanitize_html", "unescaped")):
        return "xss"
    if any(k in text for k in ("sql", "sqli", "cwe-89")):
        return "sqli"
    if any(k in text for k in ("ssrf", "server-side request", "unvalidated url")):
        return "ssrf"
    if any(k in text for k in ("idor", "insecure direct object", "cwe-639")):
        return "idor"
    if any(k in text for k in ("mass assignment", "strong param", "unfiltered input")):
        return "mass_assignment"
    if any(k in text for k in ("path traversal", "zip slip", "directory traversal", "cwe-22")):
        return "path_traversal"
    if any(k in text for k in ("auth bypass", "authentication", "cwe-287")):
        return "auth_bypass"
    if any(k in text for k in ("prompt injection", "llm", "ai injection")):
        return "prompt_injection"
    if any(k in text for k in ("open redirect", "cwe-601")):
        return "open_redirect"
    if any(k in text for k in ("graphql", "mutation", "introspect")):
        return "graphql_injection"
    if any(k in text for k in ("secret", "api key", "credential", "token leak")):
        return "secret_leak"
    if any(k in text for k in ("css inject", "css background")):
        return "css_injection"
    return "unknown"

"""
Deterministic regex-based pattern scanner for source code analysis.

Scans source files for known dangerous patterns: code injection sinks,
SQL injection, hardcoded secrets, and AWS credentials. No LLM calls.
Fast enough to run on hundreds of files in milliseconds.

Each pattern has:
  - language filter (None = all languages)
  - compiled regex
  - id, title, severity, cwe

Patterns are evaluated line by line. Line content is truncated at 200 chars
in PatternMatch to avoid sending large chunks to downstream consumers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_MAX_LINE_LENGTH = 200


@dataclass
class PatternMatch:
    """A single pattern hit in a source file."""

    file_path: str
    line_number: int
    line_content: str       # stripped, max 200 chars
    pattern_id: str
    title: str
    severity: str           # critical / high / medium / low
    cwe: str
    language: str


# ── Pattern definitions ────────────────────────────────────────────────────

@dataclass
class _Pattern:
    pattern_id: str
    title: str
    severity: str
    cwe: str
    regex: re.Pattern
    language: Optional[str]   # None = matches all languages


def _p(
    pattern_id: str,
    title: str,
    severity: str,
    cwe: str,
    pattern: str,
    language: Optional[str] = None,
    flags: int = 0,
) -> _Pattern:
    return _Pattern(
        pattern_id=pattern_id,
        title=title,
        severity=severity,
        cwe=cwe,
        regex=re.compile(pattern, flags),
        language=language,
    )


_PATTERNS: List[_Pattern] = [
    # ── Ruby ──────────────────────────────────────────────────────────────
    _p(
        "RB001",
        "Mass assignment via params.permit!",
        "high",
        "CWE-915",
        r"params\.permit!",
        language="ruby",
    ),
    _p(
        "RB002",
        "Code injection via eval with user input",
        "critical",
        "CWE-95",
        r"\beval\s*\(\s*(params|request)",
        language="ruby",
    ),
    _p(
        "RB003",
        "SSRF / RCE via open() with user input",
        "high",
        "CWE-918",
        r"\bopen\s*\(\s*(params|request)",
        language="ruby",
    ),
    _p(
        "RB004",
        "SQL injection via string interpolation in query",
        "high",
        "CWE-89",
        r'(?:where|execute)\s*\(\s*["\']\s*.*#\{',
        language="ruby",
    ),
    _p(
        "RB005",
        "Arbitrary method dispatch via send() with user input",
        "high",
        "CWE-94",
        r"\bsend\s*\(\s*(params|request)",
        language="ruby",
    ),
    _p(
        "RB006",
        "XSS / SSTI via inline render with user input",
        "medium",
        "CWE-94",
        r"render\s+inline:\s*.*(?:params|request)",
        language="ruby",
    ),

    # ── Python ────────────────────────────────────────────────────────────
    _p(
        "PY001",
        "Code injection via eval() with user input",
        "critical",
        "CWE-95",
        r"\beval\s*\(\s*(request|input)",
        language="python",
    ),
    _p(
        "PY002",
        "OS command injection via os.system() with concatenation",
        "high",
        "CWE-78",
        r"\bos\.system\s*\(",
        language="python",
    ),
    _p(
        "PY003",
        "OS command injection via subprocess.call() with concatenation",
        "high",
        "CWE-78",
        r"\bsubprocess\.(?:call|run|Popen)\s*\(",
        language="python",
    ),
    _p(
        "PY004",
        "SQL injection via string formatting in execute()",
        "high",
        "CWE-89",
        r'\.execute\s*\(\s*(?:f["\']|["\'].*?\+)',
        language="python",
    ),
    _p(
        "PY005",
        "Path traversal via open() with user input",
        "medium",
        "CWE-22",
        r"\bopen\s*\(\s*request",
        language="python",
    ),

    # ── JavaScript / TypeScript ───────────────────────────────────────────
    _p(
        "JS001",
        "Code injection via eval() with request data",
        "critical",
        "CWE-95",
        r"\beval\s*\(\s*(?:req|request)\.",
        language="javascript",
    ),
    _p(
        "JS002",
        "DOM XSS via innerHTML assignment",
        "medium",
        "CWE-79",
        r"\binnerHTML\s*=\s*(?![\"\'])",
        language="javascript",
    ),
    _p(
        "JS003",
        "DOM XSS via dangerouslySetInnerHTML",
        "medium",
        "CWE-79",
        r"dangerouslySetInnerHTML",
        language="javascript",
    ),

    # ── All languages — hardcoded secrets ─────────────────────────────────
    _p(
        "SEC001",
        "Hardcoded secret / credential",
        "high",
        "CWE-798",
        r'(?:api_key|apikey|secret|password|token|passwd)\s*[:=]\s*["\'][A-Za-z0-9+/]{16,}["\']',
        language=None,
        flags=re.IGNORECASE,
    ),
    _p(
        "SEC002",
        "Hardcoded AWS access key",
        "critical",
        "CWE-798",
        r"AKIA[0-9A-Z]{16}",
        language=None,
    ),
    _p(
        "SEC003",
        "Hardcoded private key material",
        "critical",
        "CWE-312",
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        language=None,
    ),
]


# ── Scanner ────────────────────────────────────────────────────────────────

def scan_patterns(files: List[dict]) -> List[PatternMatch]:
    """
    Scan a list of source file dicts for dangerous patterns.

    Args:
        files: List of dicts with keys: path, content, language.

    Returns:
        List of PatternMatch objects, one per matching line.
    """
    matches: List[PatternMatch] = []

    for file_dict in files:
        file_path: str = file_dict.get("path", "")
        content: str = file_dict.get("content", "")
        language: str = file_dict.get("language", "")

        if not content:
            continue

        try:
            file_matches = _scan_file(file_path, content, language)
            matches.extend(file_matches)
        except Exception as exc:
            logger.debug(
                "Pattern scan error on file",
                path=file_path,
                error=str(exc),
            )

    logger.info("Pattern scan complete", files=len(files), matches=len(matches))
    return matches


def _scan_file(
    file_path: str,
    content: str,
    language: str,
) -> List[PatternMatch]:
    """Scan a single file and return all pattern matches."""
    matches: List[PatternMatch] = []
    lines = content.splitlines()

    for pattern in _PATTERNS:
        # Skip patterns that target a different language.
        if pattern.language is not None and pattern.language != language:
            continue

        for line_number, line in enumerate(lines, start=1):
            stripped_line = line.strip()
            # Skip pure string literal lines (e.g. docstrings, title definitions)
            # — the pattern text itself would otherwise match its own patterns.
            if stripped_line.startswith(('"', "'")):
                continue
            if not pattern.regex.search(line):
                continue

            # Truncate the line for safe display.
            stripped = stripped_line[:_MAX_LINE_LENGTH]

            matches.append(PatternMatch(
                file_path=file_path,
                line_number=line_number,
                line_content=stripped,
                pattern_id=pattern.pattern_id,
                title=pattern.title,
                severity=pattern.severity,
                cwe=pattern.cwe,
                language=language,
            ))

    return matches

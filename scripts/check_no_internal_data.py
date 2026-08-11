#!/usr/bin/env python3
"""Block internal / sensitive data from being committed or pushed to the public repo.

This is a deterministic, dependency-free guard used in two places:
  - as a local pre-commit hook (see .pre-commit-config.yaml), and
  - as a pre-push gate, so a `git commit --no-verify` is still caught before the
    data ever reaches the remote.

It complements gitleaks/trufflehog (which hunt for generic secrets) by enforcing
repo-specific rules: DAST runtime artifacts, populated scope presets, CA keys,
and real (non-placeholder) AWS identifiers.

Usage:
    check_no_internal_data.py [FILE ...]

When files are passed (pre-commit / pre-push supply them) those are checked.
With no arguments it falls back to the staged file list. Exit code is non-zero
with a human-readable message when anything is rejected.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# AWS documentation placeholder account id — allowed to appear (it is not real).
PLACEHOLDER_ACCOUNT_ID = "123456789012"
# Known non-secret example access keys — allowed to appear anywhere:
#   - AWS-published documentation example key
#   - the sample STS key baked into the passive scanner's own detection regex
EXAMPLE_ACCESS_KEYS = frozenset(
    {"AKIAIOSFODNN7EXAMPLE", "ASIAZNBXTZ5JFYWWQKW4"}
)

# Files that exist only to hold scanner fixtures / placeholders / generated
# hashes. Content rules are skipped for these (path rules still apply).
CONTENT_ALLOWLIST: tuple[str, ...] = (
    ".env.example",
    "dast/scope_presets/example.json.example",
    "tests/unit/test_secrets_agent.py",
    "tests/unit/test_passive_scanner.py",
    "tests/unit/test_passive_rules_extended.py",
    "tests/unit/test_agent_logic.py",
    "dast/vuln_knowledge/sensitive_data.yaml",
    "desktop/package-lock.json",
)

# ── Path rules: reject a file purely by its location/name ────────────────────
# (pattern, human-readable reason)
FORBIDDEN_PATH_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(^|/)\.env(\.|$)"), "environment file (.env) — use .env.example instead"),
    (
        re.compile(r"(^|/)dast/scope_presets/.*\.json$"),
        "organization scope preset (per-org targets are private)",
    ),
    (re.compile(r"\.(pem|key|p12|pfx)$"), "private key / keystore"),
    (re.compile(r"(^|/)ca\.crt$"), "DAST CA certificate"),
    (re.compile(r"\.session\.json$"), "DAST session file (captured traffic)"),
    (re.compile(r"(^|/)sessions/"), "DAST session output directory"),
    (re.compile(r"(^|/)\.dast-ai/"), "DAST runtime output directory"),
    (re.compile(r"\.log$"), "log file (may contain captured traffic)"),
)

# ── Content rules: reject a file by what it contains ─────────────────────────
BEDROCK_ARN_RE = re.compile(r"arn:aws:bedrock:[a-z0-9-]+:([0-9]{12}):")
AWS_ACCESS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
AWS_SECRET_ASSIGN_RE = re.compile(
    r"AWS_SECRET_ACCESS_KEY\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{20,})"
)


def _staged_files() -> list[str]:
    """Return the list of staged file paths (fallback when none are passed in)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def _is_content_allowlisted(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(normalized == allowed or normalized.endswith("/" + allowed) for allowed in CONTENT_ALLOWLIST)


def _read_text(path: str) -> str | None:
    file_path = Path(path)
    if not file_path.is_file():
        return None
    try:
        return file_path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        # Binary or unreadable — nothing to scan for text-based secrets.
        return None


def _check_path_rules(path: str) -> list[str]:
    normalized = path.replace("\\", "/")
    # .env.example and the sample scope preset are legitimate templates.
    if normalized.endswith(".env.example") or normalized.endswith(".json.example"):
        return []
    violations: list[str] = []
    for pattern, reason in FORBIDDEN_PATH_RULES:
        if pattern.search(normalized):
            violations.append(f"{path}: forbidden path — {reason}")
    return violations


def _check_content_rules(path: str) -> list[str]:
    if _is_content_allowlisted(path):
        return []
    text = _read_text(path)
    if text is None:
        return []
    violations: list[str] = []

    for match in BEDROCK_ARN_RE.finditer(text):
        account_id = match.group(1)
        if account_id != PLACEHOLDER_ACCOUNT_ID:
            violations.append(
                f"{path}: real AWS account id in Bedrock ARN ({account_id}) — "
                "use the placeholder 123456789012"
            )

    for match in AWS_ACCESS_KEY_RE.finditer(text):
        key = match.group(1)
        if key not in EXAMPLE_ACCESS_KEYS:
            violations.append(f"{path}: AWS access key id ({key[:8]}...)")

    if AWS_SECRET_ASSIGN_RE.search(text):
        violations.append(f"{path}: AWS_SECRET_ACCESS_KEY assigned a value")

    return violations


def main(argv: list[str]) -> int:
    files = argv[1:] if len(argv) > 1 else _staged_files()
    if not files:
        return 0

    violations: list[str] = []
    for path in files:
        violations.extend(_check_path_rules(path))
        violations.extend(_check_content_rules(path))

    if violations:
        print("Internal-data guard blocked this change:\n", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        print(
            "\nRemove the offending content (or use the placeholder value). "
            "This guard also runs on push; do not bypass it with --no-verify.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

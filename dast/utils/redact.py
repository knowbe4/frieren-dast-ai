"""Masking for secrets that end up in findings, logs and reports."""

from __future__ import annotations


def redact_secret(value: str) -> str:
    """Show enough of a secret to identify it in the raw request without leaking it.

    Keeps the first and last characters (2 for short values, 4 for long ones),
    masks the middle and notes the full length, so the finding, the session file
    and SARIF exports never carry the whole credential.
    """
    value = value.strip()
    if len(value) <= 12:
        return f"{value[:2]}***{value[-2:]} ({len(value)} chars)"
    return f"{value[:4]}...{value[-4:]} ({len(value)} chars)"

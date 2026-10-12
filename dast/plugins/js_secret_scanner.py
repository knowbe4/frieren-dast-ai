"""
JS secret scanner plugin — looks for live-looking credentials in JS bundles.

Named provider patterns (AWS keys, GitHub tokens, Stripe live keys, ...) plus a
conservative high-entropy fallback that only fires near key-like assignments
(apiKey/secret/token variable names), mirroring how trufflehog/gitleaks keep
the false-positive rate down.

Evidence NEVER contains the full secret: first 8 characters + length + type.
No AI, no probing — pure response analysis on JavaScript bodies.
"""

from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING, Dict, List, Pattern, Tuple

from dast.proxy.plugin_base import ProxyPlugin
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

# Named provider patterns — (label, severity, compiled regex).
_NAMED_PATTERNS: List[Tuple[str, str, Pattern[str]]] = [
    ("AWS access key ID", "high", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("Stripe live key", "high", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    ("OpenAI-style secret key", "high", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")),
    ("Google API key", "medium", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", "medium", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("SendGrid API key", "medium", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("Twilio API key", "medium", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Private key block", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
]

# Fallback: high-entropy strings only count when assigned to key-like names.
_KEYISH_ASSIGNMENT_RE = re.compile(
    r"""["']?(?:api[-_]?key|apikey|secret|secret[-_]?key|access[-_]?token|"""
    r"""auth[-_]?token|client[-_]?secret|private[-_]?key|password)["']?\s*[:=]\s*["']([A-Za-z0-9+/_=-]{20,128})["']""",
    re.IGNORECASE,
)

_MIN_ENTROPY = 4.5
# Deduped per (host, type, first 8 chars) — the same bundle is re-fetched often.
_seen_secrets: set[Tuple[str, str, str]] = set()


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _redact(value: str) -> str:
    return f"{value[:8]}…<{len(value)} chars>"


class JsSecretScannerPlugin(ProxyPlugin):
    name = "js-secret-scanner"
    description = "Scans JavaScript responses for hardcoded API keys, tokens and private keys"
    version = "1.0.0"
    author = "Frieren DAST-AI"
    enabled = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        content_type = (entry.content_type or "").lower()
        if "javascript" not in content_type and not (entry.path or "").endswith(".js"):
            return
        if not entry.response_body:
            return

        try:
            body = entry.response_body.decode("utf-8", errors="replace")
        except Exception:
            return

        hits: List[Tuple[str, str, str]] = []  # (type, severity, full value)

        for label, severity, pattern in _NAMED_PATTERNS:
            for match in pattern.finditer(body):
                hits.append((label, severity, match.group(0)))

        for match in _KEYISH_ASSIGNMENT_RE.finditer(body):
            value = match.group(1)
            if _shannon_entropy(value) >= _MIN_ENTROPY:
                hits.append(("high-entropy key-like assignment", "medium", value))

        new_hits = []
        for label, severity, value in hits:
            key = (entry.host, label, value[:8])
            if key in _seen_secrets:
                continue
            _seen_secrets.add(key)
            new_hits.append((label, severity, value))

        if not new_hits:
            return

        evidence_lines = [
            f"{label}: {_redact(value)}" for label, _, value in new_hits[:10]
        ]
        worst = max((severity for _, severity, _ in new_hits),
                    key=lambda s: {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(s, 0))
        store.add_finding(
            entry.id,
            {
                "title": f"Possible Hardcoded Secrets In JavaScript ({len(new_hits)})",
                "severity": worst,
                "cwe": "CWE-798",
                "attack_type": "js-secrets",
                "confidence": 0.8,
                "evidence": (
                    "\n".join(evidence_lines)
                    + f"\nSource: {entry.path} (values redacted — verify in the bundle)"
                ),
                "confirmed": False,
                "validated_by": ["pattern"],
            },
            "safe",
        )

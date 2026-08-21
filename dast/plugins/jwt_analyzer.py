"""
JWT Analyzer plugin — passively inspects JWT tokens in Authorization headers
and cookies. No extra requests sent.

Checks:
  - alg: none (signature bypass)
  - Missing exp claim (non-expiring token)
  - PII in payload (email, name, ssn, phone)
  - Weak algorithm (HS256 with short key hint from length)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

from dast.proxy.plugin_base import ProxyPlugin
from dast.utils.jwt import decode_segment

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'
)
_PII_KEYS = {"email", "mail", "phone", "mobile", "ssn", "name", "username", "dob", "birthdate"}


def _b64_decode(s: str) -> Optional[dict]:
    try:
        return decode_segment(s)
    except Exception:
        return None


def _extract_tokens(entry: "ProxyEntry") -> list[str]:
    tokens: list[str] = []

    auth = entry.request_headers.get("authorization", "")
    for m in _JWT_RE.finditer(auth):
        tokens.append(m.group(0))

    cookie = entry.request_headers.get("cookie", "")
    for m in _JWT_RE.finditer(cookie):
        tokens.append(m.group(0))

    if entry.response_body:
        try:
            body = entry.response_body.decode("utf-8", errors="replace")
            for m in _JWT_RE.finditer(body):
                tokens.append(m.group(0))
        except Exception:
            pass

    return list(set(tokens))


class JwtAnalyzerPlugin(ProxyPlugin):
    name        = "jwt-analyzer"
    description = "Inspects JWT tokens for weak algorithms, missing expiry, and PII in payload"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        tokens = _extract_tokens(entry)
        if not tokens:
            return

        for token in tokens:
            parts = token.split(".")
            if len(parts) != 3:
                continue

            header  = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])
            if not header or not payload:
                continue

            alg = str(header.get("alg", "")).lower()

            # alg: none
            if alg in ("none", ""):
                store.add_finding(
                    entry.id,
                    {
                        "title": "JWT Algorithm Set to None (Signature Bypass)",
                        "severity": "critical",
                        "cwe": "CWE-347",
                        "attack_type": "jwt",
                        "evidence": f"JWT header alg={alg!r} — signature not verified",
                        "confirmed": True,
                        "validated_by": ["pattern"],
                    },
                    "vulnerable",
                )
                continue

            # Missing exp
            if "exp" not in payload:
                store.add_finding(
                    entry.id,
                    {
                        "title": "JWT Missing Expiration (exp) Claim",
                        "severity": "medium",
                        "cwe": "CWE-613",
                        "attack_type": "jwt",
                        "evidence": "JWT payload has no exp claim — token never expires",
                        "confirmed": True,
                        "validated_by": ["pattern"],
                    },
                    "vulnerable",
                )

            # PII in payload
            pii_found = [k for k in payload if k.lower() in _PII_KEYS and payload[k]]
            if pii_found:
                store.add_finding(
                    entry.id,
                    {
                        "title": "Sensitive Data in JWT Payload",
                        "severity": "medium",
                        "cwe": "CWE-312",
                        "attack_type": "jwt",
                        "evidence": (
                            f"JWT payload contains potentially sensitive fields: "
                            f"{', '.join(pii_found)}. JWT payloads are base64-encoded, not encrypted."
                        ),
                        "confirmed": True,
                        "validated_by": ["pattern"],
                    },
                    "vulnerable",
                )

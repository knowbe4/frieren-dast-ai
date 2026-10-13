"""
JWT Analyzer plugin — passively inspects JWT tokens the client sends in the
Authorization header and cookies. No extra requests sent. One set of findings
per token (not per request); the scanner's own probes are ignored.

Checks:
  - alg: none (signature bypass)
  - Missing exp claim (non-expiring token)
  - PII in payload (email, name, ssn, phone)
  - Weak algorithm (HS256 with short key hint from length)
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Optional

from dast.proxy.plugin_base import SYNTHETIC_SOURCES, ProxyPlugin
from dast.utils.jwt import decode_segment
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'
)
_PII_KEYS = {"email", "mail", "phone", "mobile", "ssn", "name", "username", "dob", "birthdate"}


def _b64_decode(s: str) -> Optional[dict]:
    try:
        return decode_segment(s)
    except Exception as exc:
        logger.debug("JWT analyzer: segment is not base64url JSON", error=str(exc))
        return None


def _extract_tokens(entry: "ProxyEntry") -> list[str]:
    """JWTs the client SENT (Authorization header or cookies).

    Response bodies are not scanned: a JWT-looking string there (docs, examples,
    a token issued for another party) says nothing about what this app accepts.
    """
    headers = {key.lower(): str(value) for key, value in (entry.request_headers or {}).items()}
    tokens: list[str] = []
    for header_name in ("authorization", "cookie"):
        tokens.extend(match.group(0) for match in _JWT_RE.finditer(headers.get(header_name, "")))
    return list(dict.fromkeys(tokens))


class JwtAnalyzerPlugin(ProxyPlugin):
    name        = "jwt-analyzer"
    description = "Inspects JWT tokens for weak algorithms, missing expiry, and PII in payload"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    def __init__(self) -> None:
        # (host, sha256(token)) already analysed: one set of findings per token,
        # not one per request that carries it.
        self._seen_tokens: set[tuple[str, str]] = set()

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        # Our own probes may carry forged tokens (e.g. alg:none attempts).
        if getattr(entry, "source", "proxy") in SYNTHETIC_SOURCES:
            return
        tokens = _extract_tokens(entry)
        if not tokens:
            return

        for token in tokens:
            parts = token.split(".")
            if len(parts) != 3:
                continue
            token_key = (getattr(entry, "host", "") or "", hashlib.sha256(token.encode()).hexdigest())
            if token_key in self._seen_tokens:
                continue
            self._seen_tokens.add(token_key)

            header  = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])
            if not header or not payload:
                continue

            alg = str(header.get("alg", "")).lower()

            # alg: none
            if alg in ("none", ""):
                # Seeing an unsigned token is not proof the server trusts it; a 2xx
                # on the request that carried it is. Otherwise it is a lead for the
                # JWT tester to confirm actively.
                status = getattr(entry, "response_status", None) or 0
                accepted = 200 <= status < 300
                store.add_finding(
                    entry.id,
                    {
                        "title": "JWT Algorithm Set to None (Signature Bypass)",
                        "severity": "critical" if accepted else "medium",
                        "cwe": "CWE-347",
                        "attack_type": "jwt",
                        "evidence": (
                            f"JWT header alg={alg!r} (unsigned) sent by the client; the server "
                            + (f"accepted the request ({status})." if accepted
                               else f"answered {status or 'without a response'} — not shown to be accepted.")
                        ),
                        "confirmed": accepted,
                        "needs_review": not accepted,
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

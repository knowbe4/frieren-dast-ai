"""
Sensitive Parameter Tracker plugin — flags when credentials or auth tokens
(JWTs, opaque bearer tokens) appear as URL query string parameters.
These values end up in server access logs, CDN logs, browser history, and
Referer headers.

Email addresses, phone numbers, and national IDs are intentionally excluded:
they appear legitimately in SSO/OAuth flows (loginHint, hint, login) and
do not represent an exploitable credential exposure.

To keep the false-positive rate low the generic opaque-token heuristic uses the
parameter NAME as evidence: a long random value is only flagged when its name
signals a secret (token, access_token, api_key, ...) and never when the name is
a known-benign carrier of long values (sig, signature, hash, cache-buster, OAuth
nonce/state, ...). JWTs are structurally unambiguous and flag on any name.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import parse_qs, urlparse
from typing import TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

# A JWT is a credential regardless of the parameter name — the structural
# prefix ("eyJ" = base64 of '{"') plus the three dot-separated segments make
# false positives vanishingly unlikely, so this fires on any parameter.
_JWT_RE = re.compile(r'^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$')

# Generic long opaque token. On its own this matches far too much (asset content
# hashes, cache-busters, URL signatures, base64 blobs), so it only counts as a
# credential when the PARAMETER NAME also signals a secret AND the value has
# enough entropy to look random rather than structured.
_BEARER_RE = re.compile(r'^[A-Za-z0-9\-_]{40,}$')

# Parameter names that legitimately carry a reusable secret/credential in the URL.
_CREDENTIAL_PARAM_NAMES = {
    "token", "access_token", "accesstoken", "id_token", "idtoken",
    "refresh_token", "refreshtoken", "auth", "authorization", "bearer",
    "api_key", "apikey", "api-key", "key", "apitoken", "api_token",
    "secret", "client_secret", "clientsecret", "password", "passwd", "pwd",
    "session", "sessionid", "session_id", "sid", "jwt", "credential",
    "credentials", "access-token",
}

# Parameter names where a long opaque value is expected and benign: URL
# signatures (Azure SAS / signed URLs / CDN), cache-busters, asset
# fingerprints, and OAuth CSRF nonces. These are never flagged by the generic
# heuristic even though their values look token-like.
_BENIGN_OPAQUE_PARAM_NAMES = {
    "sig", "signature", "sign", "hash", "checksum", "cb", "v", "ver",
    "version", "nonce", "state", "_", "t", "ts", "timestamp", "rev",
    "build", "hmac", "etag", "digest",
}

# Below this Shannon entropy (bits/char) a 40+ char string is structured
# (repeated runs, hex-with-low-variety, path-like) rather than a random secret.
_MIN_ENTROPY_BITS_PER_CHAR = 3.0


def _shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character; higher = more random-looking."""
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )


def _classify(name: str, value: str) -> str | None:
    """Classify a query parameter as a credential using the name as evidence,
    not the value alone. JWTs fire unconditionally; the generic opaque-token
    heuristic requires a credential-like name and sufficient entropy."""
    value = value.strip()
    if _JWT_RE.match(value):
        return "JWT token"

    normalized_name = name.strip().lower()
    if normalized_name in _BENIGN_OPAQUE_PARAM_NAMES:
        return None
    if normalized_name not in _CREDENTIAL_PARAM_NAMES:
        return None
    if _BEARER_RE.match(value) and _shannon_entropy(value) >= _MIN_ENTROPY_BITS_PER_CHAR:
        return "Bearer/API token"
    return None


def _redact(value: str) -> str:
    """Show enough of a secret to identify it in the raw request without
    leaking the whole credential into the findings UI/logs: keep the first
    and last 4 characters, mask the middle, and note the full length."""
    value = value.strip()
    if len(value) <= 12:
        return f"{value[:2]}***{value[-2:]} ({len(value)} chars)"
    return f"{value[:4]}...{value[-4:]} ({len(value)} chars)"


class SensitiveParamTrackerPlugin(ProxyPlugin):
    name        = "sensitive-param-tracker"
    description = "Flags credentials and auth tokens transmitted in URL query parameters"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        parsed = urlparse(entry.url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query, keep_blank_values=False)
        hits: list[str] = []
        for name, values in params.items():
            value = values[0] if values else ""
            label = _classify(name, value)
            if label:
                # Show the parameter name, its classification, and a redacted
                # preview of the value so the developer can locate exactly what
                # was flagged in the raw request without exposing the full secret.
                hits.append(f"{name}={_redact(value)} [{label}]")
                logger.debug(
                    "sensitive param detected",
                    param=name,
                    label=label,
                    path=parsed.path,
                )

        if not hits:
            return

        # Reconstruct where the credential lives so the finding is self-explanatory
        # (the shared HTTP evidence panel shows the response, not this query string).
        location = f"{parsed.path}?{parsed.query}" if parsed.path else parsed.query
        logger.info(
            "sensitive param finding recorded",
            entry_id=entry.id,
            host=parsed.hostname,
            path=parsed.path,
            hit_count=len(hits),
        )

        store.add_finding(
            entry.id,
            {
                "title": "Credential or Token Transmitted in URL Query String",
                "severity": "high",
                "cwe": "CWE-522",
                "attack_type": "sensitive-param",
                "evidence": (
                    f"Credential in request URL query string ({entry.method} {parsed.path}): "
                    f"{'; '.join(hits)}. Detected on the request line, not the response body. "
                    f"Values in the query string are recorded in server access logs, CDN logs, "
                    f"browser history, and Referer headers."
                ),
                "parameter": ", ".join(h.split("=", 1)[0] for h in hits),
                "snippet": location,
                "confirmed": True,
                "validated_by": ["pattern"],
            },
            "vulnerable",
        )

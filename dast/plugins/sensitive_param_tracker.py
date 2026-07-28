"""
Sensitive Parameter Tracker plugin — flags when credentials or auth tokens
(JWTs, opaque bearer tokens) appear as URL query string parameters.
These values end up in server access logs, CDN logs, browser history, and
Referer headers.

Email addresses, phone numbers, and national IDs are intentionally excluded:
they appear legitimately in SSO/OAuth flows (loginHint, hint, login) and
do not represent an exploitable credential exposure.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse
from typing import TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

_JWT_RE    = re.compile(r'^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$')
_BEARER_RE = re.compile(r'^[A-Za-z0-9\-_]{40,}$')  # generic long opaque token (40+ chars)

# Only credentials/tokens warrant a finding — email/phone/national-ID are omitted
# because they appear legitimately in SSO and identity flows.
_CHECKS: list[tuple[re.Pattern, str]] = [
    (_JWT_RE,    "JWT token"),
    (_BEARER_RE, "Bearer/API token"),
]


def _classify(value: str) -> str | None:
    for pattern, label in _CHECKS:
        if pattern.match(value.strip()):
            return label
    return None


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

        hits: list[str] = []
        for name, values in params.items():
            value = values[0] if values else ""
            label = _classify(value)
            if label:
                hits.append(f"{name} ({label})")

        if not hits:
            return

        store.add_finding(
            entry.id,
            {
                "title": "Credential or Token Transmitted in URL Query String",
                "severity": "high",
                "cwe": "CWE-522",
                "attack_type": "sensitive-param",
                "evidence": (
                    f"Credential detected in query string: {', '.join(hits)}. "
                    f"These appear in server logs, browser history, and Referer headers."
                ),
                "confirmed": True,
                "validated_by": ["pattern"],
            },
            "vulnerable",
        )

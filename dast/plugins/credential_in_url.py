"""
Credential in URL plugin — flags when passwords, tokens, or API keys appear
in query string parameters. These end up in server access logs, browser
history, and referrer headers — a common misconfiguration in older integrations.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse
from typing import TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

_SENSITIVE_PARAM_RE = re.compile(
    r'^(?:password|passwd|pass|pwd|secret|api[_-]?key|apikey|access[_-]?token|'
    r'auth[_-]?token|token|private[_-]?key|client[_-]?secret|app[_-]?secret|'
    r'credentials?|session[_-]?token|bearer)$',
    re.IGNORECASE,
)

# Minimum value length to avoid false positives on empty/placeholder values
_MIN_VALUE_LEN = 6


class CredentialInUrlPlugin(ProxyPlugin):
    name        = "credential-in-url"
    description = "Flags passwords, tokens, and API keys passed in URL query parameters"
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
            if not _SENSITIVE_PARAM_RE.match(name):
                continue
            value = values[0] if values else ""
            if len(value) >= _MIN_VALUE_LEN:
                hits.append(f"{name}={value}")

        if not hits:
            return

        store.add_finding(
            entry.id,
            {
                "title": "Sensitive Credential Passed in URL Query String",
                "severity": "high",
                "cwe": "CWE-598",
                "attack_type": "credential-in-url",
                "evidence": (
                    f"Sensitive parameters found in query string: {', '.join(hits)}. "
                    f"These values appear in server access logs, browser history, and Referer headers."
                ),
                "confirmed": True,
                "validated_by": ["pattern"],
            },
            "vulnerable",
        )

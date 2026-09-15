"""
Target-URL validation for operator-driven browser opens.

The "Open Browser" action in an auth pause (Exploration Copilot and the headless
Vuln Validator) is deliberately initiated by the human operator against the
target they are already scanning — commonly a local DAST lab (DVWA, Juice Shop,
VAmPI) on 127.0.0.1 or a private address. This is NOT a server-side request the
scanner makes on its own behalf, so the SSRF guard `_is_safe_url` (which rejects
loopback/private/reserved hosts to stop the validator reaching internal
infrastructure) is the wrong gate here: it blocks exactly the local targets the
operator means to open.

Guard only against what a browser open must never do: a non-http(s) scheme
(file:, javascript:, data:, ...) or a URL with no host. Loopback and private
addresses are allowed on purpose.
"""

from __future__ import annotations

from urllib.parse import urlparse

_BROWSABLE_SCHEMES = {"http", "https"}


def is_openable_target_url(url: str) -> bool:
    """Return True for an http/https URL with a non-empty host.

    Permits loopback/private targets (operator-driven browser open of a local
    DAST target); rejects non-http(s) schemes and host-less URLs.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in _BROWSABLE_SCHEMES:
        return False
    return bool(parsed.hostname)

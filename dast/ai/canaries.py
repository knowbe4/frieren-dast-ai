"""
Shared probe markers — one definition per marker so detectors and validators agree.

Kept dependency-free so agents, the FP filter, and the red-team validator can all
import it without creating import cycles.
"""

from typing import Optional
from urllib.parse import urlparse

# Open redirect: an RFC 2606 .invalid host that can never resolve, so a redirect to
# it is unambiguous proof the destination came from our input.
OPEN_REDIRECT_CANARY_HOST = "dast-redirect-canary.invalid"

# SSTI: product of two primes, unlikely to appear on a page by chance.
# 8887 * 8893 = 79032091
SSTI_ARITHMETIC_EXPR = "8887*8893"
SSTI_ARITHMETIC_PRODUCT = "79032091"


def redirect_target_host(location: str) -> Optional[str]:
    """Hostname a browser would navigate to for a Location value, or None if same-origin.

    Browsers treat backslashes like forward slashes in special-scheme URLs, so
    ``/\\host`` and ``\\\\host`` are protocol-relative too.
    """
    normalised = (location or "").strip().replace("\\", "/")
    if normalised.startswith("//"):
        normalised = "http:" + normalised
    parsed = urlparse(normalised)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return parsed.hostname.lower()


def is_redirect_to_canary(location: str) -> bool:
    """True when the redirect leaves the site for the open-redirect canary host."""
    return redirect_target_host(location) == OPEN_REDIRECT_CANARY_HOST

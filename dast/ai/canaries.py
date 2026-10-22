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

# A recognisable marker written into SPA form fields the explorer fills, so the
# submitted value is easy to spot in captured traffic and never looks like real
# data. Benign (no payload) — the explorer only submits to CAPTURE the request;
# the scanner mutates it afterwards.
FORM_CANARY_MARKER = "dastcanary7x9z"


def form_field_value(field_type: str, field_name: str = "") -> str:
    """A benign, type-valid value for a form input the explorer is filling.

    Type-aware so the value passes client-side validation and the form actually
    submits (reaching wizard step 2+ and capturing the update request). Carries
    FORM_CANARY_MARKER where free text is allowed so it is identifiable later.
    """
    kind = (field_type or "").lower()
    name = (field_name or "").lower()
    if kind in ("email",) or "email" in name:
        return f"{FORM_CANARY_MARKER}@example.com"
    if kind in ("number", "range") or "phone" in name or "zip" in name:
        return "1"
    if kind == "date":
        return "2000-01-01"
    if kind == "url" or "url" in name or "website" in name:
        return f"https://{FORM_CANARY_MARKER}.example.com"
    if kind == "password":
        # Non-trivial but obviously synthetic; never a real credential.
        return f"{FORM_CANARY_MARKER}-Aa1!"
    if kind == "tel":
        return "15555550100"
    return FORM_CANARY_MARKER


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

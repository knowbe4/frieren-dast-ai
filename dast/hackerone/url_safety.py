"""
Input safety helpers for the HackerOne validator.

Everything here is pure and deterministic: deciding whether a proof URL is
safe to drive, repairing common copy/paste breakage in proof URLs, swapping a
destructive payload for a safe variant, and sanitising user-supplied cookies
before they reach a request header or browser context.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict
from urllib.parse import quote, urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

SAFE_SCHEMES = {"http", "https"}
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_INTERNAL_HOSTNAMES = ("localhost", "metadata.google.internal")
_CRLF_RE = re.compile(r"[\r\n]")
_MAX_COOKIE_NAME_LENGTH = 128
_MAX_COOKIE_VALUE_LENGTH = 4096


def is_safe_url(url: str) -> bool:
    """Return True only for http/https URLs that don't point at private addresses."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception as exc:
        logger.debug("Proof URL could not be parsed", error=str(exc))
        return False
    if parsed.scheme not in SAFE_SCHEMES:
        return False
    host = parsed.hostname or ""
    if not host:
        return False
    # Reject obvious internal hostnames
    if host in _INTERNAL_HOSTNAMES or host.endswith(".internal"):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True  # a hostname, not an IP literal — allow
    return not any(address in network for network in PRIVATE_NETWORKS)


def repair_proof_url(url: str) -> str:
    """
    Deterministically normalize a proof URL so the browser drives the payload the
    reporter actually intended.

    The most common breakage: a ``javascript:`` redirect payload embeds literal
    ``+`` characters for JS string concatenation (``'loca'+'tion'``). In a URL
    query string a bare ``+`` decodes to a SPACE, so the browser turns
    ``'loca'+'tion'`` into ``'loca' 'tion'`` — invalid JS — and the redirect
    never fires. Reporters who got it working wrote ``%2b`` instead. We restore
    that: inside a ``javascript:`` parameter value, re-encode bare ``+`` as
    ``%2b`` so concatenation survives the browser's query decode.

    Also decodes HTML entities (``&amp;`` -> ``&``) that leak in from
    copy-pasted report bodies. Deterministic and cheap — the LLM repair is only a
    later fallback when this is not enough.

    Returns the URL unchanged when there is nothing to repair.
    """
    if not url:
        return url
    repaired = url.replace("&amp;", "&")
    # Only touch the '+' characters that sit inside a javascript: payload — never
    # a legitimate '+' elsewhere in the URL. Find "javascript:" and re-encode
    # bare '+' from there to the end of that parameter (next '&' or end).
    javascript_start = repaired.lower().find("javascript:")
    if javascript_start == -1:
        return repaired
    # The javascript payload runs until the next unencoded parameter break.
    javascript_end = repaired.find("&", javascript_start)
    if javascript_end == -1:
        javascript_end = len(repaired)
    head = repaired[:javascript_start]
    segment = repaired[javascript_start:javascript_end].replace("+", "%2b")
    tail = repaired[javascript_end:]
    return head + segment + tail


def substitute_payload_in_url(url: str, payload: str, safe_variant: str) -> str:
    """
    Replace the destructive payload inside a proof URL with a safe variant.

    Handles both the raw and URL-encoded forms of the payload. Returns the URL
    unchanged if the payload cannot be located (caller treats that as a block —
    we never fall through to sending the destructive original).
    """
    if not payload or not safe_variant:
        return url
    encoded_safe = quote(safe_variant, safe="")
    # Try raw, then singly-encoded, then doubly-encoded forms of the payload.
    candidates = [payload, quote(payload, safe=""), quote(quote(payload, safe=""), safe="")]
    for needle in candidates:
        if needle and needle in url:
            # Substitute an encoded replacement so the URL stays well-formed.
            return url.replace(needle, encoded_safe)
    return url


def sanitise_cookies(cookies: Dict[str, str]) -> Dict[str, str]:
    """Strip CRLF and limit key/value length to prevent header injection."""
    safe_cookies: Dict[str, str] = {}
    for name, value in (cookies or {}).items():
        clean_name = _CRLF_RE.sub("", str(name))[:_MAX_COOKIE_NAME_LENGTH]
        clean_value = _CRLF_RE.sub("", str(value))[:_MAX_COOKIE_VALUE_LENGTH]
        if clean_name:
            safe_cookies[clean_name] = clean_value
    return safe_cookies

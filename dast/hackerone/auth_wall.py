"""
Authentication-wall detection for the HackerOne validator.

Decides whether a response (status + final URL + body) is a login page,
permission denial, session-expired message or CAPTCHA challenge, so the
validator can ask for an authenticated session instead of mis-reporting the
vulnerability as not reproduced.
"""

from __future__ import annotations

import re

from dast.utils.logger import get_logger

logger = get_logger(__name__)

AUTH_REDIRECT_RE = re.compile(
    r'(login|signin|sign.in|sign_in|auth|sso|unauthorized|access.denied|session.expired'
    r'|please.log.in|you.must.log.in|not.authenticated|token.expired|jwt.expired)',
    re.IGNORECASE,
)

CAPTCHA_RE = re.compile(r'(captcha|recaptcha|hcaptcha|cloudflare|challenge)', re.IGNORECASE)

_AUTH_STATUS_CODES = (401, 403, 407)
_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)
_BODY_SNIPPET_LENGTH = 2000


def looks_like_auth_wall(status_code: int, url: str, body: str) -> bool:
    """Return True when the response looks like an authentication/permission wall."""
    # Explicit auth/permission codes
    if status_code in _AUTH_STATUS_CODES:
        return True
    # Redirect to anything that smells like a login page
    if status_code in _REDIRECT_STATUS_CODES:
        return bool(AUTH_REDIRECT_RE.search(url))
    # 200 response that is actually a login page or session-expired message
    if status_code == 200:
        snippet = body[:_BODY_SNIPPET_LENGTH]
        if AUTH_REDIRECT_RE.search(snippet):
            return True
        if CAPTCHA_RE.search(snippet):
            return True
    return False

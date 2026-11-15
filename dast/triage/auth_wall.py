"""
Authentication-wall detection for the external validator and the session checks.

Decides whether a response (status + final URL + body) is a login page,
permission denial, session-expired message or CAPTCHA challenge, so the
validator can ask for an authenticated session instead of mis-reporting the
vulnerability as not reproduced, and the session probes can tell a dead session
from a live one.

Signal design (deliberately asymmetric — a false WALL costs more than a false
CLEAR, because a wall triggers re-login loops):

- Status codes (401/403/407) and redirects to a login-ish URL stay authoritative.
- On a 200 body, only STRONG phrases ("session expired", "please log in", ...)
  or a concrete CAPTCHA/challenge marker classify as a wall. The old regex
  matched the substrings `auth`/`sso`/`login` ANYWHERE in the page — the word
  "Login" in every site's nav bar turned every page into a "session expired" —
  and `cloudflare`/`challenge` matched plain CDN script tags. Those weak tokens
  now require structural login-form evidence (a form / password input) in the
  snippet.
"""

from __future__ import annotations

import re

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Redirect-target check: the URL itself is a strong signal (a 302 whose Location
# lands on /login is not an accident), so broader tokens are acceptable here.
AUTH_REDIRECT_RE = re.compile(
    r'(login|signin|sign.in|sign_in|auth|sso|unauthorized|access.denied|session.expired'
    r'|please.log.in|you.must.log.in|not.authenticated|token.expired|jwt.expired)',
    re.IGNORECASE,
)

# 200-body phrases that DEFINITELY say "you are not logged in".
_STRONG_BODY_RE = re.compile(
    r'(session\s+expired|your\s+session\s+has|you\s+have\s+been\s+logged\s+out'
    r'|please\s+(?:log|sign)\s+in|you\s+must\s+(?:log|sign)\s+in'
    r'|log\s+in\s+to\s+continue|sign\s+in\s+to\s+continue'
    r'|not\s+authenticated|authentication\s+required'
    r'|token\s+expired|jwt\s+expired|access\s+denied)',
    re.IGNORECASE,
)

# Weak tokens ("login" nav links, "auth" in copy) — only a wall WITH form evidence.
_WEAK_BODY_RE = re.compile(r'(\blogin\b|\bsign[\s-]?in\b|\bsso\b|\bauth\b)', re.IGNORECASE)
_LOGIN_FORM_RE = re.compile(
    r'(<form|type\s*=\s*["\']?password|name\s*=\s*["\']?password|<input[^>]*password'
    r'|forgot\s+your\s+password)',
    re.IGNORECASE,
)

# Concrete CAPTCHA / bot-challenge markers. Bare "cloudflare" (every CDN script tag)
# and bare "challenge" (any word in copy) are NOT markers.
_CAPTCHA_RE = re.compile(
    r'(captcha|recaptcha|hcaptcha|turnstile|cf-chl|challenge-platform'
    r'|checking\s+your\s+browser|just\s+a\s+moment|attention\s+required'
    r'|verif(?:y|ying)\s+(?:that\s+)?(?:you\s+are\s+)?(?:a\s+)?human)',
    re.IGNORECASE,
)

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
        if _STRONG_BODY_RE.search(snippet):
            return True
        if _CAPTCHA_RE.search(snippet):
            return True
        # Weak tokens ("Login" in the nav) need login-form structure in the snippet.
        if _WEAK_BODY_RE.search(snippet) and _LOGIN_FORM_RE.search(snippet):
            return True
    return False

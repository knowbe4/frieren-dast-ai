"""
CSRF Passive Observer plugin — flags state-changing requests that lack CSRF protection.

Detects two conditions passively, without sending any probes:

1. State-changing request (POST/PUT/PATCH/DELETE) with no CSRF token in headers or
   body params, and no SameSite=Strict/Lax cookie as a natural CSRF defence.

2. Session cookie served without SameSite attribute (or SameSite=None without Secure),
   which means the browser will send it cross-origin and CSRF is feasible.

These are signals for the active CsrfAgent to confirm — they do not fire a confirmed
finding on their own. The CsrfAgent is queued to actively probe when condition 1 fires.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

_STATE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_CSRF_HEADER_RE = re.compile(
    r'x-csrf-token|x-xsrf-token|x-requested-with|x-request-token',
    re.IGNORECASE,
)
_CSRF_PARAM_RE = re.compile(
    r'csrf|xsrf|_token|authenticity_token|anti.?forgery|request.?verification',
    re.IGNORECASE,
)

# Paths that are inherently not exploitable for CSRF (auth/logout/static)
_SKIP_PATH_RE = re.compile(
    r'/logout|/logoff|/sign.out|/health|/metrics|/ping|/favicon|/static',
    re.IGNORECASE,
)

# Content-types that browsers can send cross-origin without a preflight —
# these are the ones where CSRF is most feasible
_SIMPLE_CT_RE = re.compile(
    r'application/x-www-form-urlencoded|multipart/form-data|text/plain',
    re.IGNORECASE,
)


def _has_csrf_token(entry: "ProxyEntry") -> bool:
    """Return True if the request carries any recognisable CSRF token."""
    for header in entry.request_headers or {}:
        if _CSRF_HEADER_RE.search(header):
            return True
    body = ""
    if entry.request_body:
        try:
            body = entry.request_body.decode("utf-8", errors="replace")
        except Exception:
            pass
    if body:
        # Form-encoded or JSON param check
        for part in re.split(r'[&\n]', body):
            key = part.split("=", 1)[0].split('"', 1)[-1].split(":", 1)[0].strip('" ')
            if _CSRF_PARAM_RE.search(key):
                return True
    return False


def _iter_set_cookies(response_headers: dict):
    """Yield each Set-Cookie string, handling both str and list values."""
    for header, value in (response_headers or {}).items():
        if header.lower() == "set-cookie":
            if isinstance(value, list):
                yield from value
            else:
                yield value


def _has_samesite_cookie(entry: "ProxyEntry") -> bool:
    """Return True if any Set-Cookie in the response has SameSite=Strict or SameSite=Lax."""
    for cookie in _iter_set_cookies(entry.response_headers):
        if re.search(r'samesite\s*=\s*(strict|lax)', cookie, re.IGNORECASE):
            return True
    return False


class CsrfObserverPlugin(ProxyPlugin):
    name        = "csrf-observer"
    description = "Passively flags state-changing requests without CSRF tokens or SameSite cookies"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        if entry.method not in _STATE_METHODS:
            return
        if not entry.response_status:
            return
        # Skip non-2xx responses — if the server rejected it already there's nothing to flag
        if entry.response_status < 200 or entry.response_status >= 300:
            return
        if _SKIP_PATH_RE.search(entry.path or ""):
            return

        # Check 1 — no CSRF token and no SameSite cookie defence
        if not _has_csrf_token(entry) and not _has_samesite_cookie(entry):
            ct = (entry.request_headers or {}).get("content-type", "")
            is_simple = bool(_SIMPLE_CT_RE.search(ct)) or not ct
            severity = "medium" if is_simple else "low"
            store.add_finding(
                entry.id,
                {
                    "title": "State-Changing Request Without CSRF Token",
                    "severity": severity,
                    "cwe": "CWE-352",
                    "attack_type": "csrf",
                    "evidence": (
                        f"{entry.method} {entry.path} returned {entry.response_status} "
                        f"with no CSRF token in headers or body, and no SameSite cookie. "
                        f"Content-Type: {ct or '(none)'}."
                    ),
                    "confirmed": False,
                    "validated_by": ["pattern"],
                    "needs_active_validation": True,
                },
                "safe",
            )

            # Queue for active CSRF agent confirmation. The active agent IS the AI
            # feature, so the scan worker only runs this when AI mode is on; with
            # AI off the passive finding above still surfaces on its own. ai_queued
            # only lets the deliberate re-scan bypass dedup, not the ai_mode gate.
            if not entry.queued_for_scan and not entry.scan_result:
                entry.ai_queued = True
                entry.queued_for_scan = True
                entry.import_hints = list(entry.import_hints or []) + [
                    {"parameter": "", "payload": "", "attack_type": "csrf"}
                ]
                store.enqueue_for_scan(entry.id)
            return

        # Check 2 — session cookie without SameSite (or SameSite=None without Secure)
        # This is one-per-host noise — the cookie_flags passive rule covers this better,
        # so we only fire here if no CSRF token was seen at all on this state-changing request.
        for value in _iter_set_cookies(entry.response_headers):
            name_match = re.match(r'([^=]+)=', value)
            if not name_match:
                continue
            cookie_name = name_match.group(1).strip().lower()
            # Focus on session-like cookies
            if not re.search(r'sess|auth|token|login|id', cookie_name, re.IGNORECASE):
                continue
            has_samesite = bool(re.search(r'samesite\s*=', value, re.IGNORECASE))
            samesite_none = bool(re.search(r'samesite\s*=\s*none', value, re.IGNORECASE))
            has_secure = bool(re.search(r'\bsecure\b', value, re.IGNORECASE))
            if not has_samesite or (samesite_none and not has_secure):
                store.add_finding(
                    entry.id,
                    {
                        "title": "Session Cookie Missing SameSite — CSRF Risk",
                        "severity": "medium",
                        "cwe": "CWE-352",
                        "attack_type": "csrf",
                        "evidence": (
                            f"Cookie '{cookie_name}' set without SameSite attribute "
                            f"(or SameSite=None without Secure). Browser will include it "
                            f"in cross-origin requests, making CSRF feasible."
                        ),
                        "confirmed": False,
                        "validated_by": ["pattern"],
                    },
                    "safe",
                )
                break  # one per entry is enough

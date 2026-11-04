"""Detect model-emitted placeholder values.

An LLM that lacks a real value (a password, a JWT, an id) often substitutes a
stand-in like ``<UNKNOWN>`` or ``<your_password>``. Those must never be sent to a
live target: they are noise, they can lock accounts, and they teach nothing. This
module is the single place that decides whether a string is such a placeholder, so
login, HTTP and GraphQL tools share one definition instead of duplicating it.

Precision matters: a real payload (an XSS probe like ``<script>``, an HTML body,
``a < b``) must NOT be flagged. So we match only two unambiguous shapes:
  1. the whole value IS a sentinel word (``unknown``, ``redacted`` ...), and
  2. a ``<...>`` token whose inner word is a known placeholder keyword
     (``<UNKNOWN>``, ``<jwt>``, ``<your_password>``) — a real HTML tag like
     ``<script>`` or an attribute-bearing ``<img src=x>`` does not match.
"""

from __future__ import annotations

import re

# The whole value equals one of these (used for short fields: url host, a header
# value, a password). Case-insensitive, surrounding brackets/quotes stripped.
_SENTINELS = frozenset({
    "unknown", "redacted", "placeholder", "changeme", "your_password",
    "yourpassword", "your-password", "your_email", "youremail", "n/a", "na",
    "tbd", "todo", "none", "null", "example", "xxx", "xxxx",
})

# Inner word of a ``<...>`` template token that marks a placeholder. Kept to
# meta-words a real request body would not contain inside angle brackets.
_PLACEHOLDER_TOKENS = frozenset({
    "unknown", "redacted", "placeholder", "changeme", "example", "value",
    "todo", "fixme", "fill", "fill_me", "fillme",
    "your_password", "your password", "yourpassword",
    "your_email", "your email", "youremail",
    "token", "jwt", "secret", "password", "email", "id", "host", "url",
})

# A ``<...>`` token with a short word-ish inside (letters/digits/_/-/space only,
# 2-40 chars). Excludes anything with other punctuation (e.g. ``<img src=x>``),
# so HTML/XSS payloads are not matched.
_BRACKET_TOKEN = re.compile(r"<\s*([a-z0-9_ -]{2,40})\s*>", re.IGNORECASE)


def looks_like_placeholder(value: str) -> bool:
    """True when ``value`` is (or contains) a model placeholder stand-in."""
    text = (value or "").strip()
    if not text:
        return False
    if text.lower().strip("<>[](){}\"'") in _SENTINELS:
        return True
    for match in _BRACKET_TOKEN.finditer(text):
        inner = match.group(1).strip().lower().replace("-", "_")
        if inner in _PLACEHOLDER_TOKENS or inner.replace("_", " ") in _PLACEHOLDER_TOKENS:
            return True
    return False

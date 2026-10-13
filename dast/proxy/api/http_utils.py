"""
Small HTTP helpers shared by the manual-tool routes (Repeater, Intruder, GraphQL).
"""

from __future__ import annotations

from typing import Dict, Mapping

# Headers the HTTP client must compute itself for the re-sent request. Copying them
# from a captured request breaks the resend (wrong length, stale host, compressed
# body the tool cannot render).
_RECOMPUTED_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection", "accept-encoding",
})


def strip_recomputed_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    """Return a copy of ``headers`` without hop-by-hop / client-computed headers.

    Case-insensitive: the old per-route copies only removed the lower-case and
    Title-Case spellings, so e.g. ``HOST`` slipped through.
    """
    return {name: value for name, value in headers.items() if name.lower() not in _RECOMPUTED_HEADERS}

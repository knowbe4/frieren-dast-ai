"""
Global HTTP history search.

The history table only carries a short request-body preview, so a client-side
filter can never find a token buried in a response body or a header. This
module searches the full stored entry: method, URL, status, request/response
headers and decoded bodies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, List, Optional

from dast.proxy.signalr import decode_body
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry

logger = get_logger(__name__)

# Bodies beyond this are only searched in their first bytes — keeps a search
# over thousands of entries interactive when a few responses are huge bundles.
_MAX_BODY_SEARCH_BYTES = 1_000_000


def _headers_text(headers: Optional[dict]) -> str:
    lines = []
    for name, value in (headers or {}).items():
        values = value if isinstance(value, list) else [value]
        lines.extend(f"{name}: {item}" for item in values)
    return "\n".join(lines)


def _body_text(raw: Optional[bytes], path: str) -> str:
    if not raw:
        return ""
    return decode_body(raw[:_MAX_BODY_SEARCH_BYTES], path) or ""


def entry_matches(entry: "ProxyEntry", needle: str) -> bool:
    """Case-insensitive substring match over every searchable part of an entry.

    `needle` must already be lowercased. Cheap fields are checked first so most
    hits never decode a body.
    """
    cheap_fields = (
        entry.method,
        entry.url,
        str(entry.response_status or ""),
        entry.probe_payload or "",
        entry.manual_note or "",
    )
    if any(needle in field.lower() for field in cheap_fields):
        return True
    if needle in _headers_text(entry.request_headers).lower():
        return True
    if needle in _headers_text(entry.response_headers).lower():
        return True
    if needle in _body_text(entry.request_body, entry.path).lower():
        return True
    return needle in _body_text(entry.response_body, entry.path).lower()


def search_entries(entries: Iterable["ProxyEntry"], query: str) -> List[str]:
    """Return the IDs of entries matching `query` (empty query matches nothing)."""
    needle = query.strip().lower()
    if not needle:
        return []
    matched_ids: List[str] = []
    for entry in entries:
        try:
            if entry_matches(entry, needle):
                matched_ids.append(entry.id)
        except Exception as exc:
            logger.warning("History search skipped entry", entry_id=entry.id, error=str(exc))
    logger.debug("History search", query_length=len(needle), matches=len(matched_ids))
    return matched_ids

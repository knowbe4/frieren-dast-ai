"""
Auth-header sniffing — find the most recent request headers that look like
credentials, for the "borrow auth from a real request" use case shared by
session snapshotting, suggestion scanning, and code-validation probing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Iterable, Optional, Sequence

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry

logger = get_logger(__name__)

_AUTH_HEADER_NAMES = ("authorization", "x-auth-token", "x-api-key", "cookie")


def extract_auth_headers(
    entries: Iterable["ProxyEntry"],
    host: Optional[str] = None,
    *,
    include_subdomains: bool = True,
    exclude_sources: Sequence[str] = ("agent", "imported"),
    limit: Optional[int] = None,
) -> Dict[str, str]:
    """
    Scan `entries` in reverse chronological order and return the auth-relevant
    headers (Authorization, X-Auth-Token, X-Api-Key, Cookie) from the most
    recent matching entry.

    `host=None` disables host filtering — any entry qualifies (used when
    snapshotting "whatever this whole session looked like most recently").
    `include_subdomains` also matches entries whose host is a subdomain of
    (or a parent domain of) `host`, via a 3-label base-domain heuristic.
    `limit` caps how many of the already-reverse-ordered entries are scanned
    before giving up; omit for an unbounded scan.
    """
    base_domain = None
    if host and include_subdomains:
        base_domain = ".".join(host.split(".")[-3:]) if host.count(".") >= 2 else host

    scanned = list(entries)[:limit] if limit is not None else entries

    auth_headers: Dict[str, str] = {}
    for entry in scanned:
        if entry.source in exclude_sources:
            continue
        if host is not None:
            host_matches = entry.host == host or (
                base_domain is not None and entry.host.endswith(base_domain)
            )
            if not host_matches:
                continue
        for k, v in (entry.request_headers or {}).items():
            if k.lower() in _AUTH_HEADER_NAMES:
                auth_headers[k] = v
        if auth_headers:
            break

    return auth_headers

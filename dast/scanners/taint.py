"""
Taint marker correlation engine.

For a DAST tool the data *input* point and the data *output* point are frequently
not the same request: user input persisted at endpoint A can surface in the
response of endpoint B (stored XSS, second-order SQLi, cross-endpoint reflection,
log injection). Reflection-only detection on the injecting request misses all of
these.

This module mints a unique, benign, alphanumeric marker per injection point
(endpoint + parameter + location), remembers which point each marker came from,
and scans every observed response for markers that surface. A marker that appears
on a *different* endpoint than the one it was injected into is direct evidence of
a cross-endpoint data flow — the exact signal agents need to confirm stored /
second-order vulnerabilities.

The marker is pure lowercase alphanumeric so it survives HTML-encoding,
JSON-encoding and most sanitisers unchanged (there are no special characters to
escape), and carries a fixed prefix so a single regex pass over a response body
finds every marker regardless of how many are registered.

This module is pure logic (no I/O, no LLM). Agents and the passive correlator
plugin share one `TaintStore` instance hung off the session store.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Fixed marker prefix + 12 hex chars. "frtnt" = Frieren taint. Distinctive enough
# that a false collision with real page content is astronomically unlikely, and
# alphanumeric so no sanitiser mangles it.
MARKER_PREFIX = "frtnt"
_MARKER_RE = re.compile(MARKER_PREFIX + r"[0-9a-f]{12}")

# Safety ceiling on how many markers we remember at once (oldest evicted first).
# Guards against unbounded growth on a very large scan, not normal use.
_MAX_MARKERS = 5000


@dataclass(frozen=True)
class TaintMarker:
    """A unique marker injected at one specific injection point."""

    token: str
    source_url: str
    source_param: str
    source_location: str  # query | body | header | cookie | ...
    source_method: str
    created_at: float


@dataclass(frozen=True)
class TaintHit:
    """A registered marker observed surfacing in some response."""

    marker: TaintMarker
    observed_url: str
    observed_entry_id: Optional[str]
    is_cross_location: bool  # surfaced on a different endpoint than it was injected


def _endpoint_key(url: str) -> str:
    """Normalise a URL to host + path (ignore scheme, port, query, fragment)."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    return f"{host}{path}"


class TaintStore:
    """
    Thread-safe registry of taint markers and the correlations discovered for them.

    `mint()` is called at injection time; `find_hits()` is called on every observed
    response; `record_correlation()` persists de-duplicated cross-reference evidence
    that agents and the report can consume.
    """

    def __init__(self, max_markers: int = _MAX_MARKERS) -> None:
        self._lock = threading.Lock()
        self._markers: "OrderedDict[str, TaintMarker]" = OrderedDict()
        self._max_markers = max_markers
        # Recorded correlations, de-duplicated by (token, observed endpoint key).
        self._correlations: Dict[str, TaintHit] = {}

    def mint(
        self,
        source_url: str,
        source_param: str,
        source_location: str,
        source_method: str = "GET",
    ) -> str:
        """Create and register a unique marker for one injection point; return the token."""
        token = MARKER_PREFIX + uuid.uuid4().hex[:12]
        marker = TaintMarker(
            token=token,
            source_url=source_url,
            source_param=source_param,
            source_location=source_location,
            source_method=source_method,
            created_at=time.time(),
        )
        with self._lock:
            self._markers[token] = marker
            self._markers.move_to_end(token)
            while len(self._markers) > self._max_markers:
                evicted_token, _ = self._markers.popitem(last=False)
                logger.debug("Taint marker evicted (registry full)", token=evicted_token)
        logger.debug(
            "Taint marker minted",
            token=token,
            source_url=source_url,
            param=source_param,
            location=source_location,
        )
        return token

    def get(self, token: str) -> Optional[TaintMarker]:
        with self._lock:
            return self._markers.get(token)

    def find_hits(
        self,
        observed_url: str,
        body: str,
        observed_entry_id: Optional[str] = None,
    ) -> List[TaintHit]:
        """
        Scan a response body for any registered markers.

        One regex pass finds every marker-shaped token; unknown tokens (markers we
        never minted) are ignored. Returns a hit per distinct registered marker
        found, flagged cross-location when it surfaced on a different endpoint than
        the one it was injected into.
        """
        if not body or MARKER_PREFIX not in body:
            return []
        found_tokens = set(_MARKER_RE.findall(body))
        if not found_tokens:
            return []
        observed_key = _endpoint_key(observed_url)
        hits: List[TaintHit] = []
        with self._lock:
            for token in found_tokens:
                marker = self._markers.get(token)
                if marker is None:
                    continue
                is_cross = _endpoint_key(marker.source_url) != observed_key
                hits.append(
                    TaintHit(
                        marker=marker,
                        observed_url=observed_url,
                        observed_entry_id=observed_entry_id,
                        is_cross_location=is_cross,
                    )
                )
        return hits

    def record_correlation(self, hit: TaintHit) -> bool:
        """
        Persist a hit, de-duplicated by (token, observed endpoint).

        Returns True only the first time a given marker is seen surfacing on a given
        endpoint, so callers can emit a finding exactly once per data flow.
        """
        dedup_key = f"{hit.marker.token}@{_endpoint_key(hit.observed_url)}"
        with self._lock:
            if dedup_key in self._correlations:
                return False
            self._correlations[dedup_key] = hit
        logger.info(
            "Taint correlation recorded",
            token=hit.marker.token,
            source_url=hit.marker.source_url,
            source_param=hit.marker.source_param,
            source_location=hit.marker.source_location,
            observed_url=hit.observed_url,
            cross_location=hit.is_cross_location,
        )
        return True

    def correlations(self) -> List[TaintHit]:
        """All recorded correlations."""
        with self._lock:
            return list(self._correlations.values())

    def correlations_for_source(
        self,
        source_url: Optional[str] = None,
        source_param: Optional[str] = None,
    ) -> List[TaintHit]:
        """Recorded correlations filtered to a given injection point."""
        with self._lock:
            hits = list(self._correlations.values())
        result: List[TaintHit] = []
        for hit in hits:
            if source_url is not None and _endpoint_key(hit.marker.source_url) != _endpoint_key(source_url):
                continue
            if source_param is not None and hit.marker.source_param != source_param:
                continue
            result.append(hit)
        return result

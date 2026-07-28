"""
Traffic graph — infers parameter data flows from observed request sequences.

How it works (zero extra requests):
1. Every JSON response is indexed: host → path → {field: value}
2. Every request's params are checked against recently-seen response values
3. When a param value matches a field from a prior response, a CallEdge is recorded:
   source_url[field] → target_url[param]

This catches IDOR chains, JWT/token forwarding, and multi-step flows without
touching the application — purely from traffic that already passed through the proxy.

Example detected chain:
  GET /api/auth → response: { "userId": 42, "token": "abc" }
  GET /api/orders?userId=42  → CallEdge: /api/auth[userId] → /api/orders[userId]
  GET /api/items?token=abc   → CallEdge: /api/auth[token] → /api/items[token]
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

from dast.discovery.models import CallEdge
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# How long to keep response values in the index (seconds)
_TTL_SECONDS = 300
# Max response values kept per host (prevents unbounded memory)
_MAX_VALUES_PER_HOST = 2000
# Minimum value length to index (skip booleans, tiny ints)
_MIN_VALUE_LEN = 3
# Max value length to index (skip huge blobs)
_MAX_VALUE_LEN = 256


class _ValueIndex:
    """
    Per-host index of field values seen in JSON responses.
    value → [(field_name, source_url, timestamp)]
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # value_str → deque of (field_name, source_url, ts)
        self._index: Dict[str, deque] = defaultdict(deque)
        self._count = 0

    def add(self, field: str, value: str, source_url: str) -> None:
        if not (_MIN_VALUE_LEN <= len(value) <= _MAX_VALUE_LEN):
            return
        with self._lock:
            if self._count >= _MAX_VALUES_PER_HOST:
                return
            self._index[value].append((field, source_url, time.time()))
            self._count += 1

    def lookup(self, value: str) -> List[Tuple[str, str]]:
        """Return [(field_name, source_url)] for value, excluding expired entries."""
        with self._lock:
            hits = []
            now = time.time()
            q = self._index.get(value)
            if not q:
                return []
            for field, source_url, ts in q:
                if now - ts <= _TTL_SECONDS:
                    hits.append((field, source_url))
            return hits

    def prune(self) -> None:
        now = time.time()
        with self._lock:
            to_delete = []
            for value, q in self._index.items():
                fresh = deque(
                    item for item in q if now - item[2] <= _TTL_SECONDS
                )
                if fresh:
                    self._index[value] = fresh
                else:
                    to_delete.append(value)
                    self._count -= (len(q) - len(fresh))
            for k in to_delete:
                del self._index[k]


class TrafficGraph:
    """
    Observes requests and responses to build a call-chain graph.
    Thread-safe — called from the proxy's completion callback.
    """

    def __init__(self) -> None:
        # Per-host value index
        self._host_index: Dict[str, _ValueIndex] = defaultdict(_ValueIndex)
        # Accumulated edges: (source_url, source_field, target_url, target_param) → CallEdge
        self._edges: Dict[Tuple, CallEdge] = {}
        self._lock = threading.Lock()
        self._prune_counter = 0

    # ── public interface ────────────────────────────────────────────────

    def observe_response(self, host: str, url: str, response_body: Optional[bytes]) -> None:
        """
        Index all string/int values from a JSON response.
        Called by DiscoveryEngine after every completed entry.
        """
        if not response_body:
            return
        try:
            text = response_body[:32768].decode("utf-8", errors="replace")
            data = json.loads(text)
        except Exception:
            return

        idx = self._host_index[host]
        self._index_value(idx, data, url, depth=0)

        self._prune_counter += 1
        if self._prune_counter % 200 == 0:
            idx.prune()

    def observe_request(self, host: str, url: str, params: List[dict]) -> None:
        """
        Check request params against the value index to detect call chains.
        Called by DiscoveryEngine before/during scan.
        params: [{name, location, value}]
        """
        if not params:
            return

        idx = self._host_index.get(host)
        if not idx:
            return

        for param in params:
            value = str(param.get("value", ""))
            if not (_MIN_VALUE_LEN <= len(value) <= _MAX_VALUE_LEN):
                continue

            hits = idx.lookup(value)
            for field_name, source_url in hits:
                if source_url == url:
                    continue  # same endpoint, skip self-reference
                key = (source_url, field_name, url, param["name"])
                with self._lock:
                    if key not in self._edges:
                        confidence = 0.9 if field_name == param["name"] else 0.5
                        edge = CallEdge(
                            source_url=source_url,
                            source_field=field_name,
                            target_url=url,
                            target_param=param["name"],
                            sample_value=value[:64],
                            confidence=confidence,
                        )
                        self._edges[key] = edge
                        logger.debug(
                            "Traffic graph: call edge detected",
                            src=source_url,
                            field=field_name,
                            dst=url,
                            param=param["name"],
                        )

    def edges_for_url(self, url: str) -> List[CallEdge]:
        """Return all edges where target_url == url."""
        with self._lock:
            return [e for e in self._edges.values() if e.target_url == url]

    def all_edges(self) -> List[CallEdge]:
        with self._lock:
            return list(self._edges.values())

    # ── internals ──────────────────────────────────────────────────────

    def _index_value(self, idx: _ValueIndex, data, url: str, depth: int) -> None:
        if depth > 4:
            return
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    idx.add(str(k), str(v), url)
                elif isinstance(v, (dict, list)):
                    self._index_value(idx, v, url, depth + 1)
        elif isinstance(data, list):
            for item in data[:20]:  # cap list depth to avoid huge arrays
                self._index_value(idx, item, url, depth + 1)

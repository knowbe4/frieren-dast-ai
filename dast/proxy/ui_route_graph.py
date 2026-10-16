"""
UI-route graph — the frontier of discovered-but-unvisited SPA routes.

The SPA explorer (``dast/proxy/spa_explorer.py``) populates this as it drives the
app: every link / client-side route / click-destination it finds becomes a
``UiRoute`` in the ``frontier`` state, and each route it actually visits flips to
``visited``. The autonomous "complete" run consults it so the run does not
declare itself finished while routes remain unexplored.

This models NAVIGATION (UI routes), which is distinct from the HTTP-endpoint
coverage the scan gate already tracks. A route is keyed by ``route_key`` so
``/orders/1`` and ``/orders/2`` collapse to one node, consistent with how REST
endpoint coverage dedups via ``normalise_endpoint_path``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from dast.proxy.session_store import normalise_endpoint_path
from dast.utils.logger import get_logger

logger = get_logger(__name__)

FRONTIER = "frontier"
VISITED = "visited"
FAILED = "failed"


def normalise_route_key(url: str) -> str:
    """Collapse a URL to a stable route key: ``host + normalised path + normalised
    hash``. Numeric/UUID/long-hex segments become ``:id`` (in both the path and a
    ``#/...`` hash route) so instance routes dedup. Query string is dropped."""
    try:
        parsed = urlparse(url)
    except Exception:
        return url or ""
    host = (parsed.hostname or "").lower()
    path = normalise_endpoint_path(parsed.path or "/")
    fragment = parsed.fragment or ""
    # SPA hash routes (#/dashboard/42) carry the real route — normalise them too.
    if fragment.startswith("/"):
        fragment = normalise_endpoint_path(fragment)
    hash_part = f"#{fragment}" if fragment else ""
    return f"{host}{path}{hash_part}"


@dataclass
class UiRoute:
    route_key: str
    url: str
    state: str = FRONTIER
    discovered_via: str = "seed"      # seed | nav | routerlink | link | click | wizard
    discovered_from: Optional[str] = None   # parent route_key
    depth: int = 0
    first_seen: float = field(default_factory=time.time)
    visited_at: Optional[float] = None
    api_entries: int = 0              # in-scope API calls captured while on this route
    interactive_elements: int = 0
    forms_submitted: int = 0


class UiRouteGraph:
    """Thread-safe set of discovered UI routes keyed by ``route_key``."""

    def __init__(self) -> None:
        self._routes: Dict[str, UiRoute] = {}
        self._lock = threading.Lock()

    def add_discovered(
        self,
        url: str,
        *,
        via: str = "link",
        parent: Optional[str] = None,
        depth: int = 0,
    ) -> bool:
        """Register a discovered route. Returns True if it is new (so a caller can
        track frontier growth). A route already visited/failed is not reopened."""
        key = normalise_route_key(url)
        if not key:
            return False
        with self._lock:
            if key in self._routes:
                return False
            self._routes[key] = UiRoute(
                route_key=key, url=url, state=FRONTIER,
                discovered_via=via, discovered_from=parent, depth=depth,
            )
            return True

    def mark_visited(
        self,
        route_key: str,
        *,
        api_entries: int = 0,
        interactive_elements: int = 0,
        forms_submitted: int = 0,
    ) -> None:
        with self._lock:
            route = self._routes.get(route_key)
            if route is None:
                return
            route.state = VISITED
            route.visited_at = time.time()
            route.api_entries = api_entries
            route.interactive_elements = interactive_elements
            route.forms_submitted = forms_submitted

    def mark_failed(self, route_key: str) -> None:
        with self._lock:
            route = self._routes.get(route_key)
            if route is not None and route.state != VISITED:
                route.state = FAILED

    def get(self, route_key: str) -> Optional[UiRoute]:
        with self._lock:
            return self._routes.get(route_key)

    def frontier(self) -> List[UiRoute]:
        with self._lock:
            return [r for r in self._routes.values() if r.state == FRONTIER]

    def visited(self) -> List[UiRoute]:
        with self._lock:
            return [r for r in self._routes.values() if r.state == VISITED]

    def stats(self) -> Dict[str, int]:
        with self._lock:
            routes = list(self._routes.values())
        return {
            "total": len(routes),
            "visited": sum(1 for r in routes if r.state == VISITED),
            "frontier": sum(1 for r in routes if r.state == FRONTIER),
            "failed": sum(1 for r in routes if r.state == FAILED),
            "forms_submitted": sum(r.forms_submitted for r in routes),
        }

    def to_list(self) -> List[dict]:
        with self._lock:
            return [asdict(r) for r in self._routes.values()]

    @classmethod
    def from_list(cls, rows: Optional[List[dict]]) -> "UiRouteGraph":
        """Rehydrate from ``to_list`` output. Tolerates a missing/empty/old field so
        loading a session saved before this feature never raises."""
        graph = cls()
        if not rows:
            return graph
        valid = {f for f in UiRoute.__dataclass_fields__}
        for row in rows:
            if not isinstance(row, dict) or not row.get("route_key"):
                continue
            try:
                graph._routes[row["route_key"]] = UiRoute(**{k: v for k, v in row.items() if k in valid})
            except Exception as exc:  # noqa: BLE001 — never fail a session load on one bad row
                logger.warning("ui_route_graph: skipping malformed route row", error=str(exc))
        return graph

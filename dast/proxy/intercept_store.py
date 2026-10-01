"""
InterceptStore — request interception with pause/edit/forward.

Each intercepted request is paused as an asyncio.Event. The proxy coroutine
awaits the event; the dashboard API sets it when the user forwards or drops.

Supports two intercept phases:
  1. Request phase  — pauses before the request is sent to the server
  2. Response phase — pauses after the response is received, before it is
                      returned to the browser (only when intercept_response=True)
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PendingRequest:
    id: str
    method: str
    url: str
    host: str
    path: str
    headers: dict           # mutable — user edits applied here
    body: Optional[bytes]   # mutable — user edits applied here
    ts: float = field(default_factory=time.time)
    action: str = "pending"   # "forward" | "forward_modified" | "drop"

    # Response intercept fields — populated after the upstream response arrives
    resp_status: Optional[int] = None
    resp_headers: dict = field(default_factory=dict)
    resp_body: Optional[bytes] = None
    resp_action: str = "pending"   # "forward" | "forward_modified"

    # Immutable snapshot of the request as first intercepted, so the UI can show
    # an original-vs-modified diff (Burp-style) even after the operator edits the
    # mutable fields above. Captured in __post_init__; never touched by forward().
    orig_method: str = ""
    orig_url: str = ""
    orig_headers: dict = field(default_factory=dict)
    orig_body: Optional[bytes] = None
    # Same idea for the response phase, captured in begin_response_intercept().
    orig_resp_status: Optional[int] = None
    orig_resp_headers: dict = field(default_factory=dict)
    orig_resp_body: Optional[bytes] = None

    # Not serialised — lives only in memory
    _event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _resp_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    def __post_init__(self) -> None:
        # Snapshot the as-received request before any operator edit.
        self.orig_method = self.method
        self.orig_url = self.url
        self.orig_headers = dict(self.headers)
        self.orig_body = self.body

    @staticmethod
    def _decode(raw: Optional[bytes]) -> Optional[str]:
        if raw is None:
            return None
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def to_dict(self) -> dict:
        body_str = self._decode(self.body) if self.body else None
        resp_body_str = self._decode(self.resp_body)
        return {
            "id":                self.id,
            "method":            self.method,
            "url":               self.url,
            "host":              self.host,
            "path":              self.path,
            "headers":           self.headers,
            "body":              body_str,
            "ts":                self.ts,
            "action":            self.action,
            "resp_status":       self.resp_status,
            "resp_headers":      self.resp_headers,
            "resp_body":         resp_body_str,
            "resp_action":       self.resp_action,
            "orig_method":       self.orig_method,
            "orig_url":          self.orig_url,
            "orig_headers":      self.orig_headers,
            "orig_body":         self._decode(self.orig_body) if self.orig_body else None,
            "orig_resp_status":  self.orig_resp_status,
            "orig_resp_headers": self.orig_resp_headers,
            "orig_resp_body":    self._decode(self.orig_resp_body),
        }


class InterceptStore:
    """Thread-safe store for intercepted requests."""

    def __init__(self) -> None:
        self._enabled: bool = False
        self._intercept_response: bool = False
        self._pending: Dict[str, PendingRequest] = {}
        self._resp_queue: Dict[str, PendingRequest] = {}
        self._lock = threading.Lock()
        # Async broadcast callback — set by the dashboard after startup.
        # Called with no args whenever the queue changes.
        self._on_change: Optional[Callable] = None

    def set_broadcast_callback(self, callback: Callable) -> None:
        """Register an async callback that broadcasts queue updates to WebSocket clients."""
        self._on_change = callback

    def _notify(self) -> None:
        """Schedule the broadcast callback on the running event loop (non-blocking)."""
        if self._on_change is None:
            return
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(lambda: asyncio.ensure_future(self._on_change()))
        except RuntimeError:
            pass

    # ── toggle ────────────────────────────────────────────────────────────

    def toggle(self, enabled: Optional[bool] = None) -> bool:
        with self._lock:
            self._enabled = enabled if enabled is not None else not self._enabled
            if not self._enabled:
                # Turning off — forward all pending without modification
                for req in list(self._pending.values()):
                    req.action = "forward"
                    req._event.set()
                self._pending.clear()
                for req in list(self._resp_queue.values()):
                    req.resp_action = "forward"
                    req._resp_event.set()
                self._resp_queue.clear()
        logger.info("Intercept mode", enabled=self._enabled)
        self._notify()
        return self._enabled

    def set_intercept_response(self, enabled: bool) -> None:
        self._intercept_response = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def intercept_response(self) -> bool:
        return self._intercept_response

    @property
    def queue_size(self) -> int:
        return len(self._pending) + len(self._resp_queue)

    # ── queue management ──────────────────────────────────────────────────

    def add(
        self,
        method: str,
        url: str,
        host: str,
        path: str,
        headers: dict,
        body: Optional[bytes],
    ) -> PendingRequest:
        req = PendingRequest(
            id=str(uuid.uuid4()),
            method=method,
            url=url,
            host=host,
            path=path,
            headers=dict(headers),
            body=body,
        )
        with self._lock:
            self._pending[req.id] = req
        logger.info("Request intercepted", id=req.id, method=method, url=url)
        self._notify()
        return req

    def begin_response_intercept(
        self,
        req: "PendingRequest",
        status: int,
        headers: dict,
        body: bytes,
    ) -> "PendingRequest":
        """
        Move a forwarded request into the response-intercept phase.

        The request was already popped from _pending when forwarded.
        Re-register it in _resp_queue so the UI can display and edit the response.
        """
        req.resp_status = status
        req.resp_headers = dict(headers)
        req.resp_body = body
        req.resp_action = "pending"
        # Snapshot the as-received response for the original-vs-modified diff.
        req.orig_resp_status = status
        req.orig_resp_headers = dict(headers)
        req.orig_resp_body = body
        with self._lock:
            self._resp_queue[req.id] = req
        self._notify()
        return req

    def forward_response(
        self,
        req_id: str,
        modified: Optional[dict] = None,
    ) -> bool:
        """Forward a response, optionally with user-edited fields."""
        with self._lock:
            req = self._resp_queue.pop(req_id, None)
            if not req:
                return False
            if modified:
                if "status" in modified and modified["status"]:
                    try:
                        req.resp_status = int(modified["status"])
                    except (ValueError, TypeError):
                        pass
                if "headers" in modified and isinstance(modified["headers"], dict):
                    req.resp_headers = modified["headers"]
                if "body" in modified and modified["body"] is not None:
                    body_val = modified["body"]
                    req.resp_body = body_val.encode("utf-8") if isinstance(body_val, str) else body_val
                req.resp_action = "forward_modified"
            else:
                req.resp_action = "forward"
            req._resp_event.set()
        logger.info("Response forwarded", id=req_id, modified=bool(modified))
        self._notify()
        return True

    def get_queue(self) -> List[dict]:
        with self._lock:
            req_items  = [dict(r.to_dict(), phase="request")  for r in self._pending.values()]
            resp_items = [dict(r.to_dict(), phase="response") for r in self._resp_queue.values()]
        return req_items + resp_items

    def forward(self, req_id: str, modified: Optional[dict] = None) -> bool:
        """Forward a request, optionally with user-edited fields."""
        with self._lock:
            req = self._pending.pop(req_id, None)
            if not req:
                return False
            if modified:
                if "method" in modified:
                    req.method = modified["method"]
                if "url" in modified:
                    req.url = modified["url"]
                if "headers" in modified and isinstance(modified["headers"], dict):
                    req.headers = modified["headers"]
                if "body" in modified and modified["body"] is not None:
                    body_val = modified["body"]
                    req.body = body_val.encode("utf-8") if isinstance(body_val, str) else body_val
                req.action = "forward_modified"
            else:
                req.action = "forward"
            req._event.set()
        logger.info("Request forwarded", id=req_id, modified=bool(modified))
        self._notify()
        return True

    def drop(self, req_id: str) -> bool:
        """Drop a request — browser receives an empty 200."""
        with self._lock:
            req = self._pending.pop(req_id, None)
            if not req:
                # also check response queue
                req = self._resp_queue.pop(req_id, None)
                if not req:
                    return False
                req.resp_action = "drop"
                req._resp_event.set()
                logger.info("Response dropped", id=req_id)
                self._notify()
                return True
            req.action = "drop"
            req._event.set()
        logger.info("Request dropped", id=req_id)
        self._notify()
        return True

    def forward_all(self) -> int:
        """Forward all pending requests and responses without modification."""
        with self._lock:
            count = len(self._pending) + len(self._resp_queue)
            for req in self._pending.values():
                req.action = "forward"
                req._event.set()
            for req in self._resp_queue.values():
                req.resp_action = "forward"
                req._resp_event.set()
            self._pending.clear()
            self._resp_queue.clear()
        logger.info("Forward all", count=count)
        self._notify()
        return count

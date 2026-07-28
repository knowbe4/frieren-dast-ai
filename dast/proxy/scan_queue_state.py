"""
ScanQueueState — shared mutable object tracking the active scan queue.

Passed from ProxyRunner to build_app so both the scan worker and the
dashboard API read/write the same state without extra IPC.

Thread-safe assumptions: all mutations happen inside the asyncio event
loop (both the scan worker coroutines and the FastAPI request handlers
run in the same loop), so no locking is needed.
"""

from __future__ import annotations

import asyncio
import collections
import time
from typing import Dict, List, Optional


class ScanQueueState:
    def __init__(self) -> None:
        self.paused: bool = False
        self._pause_event: Optional[asyncio.Event] = None

        # Lists of dicts — ordered by queue position
        self.pending: List[dict] = []
        self.running: Dict[str, dict] = {}   # entry_id → item
        self.completed: collections.deque = collections.deque(maxlen=100)
        self._cancelled: set = set()
        self._running_tasks: Dict[str, asyncio.Task] = {}   # entry_id → Task

    # ── pause / resume ─────────────────────────────────────────────────

    def _event(self) -> asyncio.Event:
        if self._pause_event is None:
            self._pause_event = asyncio.Event()
            self._pause_event.set()   # not paused → event is set
        return self._pause_event

    def pause(self) -> None:
        self.paused = True
        self._event().clear()

    def resume(self) -> None:
        self.paused = False
        self._event().set()

    async def wait_if_paused(self) -> None:
        """Yield until the queue is not paused."""
        await self._event().wait()

    # ── queue lifecycle ────────────────────────────────────────────────

    def enqueue(self, entry_id: str, method: str, url: str, host: str, operation: str = "") -> None:
        self.pending.append({
            "id":        entry_id,
            "method":    method,
            "url":       url,
            "host":      host,
            "operation": operation,
            "queued_at": time.time(),
            "status":    "pending",
        })

    def dequeue(self, entry_id: str) -> None:
        """Move item from pending → waiting-for-slot (status='waiting')."""
        for p in self.pending:
            if p["id"] == entry_id:
                p["status"] = "waiting"
                break

    def start(self, entry_id: str, method: str, url: str, host: str, task: Optional[asyncio.Task] = None, operation: str = "") -> None:
        # Carry forward the operation label from pending if not explicitly provided
        existing = next((p for p in self.pending if p["id"] == entry_id), None)
        op = operation or (existing.get("operation", "") if existing else "")
        self.pending = [p for p in self.pending if p["id"] != entry_id]
        self.running[entry_id] = {
            "id":         entry_id,
            "method":     method,
            "url":        url,
            "host":       host,
            "operation":  op,
            "started_at": time.time(),
        }
        if task is not None:
            self._running_tasks[entry_id] = task

    def finish(self, entry_id: str, findings_count: int, status: str, reason: str = "") -> None:
        """status: 'safe' | 'vulnerable' | 'error' | 'cancelled' | 'skipped'"""
        self._running_tasks.pop(entry_id, None)
        item = self.running.pop(entry_id, None)
        if not item:
            # May have been cancelled before start() — pull from pending
            item = next((p for p in self.pending if p["id"] == entry_id), None)
            self.pending = [p for p in self.pending if p["id"] != entry_id]
        if item:
            item["finished_at"]    = time.time()
            item["findings_count"] = findings_count
            item["status"]         = status
            if reason:
                item["reason"] = reason
            self.completed.appendleft(item)

    # ── cancellation ───────────────────────────────────────────────────

    def cancel(self, entry_id: str) -> None:
        """Cancel a pending item. For running items, use stop_running() instead."""
        self._cancelled.add(entry_id)
        self.pending = [p for p in self.pending if p["id"] != entry_id]

    def stop_running(self, entry_id: str) -> bool:
        """Cancel a currently-running scan task. Returns True if a task was found."""
        task = self._running_tasks.get(entry_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    def cancel_all_pending(self) -> None:
        for p in self.pending:
            self._cancelled.add(p["id"])
        self.pending.clear()

    def is_cancelled(self, entry_id: str) -> bool:
        return entry_id in self._cancelled

    def clear_cancelled(self) -> None:
        self._cancelled.clear()

    # ── serialisation ──────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "paused":          self.paused,
            "pending":         list(self.pending),
            "running":         list(self.running.values()),
            "completed":       list(self.completed),
            "pending_count":   len(self.pending),
            "running_count":   len(self.running),
            "completed_count": len(self.completed),
        }

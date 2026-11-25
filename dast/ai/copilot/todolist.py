"""Mission todolist — prerequisite-ordered plan for autonomous runs (5-C-2).

The ARTEX insight the driver was missing: a todolist where later items have
PREREQUISITES turns "keep going until complete" into an ordered plan the loop
can reason about — you cannot escalate candidates before endpoints are
scanned, and you cannot compose chains before candidates are escalated. The
todolist gives the autonomous prompt a stable backbone (rendered every turn),
gives the deterministic driver hooks to mark real completions (scans ran,
escalations done, chains inventoried), and gives the stuck detector another
honest signal: a run whose todolist has not moved in N turns is not making
progress.

In-memory by design — it lives on the session dict like every other piece of
run state (the durable stores remain app_knowledge / coverage ledger /
login_journal under ~/.dast-ai).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_STATUSES = ("pending", "in_progress", "done", "failed")


@dataclass
class TodoItem:
    id: str
    title: str
    detail: str = ""
    prerequisites: List[str] = field(default_factory=list)
    status: str = "pending"
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "detail": self.detail,
                "prerequisites": list(self.prerequisites), "status": self.status,
                "updated_at": self.updated_at}


class MissionTodoList:
    """Ordered mission items with prerequisites and honest status tracking."""

    def __init__(self) -> None:
        self._items: Dict[str, TodoItem] = {}
        self.revision: int = 0  # bumped on every status change (stuck-detection input)

    @classmethod
    def seed_default(cls, objective: str = "") -> "MissionTodoList":
        """The canonical autonomous mission phases (ARTEX todolist shape)."""
        todo = cls()
        todo.add("map", "Map the target surface (crawl / explore / OpenAPI)")
        todo.add("auth", "Establish sessions for every login profile in play")
        todo.add("scan", "Scan the mapped endpoints (scan_surface / run_scan / sweeps)",
                 prerequisites=["map"])
        todo.add("escalate", "Escalate unconfirmed candidates with attack subagents",
                 prerequisites=["scan"])
        todo.add("chains", "Compose and validate attack chains from confirmed findings",
                 prerequisites=["escalate"])
        todo.add("wrapup", "Wrap up: findings recorded, coverage ledger honest",
                 prerequisites=["chains"])
        return todo

    @classmethod
    def from_dict(cls, items: List[dict]) -> "MissionTodoList":
        """Rebuild a todolist from ``to_dict()`` output (session resume 6-A-1).
        Preserves ids, statuses, prerequisites, details and ordering; the
        revision counter restarts at the item count (history is not durable)."""
        todo = cls()
        for raw in items or []:
            if not isinstance(raw, dict):
                continue
            item_id = str(raw.get("id", "")).strip()
            if not item_id:
                continue
            todo.add(
                item_id,
                str(raw.get("title", item_id)),
                detail=str(raw.get("detail", "")),
                prerequisites=[str(p) for p in (raw.get("prerequisites") or [])],
            )
            status = str(raw.get("status", "pending"))
            if status in _STATUSES:
                item = todo._items[item_id]
                item.status = status  # direct set — mark() would gate on prereqs
        todo.revision = len(todo._items)
        return todo

    # ── mutations ────────────────────────────────────────────────────────
    def add(self, id: str, title: str, detail: str = "",
            prerequisites: Optional[List[str]] = None) -> TodoItem:
        item = TodoItem(id=id, title=title, detail=detail,
                        prerequisites=list(prerequisites or []))
        self._items[id] = item
        self.revision += 1
        return item

    def mark(self, id: str, status: str, detail: str = "") -> bool:
        """Update an item's status. ``done`` requires all prerequisites done —
        a later item cannot honestly complete before its rungs."""
        if status not in _STATUSES:
            return False
        item = self._items.get(id)
        if item is None:
            return False
        if status == "done" and not self._prereqs_done(item):
            return False
        item.status = status
        if detail:
            item.detail = detail[:300]
        item.updated_at = time.time()
        self.revision += 1
        return True

    def _prereqs_done(self, item: TodoItem) -> bool:
        return all((self._items.get(p).status == "done")
                   for p in item.prerequisites if p in self._items)

    # ── queries ──────────────────────────────────────────────────────────
    def get(self, id: str) -> Optional[TodoItem]:
        return self._items.get(id)

    def next_actionable(self) -> List[TodoItem]:
        """Pending items whose prerequisites are all done — what the mission
        can legally start NOW (in seed order)."""
        return [item for item in self._items.values()
                if item.status == "pending" and self._prereqs_done(item)]

    def progress(self) -> dict:
        total = len(self._items)
        done = sum(1 for i in self._items.values() if i.status == "done")
        failed = sum(1 for i in self._items.values() if i.status == "failed")
        return {"done": done, "total": total, "failed": failed,
                "revision": self.revision}

    def to_dict(self) -> List[dict]:
        return [item.to_dict() for item in self._items.values()]

    # ── prompt rendering ─────────────────────────────────────────────────
    _GLYPH = {"pending": "○", "in_progress": "◐", "done": "●", "failed": "✗"}

    def render(self, max_items: int = 12) -> str:
        if not self._items:
            return ""
        prog = self.progress()
        lines = [f"Mission todolist ({prog['done']}/{prog['total']} done):"]
        for item in list(self._items.values())[:max_items]:
            glyph = self._GLYPH.get(item.status, "○")
            line = f"  {glyph} {item.title}"
            if item.detail:
                line += f" — {item.detail}"
            if item.prerequisites:
                line += f"  [after: {', '.join(item.prerequisites)}]"
            lines.append(line)
        nxt = self.next_actionable()
        if nxt:
            lines.append(f"Do NEXT: {nxt[0].title}")
        return "\n".join(lines)

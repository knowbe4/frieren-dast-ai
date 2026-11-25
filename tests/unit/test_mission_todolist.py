"""Unit tests for the mission todolist (5-C-2) — prerequisites, honest marks,
next-actionable queries and prompt rendering."""

from __future__ import annotations

import pytest

from dast.ai.copilot.todolist import MissionTodoList


@pytest.fixture
def todo():
    return MissionTodoList.seed_default("pwn the shop")


def test_seed_has_prerequisite_chain(todo):
    ids = [i.id for i in todo._items.values()]
    assert ids[:2] == ["map", "auth"]  # no prerequisites first
    scan = todo.get("scan")
    assert scan.prerequisites == ["map"]
    assert todo.get("escalate").prerequisites == ["scan"]
    assert todo.get("chains").prerequisites == ["escalate"]
    assert todo.get("wrapup").prerequisites == ["chains"]
    assert todo.progress()["total"] == 6


def test_done_requires_prerequisites(todo):
    """The escalate rung cannot 'complete' before its scan rung is done."""
    assert todo.mark("escalate", "done") is False
    assert todo.get("escalate").status == "pending"
    assert todo.mark("scan", "done") is False          # map not done yet
    todo.mark("map", "done")
    assert todo.mark("scan", "done") is True           # prerequisite satisfied
    assert todo.mark("escalate", "done") is True


def test_next_actionable_respects_prerequisites(todo):
    assert [i.id for i in todo.next_actionable()] == ["map", "auth"]
    todo.mark("map", "done")
    assert [i.id for i in todo.next_actionable()] == ["auth", "scan"]
    todo.mark("auth", "done")
    todo.mark("scan", "done")
    assert [i.id for i in todo.next_actionable()] == ["escalate"]


def test_mark_rejects_unknown_status_and_item(todo):
    assert todo.mark("map", "exploded") is False
    assert todo.mark("ghost", "done") is False


def test_revision_tracks_every_change(todo):
    before = todo.revision
    todo.mark("map", "in_progress")
    todo.mark("map", "done")
    assert todo.revision == before + 2


def test_render_shows_glyphs_prereqs_and_next(todo):
    todo.mark("map", "done", detail="12 endpoints")
    text = todo.render()
    assert "Mission todolist (1/6 done)" in text
    assert "● Map the target surface" in text
    assert "— 12 endpoints" in text
    assert "[after: map]" in text
    assert "Do NEXT:" in text


def test_render_empty_list_is_empty_string():
    assert MissionTodoList().render() == ""

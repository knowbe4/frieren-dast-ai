"""Copilot session snapshots — resume across process restarts (6-A-1).

Everything the copilot keeps in memory (sessions dict, engine conversation,
scratchpad, mission todolist, autonomous counters) dies with the process. This
module persists a JSON-serializable SNAPSHOT of each session under
``~/.dast-ai/copilot_sessions/<sid>.json`` using the atomic-write pattern from
``dast/profiles/store.py`` (a crash mid-write used to leave truncated files
silently skipped), so a restarted dashboard can list and CONTINUE past runs.

Live objects are never serialized: the asyncio Tasks/Events, the Playwright
browser and the ``CopilotSession`` instance itself are rebuilt on restore;
``store.ai_mode``/``defer_identity_hosts`` are process-global flags that a
killed run leaves behind only in the dead process's memory, so they need no
snapshot handling. Snapshots are capped (oldest pruned) and never raise to the
caller — persistence failures degrade to a log line, matching the store
conventions.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_DIR = Path.home() / ".dast-ai" / "copilot_sessions"
_MAX_SNAPSHOTS = 30

# session-dict keys that are live objects or per-process bookkeeping — rebuilt
# on restore, never serialized.
_TRANSIENT_SESSION_KEYS = {
    "engine", "_task", "_pause_event", "autonomous", "trace",
}

# autonomous-dict keys that are live objects or restart-meaningless.
_TRANSIENT_AUTONOMOUS_KEYS = {"stop_event", "pause_gate", "_agent_browser"}

# CopilotSession attributes worth carrying across a restart.
_ENGINE_STATE_KEYS = (
    "messages", "_scratchpad", "_scratchpad_persisted", "_session_cookies",
    "_bearer_tokens", "_seen_calls", "_repeat_sigs", "_sig_outcomes",
    "_sig_noprogress", "_focus_hosts", "_context_hosts", "_denied_hosts",
    "_ok_endpoints", "_primed_subapps", "session_name", "_downgrade_model",
    "_primed_subapp_notes",
)


def snapshots_dir() -> Path:
    _DIR.mkdir(parents=True, exist_ok=True)
    try:
        _DIR.chmod(0o700)
    except OSError:
        pass
    return _DIR


def _snapshot_path(sid: str) -> Path:
    safe = "".join(c for c in sid if c.isalnum() or c in "-_")[:80]
    return snapshots_dir() / f"{safe}.json"


def build_snapshot(sid: str, session: dict) -> Dict:
    """A JSON-serializable snapshot of one session dict + its engine state.
    The session dict keys state by sid (session_id is only added at render
    time), so the id is passed explicitly."""
    engine = session.get("engine")
    engine_state: Dict = {}
    if engine is not None:
        for key in _ENGINE_STATE_KEYS:
            value = getattr(engine, key, None)
            if value is None:
                continue
            if isinstance(value, set):
                value = sorted(value)
            engine_state[key] = value
    autonomous = session.get("autonomous")
    auto_state: Dict = {}
    if isinstance(autonomous, dict):
        auto_state = {
            k: v for k, v in autonomous.items()
            if k not in _TRANSIENT_AUTONOMOUS_KEYS and _jsonable(v)
        }
        todo = autonomous.get("todo")
        if todo is not None and hasattr(todo, "to_dict"):
            auto_state["todo"] = todo.to_dict()
        auto_state["status"] = "interrupted" if autonomous.get("status") in (
            "running", "starting", "paused") else autonomous.get("status", "")
    data: Dict = {
        "session_id": sid,
        "saved_at": time.time(),
        "engine_state": engine_state,
        "autonomous": auto_state,
    }
    for key in ("status", "created_at", "updated_at", "origin", "profile_slug",
                "last_reply", "escalation", "hypothesis", "approved_hosts",
                "_profile_activated", "_downgrade_armed"):
        value = session.get(key)
        if isinstance(value, set):
            value = sorted(value)   # sets are not JSON-able; a sorted list restores
        if _jsonable(value):
            data[key] = value
    return data


def _jsonable(value) -> bool:
    if value is None or isinstance(value, (bool, int, float, str, list, dict)):
        try:
            json.dumps(value)
            return True
        except (TypeError, ValueError):
            return False
    return False


def save_snapshot(sid: str, session: dict) -> bool:
    """Persist one session snapshot atomically. Never raises."""
    sid = str(sid or "")
    if not sid:
        return False
    try:
        payload = json.dumps(build_snapshot(sid, session), indent=2)
        snapshots_dir().mkdir(parents=True, exist_ok=True)
        path = _snapshot_path(sid)
        fd, tmp_name = tempfile.mkstemp(dir=str(snapshots_dir()),
                                        prefix=f".{path.stem}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        _prune()
        return True
    except Exception as exc:  # noqa: BLE001 — persistence must never break a turn
        logger.warning("copilot snapshot save failed", session_id=sid, error=str(exc))
        return False


def load_snapshots() -> Dict[str, Dict]:
    """All persisted snapshots keyed by session id, newest save first.
    Unreadable files are skipped with a log (store convention)."""
    result: Dict[str, Dict] = {}
    if not _DIR.exists():
        return result
    entries: List = []
    for f in _DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            sid = str(data.get("session_id", "") or f.stem)
            entries.append((float(data.get("saved_at", 0) or 0), sid, data))
        except Exception as exc:
            logger.warning("skipping unreadable copilot snapshot",
                           file=f.name, error=str(exc))
    for _, sid, data in sorted(entries, key=lambda e: e[0], reverse=True):
        result.setdefault(sid, data)
    return result


def delete_snapshot(sid: str) -> bool:
    path = _snapshot_path(str(sid or ""))
    if path.exists():
        try:
            path.unlink()
            return True
        except OSError:
            return False
    return False


def _prune() -> None:
    """Keep only the newest _MAX_SNAPSHOTS files."""
    try:
        files = sorted(_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime,
                       reverse=True)
        for stale in files[_MAX_SNAPSHOTS:]:
            stale.unlink()
    except Exception as exc:  # noqa: BLE001
        logger.debug("snapshot prune failed", error=str(exc))

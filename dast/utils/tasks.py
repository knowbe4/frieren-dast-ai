"""
Tracked background tasks.

``asyncio.create_task()`` only keeps a WEAK reference to the task: a fire-and-forget
task can be garbage-collected mid-run, and an exception it raises surfaces only as
"Task exception was never retrieved" at interpreter shutdown. ``spawn_tracked()``
keeps a strong reference until the task finishes and logs any exception it raised.

Usage:
    spawn_tracked(run_job(job_id), name="intruder-job")
"""

from __future__ import annotations

import asyncio
from typing import Coroutine, Optional, Set

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_BACKGROUND_TASKS: Set[asyncio.Task] = set()


def _on_done(task: asyncio.Task, registry: Set[asyncio.Task]) -> None:
    registry.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("Background task failed", task=task.get_name(), error=str(exc), exc_info=exc)


def spawn_tracked(
    coro: Coroutine,
    name: Optional[str] = None,
    registry: Optional[Set[asyncio.Task]] = None,
) -> asyncio.Task:
    """Create a task that is strongly referenced until done and whose errors are logged.

    Pass ``registry`` to track the task in a caller-owned set (e.g. to bound or
    await in-flight work); otherwise a module-level set is used.
    """
    target_registry = _BACKGROUND_TASKS if registry is None else registry
    task = asyncio.get_running_loop().create_task(coro, name=name)
    target_registry.add(task)
    task.add_done_callback(lambda finished: _on_done(finished, target_registry))
    return task

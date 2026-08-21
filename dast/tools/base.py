"""
Shared tool registry — the single source of truth for agent-callable capabilities.

Each capability is registered once as a ``Tool`` (name + description + JSON Schema
+ async handler) and is then usable identically by the internal agentic triage
loop and by the MCP server. One definition, two callers.

A handler receives ``(ctx, arguments)`` and returns a JSON-serialisable dict. By
convention every handler returns ``{"ok": bool, ...}`` and NEVER raises — a
failure becomes ``{"ok": False, "error": "..."}`` so a caller (or an LLM driving
MCP) always gets structured output. Scope and payload-safety are enforced inside
the handlers, not by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List

from dast.tools.context import ToolContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

ToolHandler = Callable[[ToolContext, Dict[str, Any]], Awaitable[Dict[str, Any]]]


@dataclass
class Tool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: ToolHandler
    # Non-schema tags for grouping/filtering (e.g. "recon", "triage"). Optional.
    tags: List[str] = field(default_factory=list)


_REGISTRY: Dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    """Register a tool. A duplicate name overwrites (last import wins) with a warn."""
    if tool.name in _REGISTRY:
        logger.warning("tool name already registered — overwriting", name=tool.name)
    _REGISTRY[tool.name] = tool
    return tool


def get_tool(name: str) -> Tool | None:
    return _REGISTRY.get(name)


def all_tools() -> List[Tool]:
    """Every registered tool, ordered by name for a stable listing."""
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


async def run_tool(ctx: ToolContext, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch to a tool's handler. Unknown tool / handler exception both degrade
    to a structured ``{"ok": False, "error": ...}`` — this function never raises."""
    tool = _REGISTRY.get(name)
    if tool is None:
        return {"ok": False, "error": f"unknown tool: {name}"}
    try:
        result = await tool.handler(ctx, arguments or {})
        if not isinstance(result, dict):
            return {"ok": True, "result": result}
        return result
    except Exception as exc:
        logger.warning("tool handler raised", tool=name, error=str(exc))
        return {"ok": False, "error": str(exc)[:300]}

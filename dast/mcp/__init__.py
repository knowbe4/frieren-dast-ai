"""
MCP server package — exposes the shared tool layer (``dast/tools/``) to external
AI clients over the Model Context Protocol.

The ``mcp`` dependency is imported lazily inside ``server.run_stdio`` so importing
this package (and the rest of Frieren) never requires ``mcp`` to be installed. The
tool DEFINITIONS are the same registry the internal agentic loop uses — one
definition, two callers.
"""

from __future__ import annotations

from dast.mcp.server import run_stdio, tool_definitions

__all__ = ["run_stdio", "tool_definitions"]

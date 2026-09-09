"""
Shared tool layer — the single source of truth for agent-callable capabilities.

One typed function + JSON Schema per capability, registered in ``base``. The same
registry powers the internal agentic triage loop and the external MCP server
(``dast-ai mcp``). Importing this package registers every built-in tool.

Add a tool: create ``<name>_tools.py`` with a ``register(Tool(...))`` call and
import it below — no other wiring needed.
"""

from __future__ import annotations

from dast.tools.base import Tool, all_tools, get_tool, register, run_tool
from dast.tools.context import ToolContext

# Import side effects register the built-in tools.
from dast.tools import chain_tools as _chain_tools  # noqa: F401
from dast.tools import encoding_tools as _encoding_tools  # noqa: F401
from dast.tools import findings_tools as _findings_tools  # noqa: F401
from dast.tools import history_tools as _history_tools  # noqa: F401
from dast.tools import http_tools as _http_tools  # noqa: F401
from dast.tools import oob_tools as _oob_tools  # noqa: F401
from dast.tools import profile_tools as _profile_tools  # noqa: F401
from dast.tools import recon_tools as _recon_tools  # noqa: F401
from dast.tools import triage_tools as _triage_tools  # noqa: F401

__all__ = [
    "Tool",
    "ToolContext",
    "all_tools",
    "get_tool",
    "register",
    "run_tool",
]

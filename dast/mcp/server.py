"""
MCP stdio server — bridges the shared tool registry to the Model Context Protocol.

Every tool registered in ``dast/tools/`` is advertised over MCP with its JSON
Schema, and a ``call_tool`` request is dispatched through ``run_tool`` — the exact
same code path the internal agentic triage loop uses. The server drives an
already-running Frieren instance over the proxy port (for sending) and the
dashboard HTTP API (for reading live state), so it is a thin, stateless bridge.

``tool_definitions()`` is a pure function (no ``mcp`` import) so the registry →
protocol conversion is unit-testable without the MCP runtime. ``run_stdio``
imports ``mcp`` lazily and serves over stdin/stdout.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Any, Dict, List

from dast.tools import ToolContext, all_tools, run_tool
from dast.utils.logger import get_logger

logger = get_logger(__name__)

SERVER_NAME = "frieren-dast"

# How often the MCP server tells the dashboard it is alive. Must stay below the
# dashboard's _MCP_STALE_SECONDS (30s) so the UI badge never flaps between posts.
_HEARTBEAT_INTERVAL_SECONDS = 10.0


async def _heartbeat_loop(dashboard_base_url: str) -> None:
    """Post to the dashboard's MCP heartbeat endpoint until cancelled.

    Best-effort and self-contained: a failed post (dashboard down, restarting)
    is logged at debug and retried on the next tick — it never crashes the MCP
    server, whose real job is serving tools over stdio.
    """
    url = f"{dashboard_base_url}/api/mcp/heartbeat"
    loop = asyncio.get_running_loop()

    def _post() -> None:
        req = urllib.request.Request(url, data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).close()

    while True:
        try:
            await loop.run_in_executor(None, _post)
        except Exception as exc:  # dashboard not up yet / transient — retry next tick
            logger.debug("MCP heartbeat post failed", url=url, error=str(exc))
        await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)


def tool_definitions() -> List[Dict[str, Any]]:
    """Registry → MCP tool-definition dicts. Pure; no ``mcp`` dependency."""
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
        }
        for tool in all_tools()
    ]


async def run_stdio(proxy_port: int = 8080, dashboard_port: int = 8088) -> None:
    """Serve the shared tool layer over MCP on stdin/stdout.

    Blocks until the client disconnects. Imports ``mcp`` lazily so the rest of
    Frieren never depends on it being installed.
    """
    import mcp.types as types
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server

    ctx = ToolContext(proxy_port=proxy_port, dashboard_port=dashboard_port)

    async def on_list_tools(request_context, params):
        tools = [
            types.Tool(
                name=d["name"],
                description=d["description"],
                inputSchema=d["inputSchema"],
            )
            for d in tool_definitions()
        ]
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(request_context, params):
        result = await run_tool(ctx, params.name, params.arguments or {})
        is_error = not bool(result.get("ok", True))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(result, default=str))],
            isError=is_error,
        )

    server = Server(
        SERVER_NAME,
        version="0.8.2",
        description="Frieren DAST-AI — proxy-driven security testing tools.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )

    logger.info("MCP server starting on stdio", proxy_port=proxy_port,
                dashboard_port=dashboard_port, tools=len(tool_definitions()))

    # Announce liveness to the dashboard so its UI can show an MCP-connected
    # badge. Purely additive: if the dashboard is down the loop just retries.
    heartbeat_task = asyncio.create_task(_heartbeat_loop(ctx.dashboard_base_url))
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream, server.create_initialization_options()
            )
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass

"""
Exploration Copilot — a conversational agent over Frieren's shared tool layer.

Where ``dast/ai/triage_agent.py`` runs autonomously to a stored verdict, the
copilot is a *dialogue*: it drives the same tools (``dast/tools/`` via
``run_tool``, the exact registry the MCP server bridges), but each turn ends by
handing control back to a human with a message — a finding, a question, or an
honest "I'm blocked by X, I need you to unblock this". That makes it the single
place where automated exploration and human help meet, and (because it consumes
the shared registry) it can use every MCP-exposed capability.
"""

from __future__ import annotations

from dast.ai.copilot.session import CopilotReply, CopilotSession

__all__ = ["CopilotReply", "CopilotSession"]

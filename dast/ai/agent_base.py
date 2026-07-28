"""
Base class for all specialized vulnerability agents.

Each agent targets a single vulnerability class, embeds its own
LLM system prompt, and returns structured AgentFinding objects.
Agents that find deterministic evidence (e.g. secret patterns) can
set bypass_validation=True to skip the LLM exploit-validator step.

Safety policy — all agents MUST follow:
  - Time-based blind payloads (SLEEP, WAITFOR) allowed with max 5s delay
  - No destructive SQL (DROP, TRUNCATE, DELETE without WHERE)
  - No OS commands that write, delete, or modify files
  - No payloads that exhaust CPU/memory/connections
  - Detection only: observe server behaviour, never modify application state
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.collaborator import CollaboratorService
    from dast.scanners.active_checks import CheckTarget

logger = get_logger(__name__)


@dataclass
class AgentObservation:
    """
    Non-finding signal from an agent — observations that don't constitute a
    vulnerability but inform the coordinator and session intelligence:
    - WAF blocked a payload (payload_prefix + block signal)
    - WAF bypass succeeded (a payload got through after earlier blocks)
    - Rate limiting observed (429 / Retry-After)
    - Endpoint returned structural error (wrong schema, 404)
    """
    attack_type: str
    kind: str          # "waf_block" | "waf_bypass" | "rate_limit" | "structural_error" | "no_signal"
    payload: str = ""
    signal: str = ""   # what the server returned that indicates this kind


@dataclass
class AgentFinding:
    title: str
    severity: str           # critical | high | medium | low | info
    cwe: str
    attack_type: str
    evidence: str
    payload: str
    parameter: str
    url: str
    request_method: str
    confirmed: bool = True
    bypass_validation: bool = False  # skip LLM validator for deterministic findings
    ai_validated: bool = False  # True only when the red-team LLM call succeeded and returned a verdict
    reasoning: str = ""
    raw_response_snippet: str = ""
    browser_confirmed: Optional[bool] = None   # None = not attempted, True/False = browser result
    browser_confirm_reason: str = ""           # "confirmed" | "csp_or_sink" | "timeout" | "error:..."
    raw_request: str = ""        # original intercepted request (baseline)
    raw_response: str = ""       # original intercepted response (baseline)
    probe_request: str = ""      # exploit proof request (when a before/after pair exists)
    probe_response: str = ""     # exploit proof response


class VulnAgent(ABC):
    """
    Abstract base for a single-class vulnerability agent.

    Subclasses implement `run()` to probe a CheckTarget and return
    a list of AgentFinding objects. Each agent is responsible for:
      - Generating payloads (static list or LLM-generated)
      - Sending requests via the shared httpx client
      - Analysing responses (deterministically or via LLM)
      - Returning only confirmed findings

    Agents may also accumulate AgentObservations during run() by calling
    self.observe(...). The coordinator collects these via self.observations
    after run_safe() completes and feeds them into session intelligence.
    """

    # Agent metadata — subclasses must set these
    name: str = ""
    attack_type: str = ""
    description: str = ""

    def __init__(self) -> None:
        self.observations: List[AgentObservation] = []

    def observe(self, kind: str, payload: str = "", signal: str = "") -> None:
        """Record a non-finding observation for the coordinator to consume."""
        self.observations.append(AgentObservation(
            attack_type=self.attack_type,
            kind=kind,
            payload=payload,
            signal=signal[:200],
        ))

    @abstractmethod
    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        """Run this agent against target; return findings (empty list if none)."""

    async def run_safe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        """Wrapper that catches all exceptions so one agent can't kill others."""
        try:
            return await self.run(target, client, collaborator)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Agent crashed", agent=type(self).__name__, url=getattr(target, "url", ""), error=str(exc))
            return []

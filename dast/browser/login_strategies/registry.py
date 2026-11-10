"""Ordered registry of login strategies the cascade driver iterates.

Strategies register themselves here (on import of this module); ``ordered_strategies`` returns
them in the order to try for a given host. The default order is the historical cascade ladder
(deterministic form -> SPA JSON-API -> LLM); per-host learned reordering is layered on top via
``reorder`` (a pure function) so a host's last-winning strategy is tried first.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from dast.browser.login_strategies.base import LoginStrategy
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Default try-order: the cheap token-free form first, the DOM-independent JSON path next,
# the LLM last. Learned ordering only moves a known winner to the front of this.
_DEFAULT_ORDER = ("deterministic", "spa_api", "llm")

_REGISTRY: Dict[str, LoginStrategy] = {}


def register(strategy: LoginStrategy) -> None:
    """Register a strategy under its ``name`` (idempotent — re-registering replaces)."""
    _REGISTRY[strategy.name] = strategy


def reorder(default: Sequence[str], winner: Optional[str]) -> List[str]:
    """Move ``winner`` to the front, keeping the rest in ``default`` order. Pure. Never drops a
    strategy (so none starves); a None/unknown winner leaves the order unchanged."""
    if winner and winner in default:
        return [winner, *[name for name in default if name != winner]]
    return list(default)


def ordered_strategies(host: Optional[str] = None) -> List[LoginStrategy]:
    """The registered strategies in try-order for *host*: the host's last-winning strategy
    (from the login journal) first, then the rest in default order. No journal history (or an
    unknown host) leaves the default order untouched."""
    winner: Optional[str] = None
    if host:
        try:
            from dast.session import login_journal
            winner = login_journal.last_winning_strategy(host)
        except Exception as exc:  # noqa: BLE001 — a journal read must never break login
            logger.debug("login registry: journal read failed", error=str(exc)[:120])
    order = reorder(_DEFAULT_ORDER, winner)
    return [_REGISTRY[name] for name in order if name in _REGISTRY]


# Register the built-in strategies on import (stateless singletons).
from dast.browser.login_strategies.form import FormStrategy  # noqa: E402
from dast.browser.login_strategies.llm import LlmStrategy  # noqa: E402
from dast.browser.login_strategies.spa_api import SpaApiStrategy  # noqa: E402

for _strategy in (FormStrategy(), SpaApiStrategy(), LlmStrategy()):
    register(_strategy)

"""
Provider health registry — failure tracking with cooldown for LLM providers.

The failover chain in ``dast.ai.bedrock_client`` walks providers when the active
one fails at the PROVIDER level (expired AWS SSO, throttling exhaustion, auth,
network). Without memory, every call pays the failing provider's full retry +
backoff cost before failing over. Inspired by ARTEX's ``llmpool`` health
registry: consecutive provider-level failures put a provider in a widening
cooldown so the chain skips straight to a healthy member, and a single success
fully restores it.

Scope:
- Only PROVIDER-level failures are recorded (never a content block — a
  ``AiContentBlockedError`` says nothing about provider health).
- Cooldowns widen exponentially per additional consecutive failure and cap out,
  so a provider that comes back is re-admitted quickly, while a hard-down one
  stops costing every call.
- Pure in-memory (process lifetime) — the LLM gateway is a per-run resource;
  persistence would outlive the credentials it describes.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Consecutive provider-level failures before a cooldown starts, and the
# cooldown schedule: 60s doubling per extra failure, capped at 5 minutes —
# long enough to skip a hard-down provider on every call, short enough that a
# recovered one (e.g. after 'aws sso login') is retried within minutes.
_FAILURE_THRESHOLD = 3
_COOLDOWN_BASE_S = 60.0
_COOLDOWN_MAX_S = 300.0


class _ProviderState:
    """Per-provider failure ledger (in-memory, process lifetime)."""

    __slots__ = ("consecutive_failures", "cooldown_until", "last_error")

    def __init__(self) -> None:
        self.consecutive_failures: int = 0
        self.cooldown_until: float = 0.0
        self.last_error: str = ""


_lock = threading.Lock()
_states: Dict[str, _ProviderState] = {}


def _state_for(provider: str) -> _ProviderState:
    state = _states.get(provider)
    if state is None:
        state = _ProviderState()
        _states[provider] = state
    return state


def record_failure(provider: str, error: str = "") -> None:
    """Record one provider-level failure. From the threshold on, each extra
    consecutive failure starts a wider cooldown (60s -> 120s -> ... -> 5min cap)."""
    with _lock:
        state = _state_for(provider)
        state.consecutive_failures += 1
        state.last_error = str(error)[:200]
        if state.consecutive_failures >= _FAILURE_THRESHOLD:
            over = state.consecutive_failures - _FAILURE_THRESHOLD
            cooldown = min(_COOLDOWN_BASE_S * (2 ** over), _COOLDOWN_MAX_S)
            state.cooldown_until = time.monotonic() + cooldown
            logger.warning("LLM provider cooling down after repeated failures",
                           provider=provider, failures=state.consecutive_failures,
                           cooldown_s=cooldown, last_error=state.last_error)


def record_success(provider: str) -> None:
    """A successful call fully restores the provider (health is a running
    streak, not a half-life)."""
    with _lock:
        state = _states.get(provider)
        if state is not None and (state.consecutive_failures or state.cooldown_until):
            logger.info("LLM provider recovered", provider=provider)
        if state is not None:
            state.consecutive_failures = 0
            state.cooldown_until = 0.0
            state.last_error = ""


def is_healthy(provider: str) -> bool:
    """True when the provider is not in a failure cooldown."""
    with _lock:
        state = _states.get(provider)
        return state is None or time.monotonic() >= state.cooldown_until


def failure_streak(provider: str) -> int:
    """Consecutive provider-level failures (0 when healthy/unknown)."""
    with _lock:
        state = _states.get(provider)
        return state.consecutive_failures if state is not None else 0


def snapshot(providers: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Dashboard-shaped view of provider health. ``providers`` bounds the output
    to the named set (default: every provider ever seen)."""
    with _lock:
        names = list(providers) if providers else sorted(_states)
        now = time.monotonic()
        out: Dict[str, Dict[str, Any]] = {}
        for name in names:
            state = _states.get(name)
            if state is None:
                out[name] = {"healthy": True, "cooldown_remaining_s": 0.0,
                             "consecutive_failures": 0, "last_error": ""}
                continue
            remaining = max(0.0, state.cooldown_until - now)
            out[name] = {
                "healthy": remaining <= 0.0,
                "cooldown_remaining_s": round(remaining, 1),
                "consecutive_failures": state.consecutive_failures,
                "last_error": state.last_error,
            }
        return out


def reset() -> None:
    """Clear all state (test isolation)."""
    with _lock:
        _states.clear()

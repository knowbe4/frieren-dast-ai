"""
Opt-in memoisation of deterministic LLM responses.

Only ``invoke_json`` calls made with ``temperature=0`` are eligible: for those,
an identical (provider, model, system prompt, user prompt, schema, max_tokens)
tuple yields an identical decision, so returning a stored result is lossless.
Non-deterministic calls (the mutator, anything with ``temperature`` unset or
> 0) are never routed through here — caching them would suppress the payload
diversity they exist to produce.

The cache is OFF by default and enabled only when the operator ticks the
"Cache AI responses" box in scan config. It is process-local and bounded; keys
embed the full prompt (including the observed response body), so a target that
changes between calls produces a different key and cannot serve a stale verdict
within a scan. It is still an operator-visible trade-off — see the UI warning —
because a re-scan of an endpoint whose backend changed out-of-band would reuse
the earlier decision until the cache is cleared.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from typing import Any, Dict, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Upper bound on stored entries. A scan rarely repeats more than a few hundred
# identical deterministic prompts; the LRU eviction keeps memory bounded if it
# does. Each entry is a small decision dict, so this is a few MB at most.
_MAX_ENTRIES = 1024

_enabled: bool = False
_lock = threading.Lock()
_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
_hits: int = 0
_misses: int = 0


def set_enabled(enabled: bool) -> None:
    """Turn the response cache on or off. Toggling clears any stored entries so a
    fresh run never serves a decision captured under a previous configuration."""
    global _enabled
    with _lock:
        changed = bool(enabled) != _enabled
        _enabled = bool(enabled)
        if changed:
            _cache.clear()
    logger.info("AI response cache toggled", enabled=_enabled)


def is_enabled() -> bool:
    return _enabled


def clear() -> None:
    """Drop all cached entries (e.g. at the start of a new scan)."""
    with _lock:
        _cache.clear()


def make_key(
    *,
    provider: str,
    model: str,
    system: str,
    user: str,
    schema: Optional[Dict[str, Any]],
    max_tokens: int,
) -> str:
    """Stable hash of every input that affects a deterministic response."""
    schema_repr = json.dumps(schema, sort_keys=True) if schema is not None else ""
    material = "\x00".join((provider, model, str(max_tokens), schema_repr, system, user))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def get(key: str) -> Optional[Dict[str, Any]]:
    """Return a copy of the cached response for ``key``, or None on miss."""
    global _hits, _misses
    with _lock:
        hit = _cache.get(key)
        if hit is None:
            _misses += 1
            return None
        _cache.move_to_end(key)  # LRU: mark recently used
        _hits += 1
        logger.debug("AI response cache hit", hits=_hits, misses=_misses)
        return dict(hit)


def put(key: str, value: Dict[str, Any]) -> None:
    """Store a copy of ``value`` under ``key``, evicting the oldest if full."""
    if not isinstance(value, dict):
        return
    with _lock:
        _cache[key] = dict(value)
        _cache.move_to_end(key)
        while len(_cache) > _MAX_ENTRIES:
            _cache.popitem(last=False)


def stats() -> Dict[str, Any]:
    """Current cache counters — surfaced for observability, not correctness."""
    with _lock:
        return {"enabled": _enabled, "entries": len(_cache), "hits": _hits, "misses": _misses}

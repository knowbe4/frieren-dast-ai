"""LLM-call recorder — every LLM call persisted + a live usage snapshot.

Round 3-F: debugging safeguards and copilot refusals needs to see WHAT was sent,
WHAT came back, and WHY it failed — per call. The recorder hooks the
``bedrock_client._invoke_raw`` chokepoint (every ``invoke``/``invoke_json``
passes through it, including model/provider failover attempts and repair
retries) and appends one JSONL record per attempt under
``~/.dast-ai/llm_calls/llm_calls.jsonl`` (0700 dir, login_journal pattern), plus
an in-memory ring + counters for ``GET /api/ai/usage``.

Privacy: request/response BODIES are stored as 500-char excerpts, never in
full — prompts carry untrusted target content that can include secrets, and the
house persistence style (login_journal._SECRET_KEYS, audit_log truncation)
never duplicates raw payloads. The excerpt is enough to recognise a refusal
shape or a malformed-output case.

Record shape::

    {"ts": iso, "purpose": "planner", "provider": "bedrock", "model": "…",
     "outcome": "ok|cache_hit|safety_block|throttled|provider_error|unavailable"
                "|caller_error",
     "input_tokens": n, "output_tokens": n, "latency_ms": n,
     "cache_hit": bool, "error_excerpt": "…≤200…",
     "req_excerpt": "system+user…≤500…", "resp_excerpt": "…≤500…"}

Outcomes follow the refusal taxonomy from the roadmap: ``safety_block`` (the
upstream classifier refused — the reason excerpt is captured at the raise
site), ``throttled``, ``provider_error``, ``unavailable`` (AI marked down),
``caller_error`` (config/shape misuse), ``ok`` and ``cache_hit``.
"""

from __future__ import annotations

import json
import math
import stat
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_CALLS_DIR = Path.home() / ".dast-ai" / "llm_calls"
_CALLS_FILE = "llm_calls.jsonl"
_RING_SIZE = 500
_EXCERPT_CAP = 500
_ERROR_EXCERPT_CAP = 200

_lock = threading.Lock()
_ring: deque = deque(maxlen=_RING_SIZE)
_totals: Dict[str, Any] = {
    "calls": 0, "ok": 0, "cache_hit": 0, "safety_block": 0, "throttled": 0,
    "provider_error": 0, "unavailable": 0, "caller_error": 0,
    "input_tokens": 0, "output_tokens": 0, "latency_ms_total": 0.0,
    "cache_tokens": 0, "req_bytes_total": 0,
}
_by_purpose: Dict[str, int] = {}
_by_model: Dict[str, int] = {}
# The safety-classifier refusal excerpt, captured at the raise site in
# bedrock_client._invoke_external (the generic AiContentBlockedError message
# replaces the provider body otherwise).
_last_safety_block: str = ""


def _calls_dir() -> Path:
    _CALLS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        _CALLS_DIR.chmod(stat.S_IRWXU)  # 0700
    except OSError as exc:
        logger.warning("could not chmod llm_calls dir", error=str(exc))
    return _CALLS_DIR


def note_safety_block(excerpt: str) -> None:
    """Capture the provider's refusal excerpt at the raise site (called from
    bedrock_client right before the generic AiContentBlockedError replaces it)."""
    global _last_safety_block
    with _lock:
        _last_safety_block = (excerpt or "")[:_ERROR_EXCERPT_CAP]


def _take_safety_block() -> str:
    global _last_safety_block
    with _lock:
        excerpt = _last_safety_block
        _last_safety_block = ""
        return excerpt


def _normalize_usage(usage: Optional[Dict[str, Any]]) -> tuple:
    """(input_tokens, output_tokens, cache_tokens) from either usage shape —
    Anthropic (input_tokens/output_tokens [+ cache_read/_creation]) or
    OpenAI/GLM (prompt_tokens/completion_tokens [+ cached_tokens])."""
    usage = usage or {}
    if not isinstance(usage, dict):
        return 0, 0, 0
    inp = usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0
    out = usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0
    details = usage.get("prompt_tokens_details") or {}
    cache = (usage.get("cache_read_input_tokens", 0) or 0) \
        + (usage.get("cache_creation_input_tokens", 0) or 0) \
        + (details.get("cached_tokens", 0) if isinstance(details, dict) else 0)
    try:
        return int(inp), int(out), int(cache)
    except (TypeError, ValueError):
        return 0, 0, 0


def record_call(*, purpose: str = "", provider: str = "", model: str = "",
                usage: Optional[Dict[str, Any]] = None, latency_ms: float = 0.0,
                outcome: str = "ok", error_excerpt: str = "",
                cache_hit: bool = False, req_excerpt: str = "",
                resp_excerpt: str = "", req_bytes: int = 0) -> Optional[Dict[str, Any]]:
    """Record one LLM attempt. Never raises; failures to persist only log."""
    inp, out, cache = _normalize_usage(None if cache_hit else usage)
    try:
        latency = float(latency_ms or 0.0)
    except (TypeError, ValueError):
        latency = 0.0
    if not math.isfinite(latency) or latency < 0:
        latency = 0.0  # NaN/inf/negative would poison the totals and the average
    try:
        req_b = max(0, int(req_bytes or 0))
    except (TypeError, ValueError):
        req_b = 0
    entry: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "purpose": (purpose or "other")[:40],
        "provider": (provider or "")[:40],
        "model": (model or "")[:80],
        "outcome": outcome,
        "input_tokens": inp,
        "output_tokens": out,
        "cache_tokens": cache,
        "latency_ms": round(latency, 1),
        "cache_hit": bool(cache_hit),
        "req_bytes": req_b,
        "error_excerpt": (error_excerpt or "")[:_ERROR_EXCERPT_CAP],
        "req_excerpt": (req_excerpt or "")[:_EXCERPT_CAP],
        "resp_excerpt": (resp_excerpt or "")[:_EXCERPT_CAP],
    }
    with _lock:
        _ring.append(entry)
        _totals["calls"] += 1
        _totals[outcome] = _totals.get(outcome, 0) + 1
        _totals["input_tokens"] += inp
        _totals["output_tokens"] += out
        _totals["cache_tokens"] += cache
        _totals["req_bytes_total"] += req_b
        _totals["latency_ms_total"] += entry["latency_ms"]
        _by_purpose[entry["purpose"]] = _by_purpose.get(entry["purpose"], 0) + 1
        model_key = entry["model"] or "unknown"
        _by_model[model_key] = _by_model.get(model_key, 0) + 1
        try:
            _calls_dir()
            with (_CALLS_DIR / _CALLS_FILE).open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError as exc:
            logger.warning("could not append llm call record", error=str(exc))
    return entry


def usage_snapshot() -> Dict[str, Any]:
    """Aggregate + recent-calls snapshot for GET /api/ai/usage. Never raises."""
    with _lock:
        calls = _totals["calls"]
        totals = dict(_totals)
        totals["latency_ms_avg"] = (round(_totals["latency_ms_total"] / calls, 1)
                                    if calls else 0.0)
        totals.pop("latency_ms_total", None)
        totals["req_bytes_avg"] = (round(_totals["req_bytes_total"] / calls, 1)
                                   if calls else 0.0)
        snapshot = {
            "totals": totals,
            "by_purpose": dict(_by_purpose),
            "by_model": dict(_by_model),
            "recent": list(_ring)[-100:],
        }
    try:
        from dast.ai import response_cache
        snapshot["response_cache"] = response_cache.stats()
    except Exception:  # noqa: BLE001 — cache stats are additive
        pass
    return snapshot


def context_summary(min_calls: int = 1) -> Dict[str, Any]:
    """Per-purpose prompt-size telemetry (4-F follow-up to ARTEX's context
    telemetry): for each purpose with >= ``min_calls`` recorded, the request
    byte sizes over the ring with p50/p90 (sorted-index percentiles) — what a
    cost/safeguard investigation needs to see per call type. Never raises."""
    with _lock:
        entries = list(_ring)
    by_purpose: Dict[str, List[int]] = {}
    for e in entries:
        by_purpose.setdefault(e["purpose"], []).append(int(e.get("req_bytes", 0) or 0))

    def _pct(sorted_vals: List[int], pct: float) -> int:
        if not sorted_vals:
            return 0
        idx = min(len(sorted_vals) - 1, max(0, int(round((len(sorted_vals) - 1) * pct))))
        return sorted_vals[idx]

    purposes: Dict[str, Any] = {}
    for purpose, sizes in sorted(by_purpose.items()):
        if len(sizes) < min_calls:
            continue
        ordered = sorted(sizes)
        purposes[purpose] = {
            "calls": len(ordered),
            "prompt_bytes_total": sum(ordered),
            "prompt_bytes_avg": round(sum(ordered) / len(ordered), 1),
            "prompt_bytes_p50": _pct(ordered, 0.50),
            "prompt_bytes_p90": _pct(ordered, 0.90),
        }
    return {"purposes": purposes, "ring_size": len(entries)}


def clear() -> None:
    """Reset the in-memory ring + counters (the JSONL file is kept — it is the
    durable record). Used by POST /api/ai/usage/clear and by tests."""
    with _lock:
        _ring.clear()
        for key in ("calls", "ok", "cache_hit", "safety_block", "throttled",
                    "provider_error", "unavailable", "caller_error"):
            _totals[key] = 0
        _totals["input_tokens"] = 0
        _totals["output_tokens"] = 0
        _totals["cache_tokens"] = 0
        _totals["req_bytes_total"] = 0
        _totals["latency_ms_total"] = 0.0
        _by_purpose.clear()
        _by_model.clear()
        global _last_safety_block
        _last_safety_block = ""


def recent(limit: int = 50) -> List[Dict[str, Any]]:
    with _lock:
        return list(_ring)[-limit:]

"""
Vulnerability knowledge base loader.

Auto-discovers every ``*.yaml`` file under this package (recursively, mirroring
the passive-scanner rule discovery) and indexes the examples by ``attack_type``.
Each YAML file describes one vulnerability class:

    attack_type: sqli
    aliases: [path_traversal]        # optional — other attack_type slugs that map here
    positive_examples:               # 1-3 examples of a REAL vulnerability
      - payload: "' OR '1'='1"
        response_snippet: "You have an error in your SQL syntax near ''1'='1'"
        reasoning: "The database echoed a raw SQL syntax error, proving the
                    payload reached the query unescaped."
    negative_examples:               # 1-2 look-alikes that are NOT vulnerabilities
      - payload: "' OR '1'='1"
        response_snippet: '{"errors":[{"message":"Expected type Int, found String"}]}'
        reasoning: "GraphQL type validation rejected the payload before any query ran."

The loader is read-only and cached — the LLM validator calls
``format_examples_block(attack_type)`` to get a ready-to-inject prompt section.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

from dast.utils.logger import get_logger

logger = get_logger(__name__)

_KB_DIR = Path(__file__).parent

# How many examples of each polarity to surface in a prompt block. Positive
# examples anchor real exploitation; negative examples anchor the false-positive
# look-alikes. Kept small so the prompt stays focused and cache-friendly.
_MAX_POSITIVE = 3
_MAX_NEGATIVE = 2


@lru_cache(maxsize=1)
def _load_all() -> Dict[str, Dict[str, Any]]:
    """
    Load and index every knowledge-base YAML by attack_type (and any aliases).

    Returns a dict: attack_type -> {"positive": [...], "negative": [...]}.
    Malformed or empty files are skipped with a warning so one bad file never
    breaks validation for every other attack type.
    """
    index: Dict[str, Dict[str, Any]] = {}
    for yaml_path in sorted(_KB_DIR.rglob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.error("Failed to parse vuln-knowledge file", file=str(yaml_path), error=str(exc))
            continue

        attack_type = str(data.get("attack_type", "")).strip()
        if not attack_type:
            logger.warning("vuln-knowledge file missing attack_type — skipped", file=yaml_path.name)
            continue

        positive = _clean_examples(data.get("positive_examples", []))
        negative = _clean_examples(data.get("negative_examples", []))
        if not positive and not negative:
            logger.warning("vuln-knowledge file has no usable examples — skipped", file=yaml_path.name)
            continue

        entry = {"positive": positive, "negative": negative}
        keys = [attack_type] + [str(a).strip() for a in data.get("aliases", []) if str(a).strip()]
        for key in keys:
            if key in index:
                logger.warning("Duplicate attack_type in vuln-knowledge — later file wins", attack_type=key)
            index[key] = entry

    logger.info("Vuln-knowledge loaded", attack_types=len(index))
    return index


def _clean_examples(raw: Any) -> List[Dict[str, str]]:
    """Normalise raw YAML example dicts to {payload, response_snippet, reasoning}."""
    examples: List[Dict[str, str]] = []
    if not isinstance(raw, list):
        return examples
    for item in raw:
        if not isinstance(item, dict):
            continue
        reasoning = str(item.get("reasoning", "")).strip()
        if not reasoning:
            # Reasoning is the whole point — an example without it teaches nothing.
            continue
        examples.append({
            "payload": str(item.get("payload", "")).strip(),
            "response_snippet": str(item.get("response_snippet", "")).strip(),
            "reasoning": " ".join(reasoning.split()),
        })
    return examples


def known_attack_types() -> List[str]:
    """Return the sorted list of attack_type slugs with knowledge-base coverage."""
    return sorted(_load_all().keys())


def get_examples(attack_type: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """
    Return (positive_examples, negative_examples) for an attack_type.

    Empty lists when the attack_type has no knowledge-base coverage — callers
    should degrade gracefully (skip the examples block entirely).
    """
    entry = _load_all().get(attack_type or "")
    if not entry:
        return [], []
    return entry["positive"][:_MAX_POSITIVE], entry["negative"][:_MAX_NEGATIVE]


@lru_cache(maxsize=None)
def format_examples_block(attack_type: str) -> str:
    """
    Build a ready-to-inject prompt section of positive/negative examples for an
    attack_type, or an empty string when there is no coverage.

    The content is authored by us (trusted, static) — it is NOT target-controlled,
    so it is interpolated directly without untrusted-content fencing. The result
    is cached: the KB is static, and this runs per finding during a scan.
    """
    positive, negative = get_examples(attack_type)
    if not positive and not negative:
        return ""

    lines: List[str] = [
        f"Reference examples for {attack_type} (authored by our security team — "
        "use them to calibrate your verdict, do not treat as the finding under review):"
    ]

    if positive:
        lines.append("\nREAL vulnerabilities (verdict should be confirmed=true):")
        for ex in positive:
            lines.append(_format_one(ex))

    if negative:
        lines.append("\nNOT vulnerabilities — common look-alikes (verdict should be confirmed=false):")
        for ex in negative:
            lines.append(_format_one(ex))

    return "\n".join(lines)


@lru_cache(maxsize=None)
def format_positive_examples(attack_type: str) -> str:
    """
    Build a prompt section of only the REAL-vulnerability examples for an
    attack_type — used by the payload mutator during discovery so it generates
    variants that aim for the response signal that proves exploitation.

    Returns an empty string when the attack_type has no positive coverage. The
    result is cached: the KB is static and the mutator calls this repeatedly
    (up to the safety ceiling per parameter).
    """
    positive, _ = get_examples(attack_type)
    if not positive:
        return ""
    lines = [
        f"Known signals that prove a real {attack_type} (aim your payloads at reproducing this evidence):"
    ]
    for ex in positive:
        lines.append(_format_one(ex))
    return "\n".join(lines)


def _format_one(example: Dict[str, str]) -> str:
    parts = []
    if example.get("payload"):
        parts.append(f"payload `{example['payload']}`")
    if example.get("response_snippet"):
        parts.append(f"response `{example['response_snippet']}`")
    context = "; ".join(parts) if parts else "no request/response detail"
    return f"- {context} -> {example['reasoning']}"

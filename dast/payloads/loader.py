"""
Payload loader — reads YAML files from dast/payloads/ and caches them.
Provides typed access to payload lists and detection signatures.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Dict, List

import yaml

_PAYLOADS_DIR = os.path.dirname(__file__)


@lru_cache(maxsize=None)
def _load(filename: str) -> Dict[str, Any]:
    path = os.path.join(_PAYLOADS_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_payloads(category: str, group: str) -> List[str]:
    """
    Return a flat list of payload strings for a given category and group.

    Examples:
        get_payloads("xss", "basic")
        get_payloads("sqli", "error_based")
        get_payloads("lfi", "unix")
    """
    data = _load(f"{category}.yaml")
    payloads_section = data.get("payloads", {})
    items = payloads_section.get(group, [])
    result = []
    for item in items:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict) and "payload" in item:
            result.append(item["payload"])
    return result


def get_all_payloads(category: str) -> List[str]:
    """Return all payloads for a category, across all groups, deduplicated."""
    data = _load(f"{category}.yaml")
    seen = set()
    result = []
    for group_items in data.get("payloads", {}).values():
        for item in group_items:
            p = item if isinstance(item, str) else item.get("payload", "")
            if p and p not in seen:
                seen.add(p)
                result.append(p)
    return result


def get_detection_payloads(category: str) -> List[Dict[str, Any]]:
    """
    Return detection payloads with expected values (used by SSTI agent).
    Each item has at minimum: payload (str), expected (str|None).
    """
    data = _load(f"{category}.yaml")
    return data.get("payloads", {}).get("detection", [])


def get_signatures(category: str, key: str = "match_signatures") -> List[str]:
    """Return detection regex signatures for a category."""
    data = _load(f"{category}.yaml")
    return data.get(key, [])


def get_value(category: str, key: str, default: Any = None) -> Any:
    """Get a top-level config value from a payload YAML (e.g. time_threshold_ms)."""
    return _load(f"{category}.yaml").get(key, default)

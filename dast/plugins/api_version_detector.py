"""
API Version Detector plugin — tracks versioned API paths seen in traffic and
flags when multiple versions of the same endpoint are active simultaneously.

Older API versions frequently lack security controls added in newer versions
(auth checks, rate limiting, input validation).

Passive only — no extra requests.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING

from dast.proxy.plugin_base import ProxyPlugin

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

# Matches /v1/, /v2/, /api/v3/, /api/1.0/, etc.
_VERSION_RE = re.compile(
    r'^(.*?)/v(\d+(?:\.\d+)?)(/.*)?$',
    re.IGNORECASE,
)

# host → { base_path → set of versions }
_seen: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))


def _parse_version(path: str):
    m = _VERSION_RE.match(path)
    if not m:
        return None, None
    prefix  = m.group(1) or ""
    version = m.group(2)
    suffix  = m.group(3) or ""
    base    = f"{prefix}{suffix}"
    return version, base


class ApiVersionDetectorPlugin(ProxyPlugin):
    name        = "api-version-detector"
    description = "Flags when multiple API versions of the same endpoint are seen in traffic"
    version     = "1.0.0"
    author      = "Frieren DAST-AI"
    enabled     = True

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        version, base = _parse_version(entry.path)
        if not version or not base:
            return

        host_map = _seen[entry.host]
        host_map[base].add(version)

        versions = host_map[base]
        if len(versions) < 2:
            return

        sorted_versions = sorted(versions, key=lambda v: [int(x) for x in v.split(".")])
        oldest = sorted_versions[0]
        newest = sorted_versions[-1]

        # Only flag once per host+base combination
        store.add_finding(
            entry.id,
            {
                "title": f"Multiple API Versions Active: v{oldest} and v{newest}",
                "severity": "medium",
                "cwe": "CWE-1059",
                "attack_type": "api-version",
                "evidence": (
                    f"Versions observed for {entry.host}{base}: "
                    f"{', '.join(f'v{v}' for v in sorted_versions)}. "
                    f"Older versions may lack security controls present in v{newest}."
                ),
                "confirmed": False,
                "validated_by": ["pattern"],
            },
            "safe",
        )

"""Reproducible PoC + POE levels for findings (5-B-5, ARTEX semantics).

``build_poc_curl`` turns a finding's stored ``raw_request`` (the probe the
agent actually sent) into a shell-reproducible curl command; ``derive_poe``
scores HOW WELL the finding is proven, deterministically — no LLM:

    0  narrative only   — no verifiable evidence at all
    1  described        — evidence text exists, nothing replayable/linkable
    2  evidence linked  — real history entry ids / browser confirmation
    3  validated        — confirmed (agent oracle, validator, or OOB callback)
    4  impact shown     — extracted_data / chain validated / narrative steps

The finding dict shape is whatever the scan pipeline or record_finding stores
(see ``session_store.add_finding`` / ``record_manual_finding``); every field is
read defensively so partial findings still score.
"""

from __future__ import annotations

import shlex
from typing import List, Optional, Tuple

_POE_LABELS = {
    0: "POE-0 narrative (no verifiable evidence)",
    1: "POE-1 described (evidence text only)",
    2: "POE-2 evidence linked (captured request/response)",
    3: "POE-3 validated (oracle/validator/OOB confirmed)",
    4: "POE-4 impact demonstrated (extracted data / validated chain)",
}

# Headers that must NOT be copied into the PoC verbatim.
_POC_SKIP_HEADERS = {"host", "content-length", "accept-encoding"}


def poe_label(poe: int) -> str:
    return _POE_LABELS.get(poe, "POE-?")


def derive_poe(finding: dict) -> int:
    """ARTEX-style Proof-of-Exploit level, derived from the finding's own
    fields. Higher wins — order the checks strongest-first."""
    if not isinstance(finding, dict):
        return 0
    # 4 — demonstrated impact: extracted data, a validated chain, or narrative
    # steps that compose a chain of real requests.
    if finding.get("extracted_data"):
        return 4
    if (finding.get("attack_type") or "") == "chain":
        return 4
    if isinstance(finding.get("steps"), list) and finding["steps"]:
        return 4
    # 3 — validated by an oracle: agent confirmation, OOB callback, browser
    # execution, or the red-team validator passing.
    if finding.get("confirmed") or finding.get("bypass_validation") \
            or finding.get("ai_validated") or finding.get("browser_confirmed"):
        return 3
    # 2 — evidence linked to real captured traffic.
    if finding.get("evidence_entry_ids"):
        return 2
    if finding.get("probe_request") or finding.get("raw_request"):
        return 2
    # 1 — narrative evidence text only.
    if (finding.get("evidence") or "").strip():
        return 1
    return 0


def _parse_raw_request(raw: str) -> Optional[Tuple[str, str, List[Tuple[str, str]], str]]:
    """Parse raw HTTP request text into (method, path, headers, body)."""
    if not raw or "\n" not in raw and len(raw) < 8:
        return None
    lines = raw.split("\n")
    first = lines[0].strip()
    parts = first.split()
    if len(parts) < 2 or "/" not in parts[1]:
        return None
    method = parts[0].upper()
    path = parts[1]
    headers: List[Tuple[str, str]] = []
    body_start = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    body = ""
    if body_start is not None and body_start < len(lines):
        body = "\n".join(lines[body_start:]).strip()
    return method, path, headers, body


def build_poc_curl(finding: dict) -> str:
    """A shell-reproducible curl for the finding's probe request.

    Prefers ``raw_request`` (the exact bytes the agent sent — including the
    payload, headers and cookies); falls back to a bare method+url curl when
    only the finding's URL is known. Authentication headers are kept: the PoC
    documents what the scan PROVED, not a sanitized variant.
    """
    url = str(finding.get("url", "") or "").strip()
    raw = str(finding.get("raw_request", "") or finding.get("probe_request", "") or "")
    parsed = _parse_raw_request(raw)
    if parsed is None or not url:
        method = str(finding.get("request_method", finding.get("method", "GET")) or "GET").upper()
        if not url:
            return "# PoC unavailable: no stored request and no URL on this finding"
        return f"curl -sk -X {shlex.quote(method)} {shlex.quote(url)}"

    from urllib.parse import urlparse
    base = urlparse(url)
    method, path, headers, body = parsed
    if path.startswith("http://") or path.startswith("https://"):
        full_url = path  # absolute-form request line (proxy style)
    else:
        full_url = f"{base.scheme or 'https'}://{base.netloc}{path}"

    parts = ["curl", "-sk", "-X", shlex.quote(method), shlex.quote(full_url)]
    for key, value in headers:
        if key.lower() in _POC_SKIP_HEADERS:
            continue
        parts += ["-H", shlex.quote(f"{key}: {value}")]
    if body:
        parts += ["--data-raw", shlex.quote(body)]
    return " ".join(parts)

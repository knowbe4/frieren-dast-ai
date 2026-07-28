"""
ThreatModelWorker — per-host architectural security analysis.

Complements AppContextWorker (which answers "what IS this app?") by answering
"what is architecturally impossible to exploit here?" — structural constraints
that make certain attacks non-viable regardless of parameter values.

The ThreatModel is injected into red_team.validate() as additional LLM context,
reducing false positives by telling the validator about known security invariants.

Examples of useful threat model facts:
  - "All /api/* routes return 401 without Authorization header — IDOR requires auth"
  - "All responses are application/json — reflected XSS cannot execute in browser"
  - "Redirects always stay on the same domain — open redirect structurally impossible"
  - "Admin endpoints consistently return 403 for non-admin tokens — privilege escalation blocked at infra"

Triggers after the same 15-entry threshold as AppContextWorker.
Re-analyses every 50 new entries (less frequent — invariants change slowly).
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore
    from dast.discovery.engine import DiscoveryEngine

logger = get_logger(__name__)

_FIRST_THRESHOLD = 15
_DELTA_ENTRIES = 50     # invariants change slowly — re-analyse less often
_SAMPLE_SIZE = 25

_INJECTION_RE = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)"
    r"|system\s*:\s*you\s+are"
    r"|<\s*/?system\s*>"
    r"|\[INST\]|\[/INST\]"
    r"|forget\s+(everything|all)\s+(above|previous)"
    r"|you\s+are\s+now\s+(a\s+)?(different|new)\s+(ai|assistant))",
    re.IGNORECASE,
)


def _sanitize(value: str, max_len: int = 200) -> str:
    return _INJECTION_RE.sub("[redacted]", str(value)[:max_len])


@dataclass
class ThreatModel:
    """
    Architectural security constraints observed for a host.
    Each list entry is a one-sentence fact about what is structurally impossible
    or consistently enforced, making certain findings false positives.
    """
    host: str
    trust_boundaries: List[str] = field(default_factory=list)
    high_risk_surfaces: List[str] = field(default_factory=list)
    security_invariants: List[str] = field(default_factory=list)
    not_vulnerabilities: List[str] = field(default_factory=list)
    last_analysed_at: Optional[float] = None
    analysis_count: int = 0

    def to_validator_hint(self) -> str:
        """
        Compact text injected into red_team.validate() LLM prompt.
        Focuses on what the validator should NOT confirm.
        """
        lines = []
        if self.security_invariants:
            lines.append("Security invariants (architecturally enforced):")
            for inv in self.security_invariants[:6]:
                lines.append(f"  - {_sanitize(inv)}")
        if self.not_vulnerabilities:
            lines.append("Known non-vulnerabilities for this host:")
            for nv in self.not_vulnerabilities[:6]:
                lines.append(f"  - {_sanitize(nv)}")
        if self.trust_boundaries:
            lines.append("Trust boundaries:")
            for tb in self.trust_boundaries[:4]:
                lines.append(f"  - {_sanitize(tb)}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "trust_boundaries": self.trust_boundaries,
            "high_risk_surfaces": self.high_risk_surfaces,
            "security_invariants": self.security_invariants,
            "not_vulnerabilities": self.not_vulnerabilities,
            "last_analysed_at": self.last_analysed_at,
            "analysis_count": self.analysis_count,
        }


_SYSTEM = """\
You are an expert web application security architect.
You are observing HTTP traffic through a proxy to identify the structural security
properties of the application — the things that are ALWAYS true regardless of
which request you look at, and which make certain attacks impossible.

Your goal is to identify:
1. Trust boundaries: authentication/authorisation rules that are consistently enforced
2. High-risk surfaces: endpoints or parameters that handle sensitive operations or data
3. Security invariants: facts about the app that make specific attack classes impossible
   (e.g. "all responses are JSON so XSS cannot execute", "redirects always stay on-domain")
4. Not-vulnerabilities: patterns that look suspicious but are structurally safe

Focus on what you OBSERVE consistently across multiple requests, not speculation.
Only include facts supported by at least 3 examples in the traffic sample.

Respond ONLY with JSON matching this schema:
{
  "trust_boundaries": ["<one sentence each>", ...],
  "high_risk_surfaces": ["<METHOD /path — reason>", ...],
  "security_invariants": ["<one sentence fact>", ...],
  "not_vulnerabilities": ["<one sentence why X cannot be exploited>", ...]
}

Rules:
- Maximum 8 items per list
- Each item must be one sentence, max 120 characters
- Base facts only on patterns you see in at least 3 requests
- Do NOT include speculative claims
- Never echo user-controlled values verbatim
"""


class ThreatModelWorker:
    """
    Background coroutine that builds per-host ThreatModel objects.
    Runs in the same event loop as AppContextWorker.
    """

    def __init__(self, store: "SessionStore", engine: "DiscoveryEngine") -> None:
        self._store = store
        self._engine = engine
        self._models: Dict[str, ThreatModel] = {}
        self._seen_count: Dict[str, int] = {}
        self._running = False

    def get_model(self, host: str) -> Optional[ThreatModel]:
        return self._models.get(host)

    def all_models(self) -> Dict[str, ThreatModel]:
        return dict(self._models)

    async def run(self) -> None:
        self._running = True
        logger.info("ThreatModelWorker started")
        while self._running:
            try:
                await self._check_all_hosts()
            except Exception as e:
                logger.debug("ThreatModelWorker loop error", error=str(e))
            await asyncio.sleep(15)

    def stop(self) -> None:
        self._running = False

    async def _check_all_hosts(self) -> None:
        # AI synthesis is an AI feature — it must stay OFF unless the user has
        # explicitly enabled AI mode. In manual mode (the default) no AI config
        # runs at all: the worker stays alive but performs no LLM analysis, and
        # resumes automatically once AI mode is turned on.
        if not getattr(self._store, "ai_mode", False):
            return

        all_entries = list(self._store.all_entries())
        settings = getattr(self._store, "_settings", None) or getattr(self, "_settings", None)
        host_entries: Dict[str, List["ProxyEntry"]] = {}
        for entry in all_entries:
            if not entry.host or entry.method == "CONNECT":
                continue
            if entry.source == "out-of-scope":
                continue
            if settings and not settings.is_in_scope(entry.url):
                continue
            host_entries.setdefault(entry.host, []).append(entry)

        for host, entries in host_entries.items():
            total = len(entries)
            last = self._seen_count.get(host, 0)
            model = self._models.get(host)

            if model is None and total >= _FIRST_THRESHOLD:
                await self._analyse(host, entries)
            elif model is not None and (total - last) >= _DELTA_ENTRIES:
                await self._analyse(host, entries)

    async def _analyse(self, host: str, entries: List["ProxyEntry"]) -> None:
        logger.info("ThreatModelWorker: analysing", host=host, entries=len(entries))
        self._seen_count[host] = len(entries)

        sample = _diverse_sample(entries, _SAMPLE_SIZE)
        traffic_lines = []
        for e in sample:
            auth_hdr = e.request_headers.get("authorization", "")
            cookie_hdr = e.request_headers.get("cookie", "")
            ct_resp = e.response_headers.get("content-type", "") if e.response_headers else ""
            cors_hdr = e.response_headers.get("access-control-allow-origin", "") if e.response_headers else ""
            location_hdr = e.response_headers.get("location", "") if e.response_headers else ""

            line = f"{e.method} {_sanitize(e.path, 80)} → {e.response_status}"
            if auth_hdr:
                line += f" | auth={_sanitize(auth_hdr[:30])}"
            if cookie_hdr:
                names = [p.split("=")[0].strip() for p in cookie_hdr.split(";") if "=" in p]
                line += f" | cookies=[{','.join(names[:4])}]"
            if ct_resp:
                line += f" | resp_ct={_sanitize(ct_resp[:40])}"
            if cors_hdr:
                line += f" | cors={_sanitize(cors_hdr[:40])}"
            if location_hdr:
                line += f" | location={_sanitize(location_hdr[:60])}"
            traffic_lines.append(line)

        user = (
            f"Host: {host}\n"
            f"Total requests observed: {len(entries)}\n"
            f"\nTraffic sample ({len(sample)} requests):\n"
            + "\n".join(traffic_lines)
        )

        try:
            from dast.ai import bedrock_client
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: bedrock_client.invoke_json(system=_SYSTEM, user=user, max_tokens=800),
            )
            self._apply_result(host, result)
            logger.info(
                "ThreatModelWorker: analysis complete",
                host=host,
                invariants=len(self._models[host].security_invariants),
            )
        except Exception as e:
            logger.warning("ThreatModelWorker: LLM call failed", host=host, error=str(e))

    def _apply_result(self, host: str, result: dict) -> None:
        existing = self._models.get(host) or ThreatModel(host=host)

        def _merge(current: List[str], incoming: list, max_items: int) -> List[str]:
            for item in incoming:
                item = str(item)[:120]
                if item and item not in current:
                    current.append(item)
            return current[:max_items]

        existing.trust_boundaries = _merge(
            existing.trust_boundaries, result.get("trust_boundaries", []), 8
        )
        existing.high_risk_surfaces = _merge(
            existing.high_risk_surfaces, result.get("high_risk_surfaces", []), 8
        )
        existing.security_invariants = _merge(
            existing.security_invariants, result.get("security_invariants", []), 8
        )
        existing.not_vulnerabilities = _merge(
            existing.not_vulnerabilities, result.get("not_vulnerabilities", []), 8
        )

        existing.last_analysed_at = time.time()
        existing.analysis_count += 1
        self._models[host] = existing


def _diverse_sample(entries: List["ProxyEntry"], n: int) -> List["ProxyEntry"]:
    seen_paths: set = set()
    result = []
    for e in reversed(entries):
        if e.path not in seen_paths:
            seen_paths.add(e.path)
            result.append(e)
        if len(result) >= n:
            break
    if len(result) < n:
        remaining = [e for e in reversed(entries) if e not in result]
        result.extend(remaining[: n - len(result)])
    return result[:n]

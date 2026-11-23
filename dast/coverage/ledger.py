"""Coverage ledger — what was examined / ruled out / left open, per surface.

Round 3-H, distilled from ARTEX's coverage ledger (BaaRai/ARTEX #207,
``db/coverage_ledger.go``). Two central invariants carry over verbatim:

- A risk class with NO entry is UNEXAMINED — never clean.
- The absence of a finding is never read as "clean": an incomplete scan
  (budget/timeout/abort) always carries a non-empty caveat.

V1 is MACHINE-OBSERVED: the Coordinator records one entry per dispatched
attack_type with a closed outcome vocabulary (the frieren agents are code
loops, not free tool-use — an LLM-facing ``record_coverage`` tool for the
copilot is a documented follow-up). Entries are normalised to a single line:
they reach the planner prompt and the dashboard card, and must never carry
newlines or control chars (ARTEX ``NormalizeCoverageField`` — anti-injection).

Storage is in-memory (house style — SessionStore is memory too): upsert with
last-write-wins per ``(surface, risk_area)`` plus a bounded append-only
history. Caps mirror ARTEX: over-limit is an ERROR, never a silent truncate.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from dast.utils.logger import get_logger

logger = get_logger(__name__)

OUTCOMES = ("reported", "no_issue_found", "ruled_out", "not_applicable", "needs_follow_up")

_SURFACE_CAP = 200
_RISK_AREA_CAP = 64
_EVIDENCE_CAP = 500
_REASON_CAP = 500
_MAX_ENTRIES = 5000          # total current rows; a NEW key above this is rejected
_MAX_HISTORY_PER_KEY = 10

# Whitespace/control normalisation: everything the agents report becomes one
# line (C0/C1/DEL + Unicode separators → space, runs collapsed).
_UNLINE_RE = re.compile(r"[\x00-\x1f\x7f\u2028\u2029\ufeff]")


def _one_line(text: str, cap: int) -> str:
    cleaned = _UNLINE_RE.sub(" ", str(text or ""))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:cap]


@dataclass
class CoverageEntry:
    """One (surface, risk_area) coverage fact. ``surface`` is the scan key —
    the same notion of 'distinct endpoint' as the scan dedup."""
    method: str
    host: str
    path: str
    op: str
    risk_area: str
    outcome: str
    evidence: str = ""
    reason: str = ""
    updated_at: float = field(default_factory=time.time)

    @property
    def surface(self) -> str:
        op = f" ({self.op})" if self.op else ""
        return f"{self.method} {self.path}{op}"

    def as_dict(self) -> Dict[str, str]:
        return {
            "surface": self.surface, "host": self.host, "method": self.method,
            "path": self.path, "op": self.op, "risk_area": self.risk_area,
            "outcome": self.outcome, "evidence": self.evidence,
            "reason": self.reason,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.updated_at)),
        }


@dataclass
class CoverageGap:
    kind: str          # unrecorded_risk_class | needs_follow_up | missing_evidence | missing_reason
    surface: str = ""
    risk_area: str = ""

    def as_line(self) -> str:
        return " ".join(p for p in (self.kind, self.surface, self.risk_area) if p)


@dataclass
class Completeness:
    complete: bool
    state: str
    caveat: str = ""


# ── store ────────────────────────────────────────────────────────────────────

_lock = threading.Lock()
_entries: Dict[Tuple[str, str], CoverageEntry] = {}          # (surface, risk_area)
_history: Dict[Tuple[str, str], List[CoverageEntry]] = {}


def _surface(method: str, path: str, op: str = "") -> str:
    op_s = f" ({_one_line(op, 64)})" if op else ""
    return f"{_one_line(method, 16)} {_one_line(path, _SURFACE_CAP - 24)}{op_s}"


def record(method: str, host: str, path: str, op: str = "", risk_area: str = "",
           outcome: str = "", evidence: str = "", reason: str = "") -> CoverageEntry:
    """Upsert one coverage entry (last write wins on the current row; the old
    row moves to the bounded history). Raises ValueError on a bad outcome or
    an over-limit NEW key — never truncates silently (ARTEX semantics)."""
    outcome = (outcome or "").strip()
    if outcome not in OUTCOMES:
        raise ValueError(f"invalid coverage outcome: {outcome!r}")
    surface = _surface(method, path, op)
    area = _one_line(risk_area, _RISK_AREA_CAP) or "unknown"
    entry = CoverageEntry(
        method=_one_line(method, 16), host=_one_line(host, _SURFACE_CAP),
        path=_one_line(path, _SURFACE_CAP), op=_one_line(op, 64),
        risk_area=area, outcome=outcome,
        evidence=_one_line(evidence, _EVIDENCE_CAP),
        reason=_one_line(reason, _REASON_CAP),
    )
    key = (surface, area)
    with _lock:
        if key not in _entries and len(_entries) >= _MAX_ENTRIES:
            raise ValueError("coverage ledger full — new keys are rejected, updates still allowed")
        old = _entries.get(key)
        if old is not None:
            hist = _history.setdefault(key, [])
            hist.append(old)
            del hist[: max(0, len(hist) - _MAX_HISTORY_PER_KEY)]
        _entries[key] = entry
    return entry


def record_scan_outcome(method: str, host: str, path: str, op: str, attack_type: str,
                        findings: Optional[List[str]] = None,
                        probe_count: int = 0,
                        blockers: Optional[List[str]] = None,
                        followups: Optional[List[str]] = None) -> Optional[CoverageEntry]:
    """Machine-observed translation of one dispatch's result into a ledger
    entry (the v1 writer — see the module docstring). Mapping:
    findings → ``reported``; auth-gated → ``not_applicable``; any other
    blocker/needs-follow-up → ``needs_follow_up``; ran clean →
    ``no_issue_found`` with probe-count evidence (an absent finding is NOT a
    silent pass — the evidence line says what covered it)."""
    area = _one_line(attack_type, _RISK_AREA_CAP)
    if not area:
        return None
    blockers = [b for b in (blockers or []) if b]
    followups = [f for f in (followups or []) if f]
    if findings:
        joined = _one_line("; ".join(findings[:2]), _EVIDENCE_CAP)
        return record(method, host, path, op, area, "reported", evidence=joined)
    lowered = " ".join(blockers).lower()
    if any(k in lowered for k in ("auth", "401", "403", "login", "credential")):
        return record(method, host, path, op, area, "not_applicable",
                      reason=_one_line("; ".join(blockers[:2]), _REASON_CAP))
    if blockers or followups:
        why = "; ".join((blockers[:2] or []) + (followups[:1] or []))
        return record(method, host, path, op, area, "needs_follow_up",
                      reason=_one_line(why, _REASON_CAP))
    return record(method, host, path, op, area, "no_issue_found",
                  evidence=f"{max(int(probe_count or 0), 0)} probes, no signal")


def entries_for(method: str, path: str, op: str = "") -> List[CoverageEntry]:
    surface = _surface(method, path, op)
    with _lock:
        return [e for (s, _a), e in sorted(_entries.items()) if s == surface]


def history_for(method: str, path: str, op: str, risk_area: str) -> List[CoverageEntry]:
    surface = _surface(method, path, op)
    key = (surface, _one_line(risk_area, _RISK_AREA_CAP))
    with _lock:
        return list(_history.get(key, []))


def reset() -> None:
    with _lock:
        _entries.clear()
        _history.clear()


# ── derivation ───────────────────────────────────────────────────────────────

def build_ledger(entries: List[CoverageEntry], candidate_classes: Optional[List[str]] = None,
                 completeness: Optional[Completeness] = None) -> Dict[str, object]:
    """Derive {entries, gaps, unexamined, findings_by_class, completeness} from
    the raw rows (ARTEX ``BuildCoverageLedger``). Gap order: the central
    invariant first — unrecorded classes — then per-entry gaps in input order.
    A class is CLOSED by ``reported``, or ``no_issue_found`` with evidence, or
    ``ruled_out``/``not_applicable`` with reason; ``needs_follow_up`` keeps the
    gap open. Findings never close a class on their own beyond ``reported``."""
    entries = list(entries or [])
    gaps: List[CoverageGap] = []
    covered_classes = set()
    findings_by_class: Dict[str, int] = {}
    for e in entries:
        area = e.risk_area.lower()
        if e.outcome == "reported":
            covered_classes.add(area)
            findings_by_class[area] = findings_by_class.get(area, 0) + 1
        elif e.outcome == "no_issue_found":
            if e.evidence.strip():
                covered_classes.add(area)
            else:
                gaps.append(CoverageGap("missing_evidence", e.surface, e.risk_area))
        elif e.outcome in ("ruled_out", "not_applicable"):
            if e.reason.strip():
                covered_classes.add(area)
            else:
                gaps.append(CoverageGap("missing_reason", e.surface, e.risk_area))
        elif e.outcome == "needs_follow_up":
            # Covered but open (ARTEX: needs_follow_up keeps the class out of
            # `unexamined` while the gap stays listed).
            covered_classes.add(area)
            gaps.append(CoverageGap("needs_follow_up", e.surface, e.risk_area))
    unexamined = sorted({c.lower().strip() for c in (candidate_classes or [])
                         if c and c.lower().strip() not in covered_classes})
    if unexamined:  # the central invariant leads; keep sorted order
        gaps[:0] = [CoverageGap("unrecorded_risk_class", risk_area=cls)
                    for cls in unexamined]
    return {
        "entries": entries,
        "gaps": gaps,
        "unexamined": unexamined,
        "findings_by_class": findings_by_class,
        "completeness": completeness,
    }


def completeness_for(end_reason: str = "") -> Completeness:
    """Run-completeness caveat (ARTEX ``CoverageCompletenessFor`` precedence:
    budget > timeout > aborted > paused > in_progress). An incomplete run is
    NEVER silent — the caveat always explains that a missing finding is not a
    clean bill."""
    reason = (end_reason or "").strip().lower()
    if not reason:
        return Completeness(True, "complete")
    if reason == "budget":
        return Completeness(False, "budget",
                            "Incomplete scan (budget): the per-endpoint time budget ran out "
                            "before every selected agent finished — uncovered classes were "
                            "NOT tested; the absence of a finding does not mean the target "
                            "is clean.")
    if reason in ("timeout", "deadline"):
        return Completeness(False, "timeout",
                            "Incomplete scan (timeout): the endpoint deadline hit before "
                            "every selected agent finished — uncovered classes were NOT "
                            "tested; the absence of a finding does not mean the target is "
                            "clean.")
    if reason in ("aborted", "failed", "error", "cancelled"):
        return Completeness(False, "aborted",
                            "Incomplete scan (aborted): the run was cancelled or failed — "
                            "uncovered classes were NOT tested; the absence of a finding "
                            "does not mean the target is clean.")
    if reason == "paused":
        return Completeness(False, "paused",
                            "Scan paused — coverage so far is partial.")
    return Completeness(False, reason or "in_progress",
                        "Scan not finished — coverage so far is partial.")


def planner_gap_lines(method: str, path: str, op: str = "",
                      candidate_classes: Optional[List[str]] = None,
                      max_gaps: int = 3) -> List[str]:
    """Gap lines for the planner prompt (top-N, unrecorded classes first —
    ARTEX ``plannerLedgerTopGaps``). Empty list when there is nothing to say:
    the caller keeps the prompt byte-identical in that case."""
    surface = _surface(method, path, op)
    with _lock:
        entries = [e for (s, _a), e in sorted(_entries.items()) if s == surface]
    ledger = build_ledger(entries, candidate_classes)
    return [g.as_line() for g in ledger["gaps"]][:max_gaps]


# ── dashboard aggregation ────────────────────────────────────────────────────

def snapshot(host: Optional[str] = None) -> Dict[str, object]:
    """Aggregate for GET /api/coverage: per-host outcome histogram + open
    needs_follow_up gaps + reported findings. Hosts with no rows are omitted."""
    with _lock:
        entries = list(_entries.values())
    by_host: Dict[str, Dict[str, object]] = {}
    for e in entries:
        if host and e.host != host:
            continue
        h = by_host.setdefault(e.host, {
            "entries": 0, "outcomes": {}, "findings": 0,
            "needs_follow_up": [], "last_updated_at": 0.0,
        })
        h["entries"] += 1
        h["outcomes"][e.outcome] = h["outcomes"].get(e.outcome, 0) + 1
        if e.outcome == "reported":
            h["findings"] += 1
        if e.outcome == "needs_follow_up":
            h["needs_follow_up"].append(f"{e.surface} {e.risk_area}")
        h["last_updated_at"] = max(float(h["last_updated_at"]), e.updated_at)
    for h in by_host.values():
        h["needs_follow_up"].sort()
        h["last_updated_at"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.localtime(float(h["last_updated_at"])))
    return {
        "total_entries": len(entries),
        "hosts": dict(sorted(by_host.items())),
    }

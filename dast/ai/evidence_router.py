"""
Evidence -> action router.

Turns the signals Frieren already derives from traffic (tech/DB fingerprint,
app-context vuln hypotheses, probe-diff verdicts, data-flow CallEdges, LLM /
GraphQL endpoint registries, per-host WAF/ineffective/confirmed intel) into a
ranked list of recommended tool/attack actions — and a list of attacks to AVOID
(wrong DB dialect, already confirmed, known-ineffective, already tested). This is
the deterministic half of "see id=123 -> test SQLi; see an AI prompt -> test
prompt injection; MySQL -> don't test MSSQL".

``route()`` is PURE (operates on a ``RouterEvidence`` bundle) so it is trivially
unit-testable and reused by both the copilot driver and (later) the coordinator.
``RouterEvidence.from_store`` is the one store-coupled adapter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, List, Set, Tuple

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Same keyword set as dast/passive_rules/ai/llm_endpoints.yaml — an endpoint whose
# path looks like an LLM/AI inference route should be tested for prompt injection.
_LLM_PATH_RE = re.compile(
    r"/(?:v\d+/)?(?:chat|completions?|generate|llm|copilot|assistant|gpt|claude|"
    r"bedrock|openai|messages|inference|predict|prompt)(?:/|$|\?)",
    re.IGNORECASE,
)

_HIGH, _MED, _LOW = 0.8, 0.5, 0.3
_PRIORITY_CONFIDENCE = {"high": _HIGH, "medium": _MED, "low": _LOW}

# Within-target replan (coordinator feedback loop): a CONFIRMED injection means the
# input reaches an interpreter unsanitised, so the adjacent injection classes are
# worth a follow-up pass on the same endpoint. A confirmed IDOR implies auth-bypass
# siblings; LFI implies SSRF (both are "fetch a resource the server controls").
# Deliberately small and injection-centric — not a brainstorm of every attack type.
_FOLLOWUP_MAP = {
    "sqli": ["ssti", "cmdi"],
    "ssti": ["cmdi", "sqli"],
    "cmdi": ["ssti", "sqli"],
    "xss": ["ssti"],
    "idor": ["auth_bypass"],
    "lfi": ["ssrf"],
}


def implied_followups(confirmed_attack_types, already_run) -> List[str]:
    """Attack types a confirmed finding implies are worth testing next on the SAME
    target, minus anything already run this pass. Pure; order-stable; deduped."""
    done = set(already_run or ())
    out: List[str] = []
    for atype in confirmed_attack_types or ():
        for follow in _FOLLOWUP_MAP.get(atype, ()):
            if follow not in done and follow not in out:
                out.append(follow)
    return out


@dataclass
class RouteRecommendation:
    kind: str                 # tool to call: run_scan | idor_probe | graphql_sweep | graphql_fuzz
    attack_type: str          # e.g. sqli, llm_injection, idor ("" when tool is not type-specific)
    target_url: str
    target_param: str = ""
    rationale: str = ""
    confidence: float = _MED
    source: str = ""          # tech_stack | vuln_hypothesis | probe_verdict | call_edge | llm_endpoint | graphql
    auto_safe: bool = False    # unambiguous + safe enough to auto-run deterministically


@dataclass
class RouteAvoid:
    attack_type: str
    target: str = ""          # "" = host-wide
    reason: str = ""


@dataclass
class RouterEvidence:
    tech_stack: Any = None
    call_edges: List[Any] = field(default_factory=list)
    app_profile: Any = None
    host_intel: Any = None
    graphql_endpoints: Set[str] = field(default_factory=set)
    llm_endpoints: List[Tuple[str, str]] = field(default_factory=list)   # (url, path)
    probe_verdicts: List[Tuple[str, str, Any]] = field(default_factory=list)  # (url, param, ProbeVerdict)
    tested_ledger: Set[Tuple[str, str]] = field(default_factory=set)     # (norm_path, attack_type | "*")
    tested_gql_ops: Set[str] = field(default_factory=set)                # graphql endpoints fully swept

    @classmethod
    def from_store(cls, store: Any, host: str) -> "RouterEvidence":
        """Gather the evidence bundle for a host from the live store. The only
        store-coupled code; everything else operates on this bundle."""
        from dast.plugins.graphql_analyzer import _is_graphql
        from dast.proxy.session_store import normalise_endpoint_path

        ev = cls()
        host = (host or "").split(":")[0]
        engine = getattr(store, "discovery_engine", None)
        if engine is not None:
            try:
                ctx = engine.context_for_host(host)
                if ctx is not None:
                    ev.tech_stack = getattr(ctx, "tech_stack", None)
                    ev.call_edges = list(getattr(ctx, "call_edges", None) or [])
            except Exception as exc:  # noqa: BLE001 — evidence is best-effort
                logger.debug("router evidence: discovery context failed", host=host, error=str(exc))
            try:
                ev.app_profile = engine.get_app_profile(host)
            except Exception as exc:  # noqa: BLE001
                logger.debug("router evidence: app profile failed", host=host, error=str(exc))

        intel = getattr(store, "session_intelligence", None)
        if intel is not None:
            try:
                ev.host_intel = intel.peek(host)
                if ev.host_intel is not None:
                    ev.graphql_endpoints = set(getattr(ev.host_intel, "graphql_endpoints", None) or set())
            except Exception as exc:  # noqa: BLE001
                logger.debug("router evidence: host intel failed", host=host, error=str(exc))

        # Per-entry scan: scanned endpoints (ledger) + LLM endpoints + graphql urls.
        llm_seen: Set[str] = set()
        try:
            for entry in store.in_scope_entries():
                ehost = (getattr(entry, "host", "") or "").split(":")[0]
                if ehost != host:
                    continue
                path = getattr(entry, "path", "") or ""
                norm = normalise_endpoint_path(path)
                if getattr(entry, "scan_result", None):
                    ev.tested_ledger.add((norm, "*"))
                if _is_graphql(entry):
                    ev.graphql_endpoints.add(entry.url)
                elif _LLM_PATH_RE.search(path) and norm not in llm_seen:
                    llm_seen.add(norm)
                    ev.llm_endpoints.append((entry.url, path))
        except Exception as exc:  # noqa: BLE001
            logger.debug("router evidence: entry scan failed", host=host, error=str(exc))

        # Confirmed vulns are both a "tested" and an "avoid re-recommending" signal.
        if ev.host_intel is not None:
            try:
                for (p, _param), types in (getattr(ev.host_intel, "confirmed_vulns", None) or {}).items():
                    for attack_type in types:
                        ev.tested_ledger.add((normalise_endpoint_path(p), attack_type))
            except Exception as exc:  # noqa: BLE001
                logger.debug("router evidence: confirmed vulns failed", host=host, error=str(exc))

        gql_tested = getattr(store, "graphql_tested_ops", None) or {}
        ev.tested_gql_ops = {url for url, ops in gql_tested.items() if ops}
        return ev


@dataclass
class RoutingPlan:
    recommend: List[RouteRecommendation] = field(default_factory=list)
    avoid: List[RouteAvoid] = field(default_factory=list)

    def auto_actions(self, read_only: bool = False) -> List[RouteRecommendation]:
        """The auto_safe subset. In read-only, active tools are dropped — only
        read/recon kinds survive (so mapping continues, no attack traffic)."""
        safe_in_read_only = {"graphql_introspect"}
        out = []
        for rec in self.recommend:
            if not rec.auto_safe:
                continue
            if read_only and rec.kind not in safe_in_read_only:
                continue
            out.append(rec)
        return out

    def to_prompt_block(self, max_items: int = 8) -> str:
        if not self.recommend and not self.avoid:
            return ""
        lines = ["Evidence-driven recommendations (derived from observed signals — act on these):"]
        for rec in self.recommend[:max_items]:
            where = rec.target_param and f" param={rec.target_param}" or ""
            atk = rec.attack_type and f" [{rec.attack_type}]" or ""
            lines.append(f"- {rec.kind}{atk} on {rec.target_url}{where} — {rec.rationale}")
        if self.avoid:
            lines.append("Do NOT waste calls on (evidence rules these out):")
            for av in self.avoid[:max_items]:
                scope = av.target or "this host"
                lines.append(f"- {av.attack_type} on {scope} — {av.reason}")
        return "\n".join(lines)


def _norm(path_or_url: str) -> str:
    from dast.proxy.session_store import normalise_endpoint_path
    from urllib.parse import urlparse
    try:
        parsed = urlparse(path_or_url)
        return normalise_endpoint_path(parsed.path or path_or_url)
    except Exception:
        return normalise_endpoint_path(path_or_url)


def route(evidence: RouterEvidence) -> RoutingPlan:
    """Pure: evidence bundle -> ranked recommendations + avoids."""
    from dast.agents.db_dialect import definite_db

    plan = RoutingPlan()
    ineffective: Set[str] = set()
    if evidence.host_intel is not None:
        try:
            ineffective = set(evidence.host_intel.consistently_ineffective_types())
        except Exception:  # noqa: BLE001
            ineffective = set()

    def _is_tested(path: str, attack_type: str) -> bool:
        norm = _norm(path)
        return (norm, "*") in evidence.tested_ledger or (norm, attack_type) in evidence.tested_ledger

    def _add(rec: RouteRecommendation) -> None:
        if rec.attack_type and rec.attack_type in ineffective:
            return  # known ineffective host-wide
        if rec.attack_type and _is_tested(rec.target_url, rec.attack_type):
            return  # already tested/confirmed — the loop shrinks here
        plan.recommend.append(rec)

    # 1) Data-flow numeric-id / uuid -> sqli + idor
    from dast.ai.coordinator import _classify_param
    for edge in evidence.call_edges:
        param = getattr(edge, "target_param", "") or ""
        value = getattr(edge, "sample_value", "") or ""
        url = getattr(edge, "target_url", "") or ""
        if not url or not param:
            continue
        kind = _classify_param(param, value)
        if kind not in ("numeric_id", "uuid"):
            continue
        conf = float(getattr(edge, "confidence", 0.5) or 0.5)
        auto = conf >= 0.9
        _add(RouteRecommendation("run_scan", "sqli", url, param,
                                 f"{param}={value or kind} flows between endpoints — test SQL injection",
                                 conf, "call_edge", auto))
        _add(RouteRecommendation("idor_probe", "idor", url, param,
                                 f"{param} is an object reference — test IDOR/BOLA by swapping ids",
                                 conf, "call_edge", auto))

    # 2) LLM endpoint -> llm_injection
    for url, path in evidence.llm_endpoints:
        _add(RouteRecommendation("run_scan", "llm_injection", url, "",
                                 "endpoint looks like an AI/LLM route — test prompt injection",
                                 _HIGH, "llm_endpoint", auto_safe=True))

    # 3) Probe-diff verdicts -> recommended agents
    for url, param, verdict in evidence.probe_verdicts:
        agents = list(getattr(verdict, "recommended_agents", None) or [])
        if not agents:
            inj = getattr(verdict, "injection_class", "") or ""
            if inj and inj != "none":
                agents = [inj]
        conf = float(getattr(verdict, "confidence", 0.5) or 0.5)
        for attack_type in agents:
            _add(RouteRecommendation("run_scan", attack_type, url, param,
                                     f"probe-diff signature points to {attack_type}",
                                     conf, "probe_verdict", conf >= 0.7))

    # 4) App-context vuln hypotheses -> the hypothesised agent
    hyps = getattr(evidence.app_profile, "vuln_hypotheses", None) or [] if evidence.app_profile else []
    for hyp in hyps:
        attack_type = getattr(hyp, "attack_type", "") or ""
        if not attack_type:
            continue
        priority = (getattr(hyp, "priority", "") or "low").lower()
        conf = _PRIORITY_CONFIDENCE.get(priority, _LOW)
        endpoint = getattr(hyp, "endpoint", "") or ""
        kind = "idor_probe" if attack_type == "idor" else "run_scan"
        _add(RouteRecommendation(kind, attack_type, endpoint, getattr(hyp, "parameter", "") or "",
                                 getattr(hyp, "rationale", "") or f"app-context hypothesis: {attack_type}",
                                 conf, "vuln_hypothesis", priority in ("high", "medium")))

    # 5) GraphQL endpoint not yet fully swept -> sweep/fuzz
    for gql_url in sorted(evidence.graphql_endpoints):
        if gql_url in evidence.tested_gql_ops:
            continue
        _add(RouteRecommendation("graphql_sweep", "", gql_url, "",
                                 "GraphQL endpoint not yet swept — introspect+sweep, or fuzz captured ops",
                                 _HIGH, "graphql", auto_safe=True))

    # 6) AVOID — wrong DB dialect, known-ineffective (confirmed/tested already filtered above)
    hints = getattr(evidence.tech_stack, "database_hints", None) or [] if evidence.tech_stack else []
    db = definite_db(hints)
    if db:
        for other in ("MySQL", "MSSQL", "PostgreSQL", "Oracle", "SQLite"):
            if other != db:
                plan.avoid.append(RouteAvoid("sqli", "", f"backend is {db} — skip {other}-specific SQLi payloads"))
                break  # one concise avoid line is enough for the prompt
        plan.avoid.append(RouteAvoid("sqli", "", f"backend DB confirmed {db} — other dialects' payloads are noise"))
    for attack_type in sorted(ineffective):
        plan.avoid.append(RouteAvoid(attack_type, "", "consistently ineffective on this host so far"))

    plan.recommend.sort(key=lambda r: r.confidence, reverse=True)
    return plan

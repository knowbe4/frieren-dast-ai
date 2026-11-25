"""Chain inventor — the copilot COMPOSES attack chains from local findings.

Round 5-B-4 (XBOW/ARTEX). ``ChainEngine`` + ``validate_chain`` execute chains
that are *described* (by a report or by hand); nothing proposed chains from the
scan's own findings. The inventor closes that loop: given the confirmed
findings of one host, the LLM proposes at most 2 candidate chains (schema
forced, ``{{var}}`` extractors compatible with ``ChainEngine`` — SSRF→metadata,
IDOR→foreign object, open-redirect→OAuth, reflected XSS + sensitive endpoint…).
Every candidate is then validated by the real engine with the existing
payload-safety and scope gates, plus one inventor-specific rule: a MANDATORY
impact assertion on the final sensitive step (or the step before a control
step) — a chain that cannot assert impact is rejected before any traffic.

Outcome bookkeeping (ARTEX semantics): a chain the engine CONFIRMS becomes a
``chain`` finding grounded in real history; a chain the engine REFUTES is
recorded as ``ruled_out`` in the coverage ledger (risk_area ``chain``), so a
later run does not re-invent the same dead combination.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dast.ai import bedrock_client
from dast.ai.prompt_safety import UNTRUSTED_CONTENT_DIRECTIVE, wrap_untrusted
from dast.ai.schemas import ATTACK_CHAIN_SCHEMA
from dast.chains.models import Chain
from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Assertion kinds that prove IMPACT (vs. mere reachability like status_eq).
IMPACT_ASSERTION_KINDS = {
    "body_contains", "header_contains", "var_present", "var_contains", "var_equals",
}

_INVENT_SYSTEM = (
    "You are a red-team chain inventor. You are given the CONFIRMED findings of one "
    "host plus known endpoints. Compose at most 2 attack CHAINS that combine those "
    "findings into a compound impact none of them proves alone — the classic XBOW "
    "moves: SSRF->cloud metadata, IDOR->foreign object read, open-redirect->OAuth "
    "token theft, reflected XSS + a sensitive endpoint, unauth bootstrap -> "
    "privileged read.\n\n"
    "Rules:\n"
    "1. Use ONLY hosts/paths/parameters that appear in the findings or endpoints you "
    "were given. Do not invent endpoints.\n"
    "2. Thread state with extractors: bind a token/cookie/path out of one response "
    "and consume it later via {{variable}}. Set-Cookie is harvested automatically.\n"
    "3. MANDATORY: the final sensitive step (or the step immediately before a "
    "send_cookies:[] control step) MUST carry an impact assertion — body_contains / "
    "header_contains / var_present / var_contains proving the sensitive data was "
    "actually reached. A chain without one will be rejected.\n"
    "4. End with a CONTROL step (send_cookies: [] or without the key credential) "
    "asserting the request now FAILS (status_in [401,403]) when a credential is what "
    "defeats the check.\n"
    "5. SAFETY: this runs against a LIVE target. Never write/delete/mutate. Fetch "
    "content with max_range_bytes (e.g. 64) so only a proof-sized slice is read. "
    "Detection only.\n"
    "6. Fewest steps that prove the compound impact. If the findings cannot compose "
    "a chain, return an empty list — do not force one."
)
_INVENT_SYSTEM += UNTRUSTED_CONTENT_DIRECTIVE

# Reuse the attack-chain step schema verbatim — inventor output is engine input.
_CHAIN_ITEMS: Dict[str, Any] = ATTACK_CHAIN_SCHEMA["properties"]["steps"]["items"]
_INVENTED_CHAINS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "chains": {
            "type": "array",
            "maxItems": 2,
            "description": "At most 2 candidate chains, highest expected impact first.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Short slug, e.g. 'ssrf-metadata-chain'."},
                    "description": {"type": "string", "description": "What the chain proves and why it matters."},
                    "vuln_type": {"type": "string", "description": "broken_access_control | business_logic | auth_bypass | idor | info_disclosure | attack_chain."},
                    "rationale": {"type": "string", "description": "Which findings this composes and why they compound."},
                    "steps": {
                        "type": "array",
                        "description": "Ordered requests, per the chain-step rules.",
                        "items": _CHAIN_ITEMS,
                    },
                },
                "required": ["name", "steps"],
            },
        },
    },
    "required": ["chains"],
}


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


def chain_has_impact_assertion(chain: Chain) -> bool:
    """Mandatory-impact gate (5-B-4): the final step asserts impact, or the step
    before a trailing control step does."""
    steps = chain.steps
    if not steps:
        return False

    def _has(step) -> bool:
        return any(a.kind in IMPACT_ASSERTION_KINDS for a in step.assertions)

    if _has(steps[-1]):
        return True
    return len(steps) >= 2 and steps[-1].send_cookies == [] and _has(steps[-2])


async def _gather_findings(ctx) -> List[dict]:
    """Finding rows from the in-process store or the dashboard API (MCP path)."""
    store = getattr(ctx, "store", None)
    if store is not None:
        from dast.tools.findings_tools import flatten_findings
        return flatten_findings([e.to_dict() for e in store.all_entries()])
    import httpx

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{ctx.dashboard_base_url}/api/findings")
        resp.raise_for_status()
        rows = resp.json()
    return rows if isinstance(rows, list) else []


def invent_candidates(
    findings: List[dict], endpoints: List[str], host: str,
    model_id: Optional[str] = None,
) -> List[dict]:
    """LLM pass: findings inventory -> <=2 candidate chain specs (sync)."""
    lines = []
    for row in findings[:20]:
        lines.append(
            f"- [{row.get('severity', '?')}] {row.get('title', '?')} "
            f"({row.get('attack_type', '?')}) {row.get('method', 'GET')} "
            f"{row.get('url', row.get('host', ''))}"
            + (f" — param {row.get('parameter')}" if row.get("parameter") else "")
        )
    ep_lines = [f"- {ep}" for ep in endpoints[:15]]
    user = (
        f"Host under test: {host}\n\nConfirmed findings:\n"
        + wrap_untrusted("\n".join(lines) or "- (none)", "findings", 6000)
        + "\n\nKnown endpoints:\n"
        + wrap_untrusted("\n".join(ep_lines) or "- (none)", "endpoints", 2000)
        + "\n\nPropose at most 2 chains that COMPOUND these findings into a "
          "demonstrable impact. Empty list if nothing composes."
    )
    try:
        data = bedrock_client.invoke_json(
            system=_INVENT_SYSTEM,
            user=user,
            model_id=model_id,
            max_tokens=4000,
            temperature=0,
            cache_system=True,
            schema=_INVENTED_CHAINS_SCHEMA,
            purpose="chain_inventor",
        )
    except Exception as exc:
        logger.warning("chain invention failed", error=str(exc))
        return []
    chains = data.get("chains") if isinstance(data, dict) else None
    return [c for c in chains if isinstance(c, dict)][:2] if chains else []


async def run_inventor(ctx, host: Optional[str] = None, max_chains: int = 2) -> Dict[str, Any]:
    """Compose + validate chains for ``host`` (default: host with most findings,
    minimum 2 findings required). Returns a summary of confirmed/ruled_out.

    One call = one attempt per host with a small budget — callers (the
    autonomous driver at run end, or the ``invent_chain`` tool) decide when.
    """
    from dast.tools.chain_tools import _make_sender  # reuse the proxy-routed sender

    rows = await _gather_findings(ctx)
    confirmed_rows = [r for r in rows if not r.get("dismissed")]
    by_host: Dict[str, List[dict]] = {}
    for row in confirmed_rows:
        by_host.setdefault(_host_of(row.get("url", "") or f"https://{row.get('host', '')}/"), []).append(row)

    if host:
        host = _host_of(host) or host
        host_rows = by_host.get(host, [])
    else:
        host, host_rows = max(
            by_host.items(), key=lambda kv: len(kv[1]), default=(None, []))
    if not host or len(host_rows) < 2:
        return {"ok": False, "error": "need a host with >=2 findings to compose chains",
                "host": host, "finding_count": len(host_rows)}

    endpoints: List[str] = []
    for row in host_rows:
        url = row.get("url", "")
        if url and url not in endpoints:
            endpoints.append(url)

    loop = asyncio.get_running_loop()
    candidates = await loop.run_in_executor(
        None, lambda: invent_candidates(host_rows, endpoints, host))
    if not candidates:
        return {"ok": True, "host": host, "tried": 0,
                "confirmed": [], "ruled_out": []}

    sender = await _make_sender(ctx)
    from dast.chains.engine import ChainEngine

    out_confirmed: List[dict] = []
    out_ruled_out: List[dict] = []
    for spec in candidates[:max_chains]:
        name = str(spec.get("name", "invented_chain"))[:80]
        try:
            chain = Chain.from_dict(spec)
        except Exception as exc:
            out_ruled_out.append({"name": name, "status": "invalid",
                                  "reason": f"bad spec: {str(exc)[:160]}"})
            continue
        if not chain.steps:
            out_ruled_out.append({"name": name, "status": "invalid",
                                  "reason": "no steps"})
            continue
        # Scope gate over literal hosts (templated hosts are gated at runtime).
        out_of_scope = [
            _host_of(s.url) for s in chain.steps
            if s.url and "{{" not in s.url and not ctx.is_in_scope(s.url)
        ]
        if any(out_of_scope):
            out_ruled_out.append({"name": name, "status": "blocked",
                                  "reason": "out-of-scope host", "hosts": out_of_scope})
            continue
        if not chain_has_impact_assertion(chain):
            out_ruled_out.append({"name": name, "status": "invalid",
                                  "reason": "no impact assertion on the final sensitive step"})
            continue

        engine = ChainEngine(sender=sender, is_in_scope=ctx.is_in_scope)
        result = await engine.run(chain)
        if result.status == "confirmed":
            finding = {
                "title": f"Attack Chain Confirmed: {chain.name}",
                "severity": "high",
                "cwe": "",
                "attack_type": "chain",
                "evidence": (result.evidence or "")[:4000] or chain.description,
                "reasoning": str(spec.get("rationale", ""))[:500],
                "steps": [
                    {"url": s.get("url", ""), "method": s.get("method", "GET"),
                     "description": s.get("name", "")}
                    for s in spec.get("steps", []) if isinstance(s, dict)
                ],
            }
            store = getattr(ctx, "store", None)
            if store is not None:
                store.record_manual_finding(
                    finding, url=endpoints[0] if endpoints else f"https://{host}/",
                    method=(spec.get("steps") or [{}])[0].get("method", "GET"),
                )
            out_confirmed.append({
                "name": chain.name, "vuln_type": chain.vuln_type,
                "description": chain.description, "recorded": store is not None,
                "evidence": (result.evidence or "")[:1500],
            })
        else:
            out_ruled_out.append({"name": name, "status": result.status,
                                  "reason": chain.description[:200]})
            # ARTEX bookkeeping: the dead combination is closed so a later run
            # does not re-invent it (bounded ledger upsert; failures never fatal).
            try:
                from dast.coverage import ledger
                ledger.record(
                    method="CHAIN", host=host, path=f"/chain/{chain.name}",
                    op="invented", risk_area="chain", outcome="ruled_out",
                    evidence=f"chain engine verdict: {result.status}",
                    reason=chain.description[:200],
                )
            except Exception as exc:
                logger.debug("chain ruled_out ledger write failed", error=str(exc))

    logger.info("chain inventor done", host=host, candidates=len(candidates),
                confirmed=len(out_confirmed), ruled_out=len(out_ruled_out))
    return {"ok": True, "host": host, "tried": len(candidates[:max_chains]),
            "confirmed": out_confirmed, "ruled_out": out_ruled_out}

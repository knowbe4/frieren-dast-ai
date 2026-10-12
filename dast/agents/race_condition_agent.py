"""
Race condition agent — TOCTOU / double-spend via concurrent duplicate requests.

Approach (hybrid, FP-first):
  1. Replay the ORIGINAL request once (baseline) — no values are changed, the
     agent only re-sends what the user's browser already sent.
  2. LLM gate (optional): judge from params + baseline response whether the
     endpoint is a plausible race target (single-use resource, balance, vote,
     claim). With AI unavailable, fall back to a conservative keyword filter on
     parameter names.
  3. Burst: a small number of identical concurrent requests (asyncio.gather).
  4. Confirm deterministically: for single-use semantics, two or more DISTINCT
     success responses (same request, different business outcome) is a
     double-spend by construction. Divergent-but-unclear outcomes go through a
     final LLM verdict; anything ambiguous is dropped.

Safety: detection only — no new amounts, users, or resources are created; the
burst re-uses the exact captured request, capped at _BURST_SIZE copies.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai import bedrock_client
from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.prompt_safety import wrap_untrusted
from dast.ai.schemas import RACE_CANDIDATE_SCHEMA, RACE_VERDICT_SCHEMA
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_BURST_SIZE = 5

# Deterministic fallback gate when no LLM is available: parameter names that
# smell like limited-resource / single-use operations.
_RACE_PARAM_RE = re.compile(
    r"coupon|voucher|gift|promo|vote|ballot|like|follow|reward|point|credit|"
    r"balance|withdraw|transfer|claim|redeem|ticket|checkout|quantity|qty|amount",
    re.IGNORECASE,
)

# Response words that indicate the operation was REFUSED (used to count true
# successes). Matched case-insensitively on the body.
_FAILURE_RE = re.compile(
    r"already\s+(been\s+)?(?:used|claimed|redeemed|voted)|insufficient|exceed|"
    r"limit\s+reach|not\s+enough|duplicate|invalid|expired|error|failed|denied",
    re.IGNORECASE,
)

_SYSTEM_GATE = """\
You are a senior web application security tester judging whether an endpoint is worth
testing for a race condition (TOCTOU / double-spend).

Answer worth_racing=true ONLY when the endpoint performs an operation where two
identical concurrent requests could beat a server-side single-use check, balance,
quota, or limit — redemption, voting, transferring, claiming, checkout, following.
Answer false for pure reads, searches, uploads, idempotent updates, login flows.

Answer single_use=true when the business semantics allow the operation to succeed at
most once per resource (one coupon redemption, one vote per user, one claim).

Judge from the actual parameters and baseline response, never from the URL path alone.
"""

_SYSTEM_VERDICT = """\
You are a senior web application security tester. A DAST scanner sent the SAME request
{burst} times concurrently. You get the baseline (single) response and the distinct
response variants observed in the burst.

Decide confirmed=true ONLY if the responses prove the server applied the operation more
times than its business rules allow — e.g. the single-use coupon was accepted twice, the
balance went negative, the vote was counted twice. Divergence alone (one 409 vs one 200
from interleaving) is evidence of missing serialization only when the successes repeat.
When in doubt, answer false — a false positive wastes a developer's time.
"""


async def _llm_gate(target: "CheckTarget", baseline_text: str) -> Optional[dict]:
    """Ask the LLM whether the endpoint is race-worthy; None on any failure."""
    param_names = ", ".join(p.get("name", "") for p in (target.params or [])) or "(none)"
    user = (
        f"Method: {target.method}\n"
        f"Endpoint: {target.url[:200]}\n"
        f"Parameters: {wrap_untrusted(param_names, 'target_params', 300)}\n"
        f"Body: {wrap_untrusted((target.body or '')[:400], 'target_body', 400)}\n\n"
        f"--- Baseline response (single replay of the original request) ---\n"
        f"{wrap_untrusted(baseline_text[:800], 'target_response', 800)}\n"
    )
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=_SYSTEM_GATE, user=user, schema=RACE_CANDIDATE_SCHEMA, temperature=0
            ),
        )
    except Exception as exc:
        logger.debug("Race agent LLM gate failed", error=str(exc))
        return None


async def _llm_verdict(baseline_text: str, variants: List[str], burst_size: int) -> Optional[dict]:
    """Ask the LLM for a final verdict on ambiguous burst outcomes; None on failure."""
    variant_blocks = "\n\n".join(
        f"--- Burst response variant {index + 1} ---\n{wrap_untrusted(v[:500], 'target_response', 500)}"
        for index, v in enumerate(variants[:4])
    )
    user = (
        f"--- Baseline (single request) ---\n{wrap_untrusted(baseline_text[:500], 'target_response', 500)}\n\n"
        f"{variant_blocks}\n"
    )
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: bedrock_client.invoke_json(
                system=_SYSTEM_VERDICT.format(burst=burst_size),
                user=user,
                schema=RACE_VERDICT_SCHEMA,
                temperature=0,
            ),
        )
    except Exception as exc:
        logger.debug("Race agent LLM verdict failed", error=str(exc))
        return None


def _is_success(status: int, text: str) -> bool:
    return 200 <= status < 300 and not _FAILURE_RE.search(text or "")


def _distinct_successes(responses: List["httpx.Response"]) -> List[str]:
    """Distinct bodies among the successful burst responses."""
    seen: set[str] = set()
    for resp in responses:
        if _is_success(resp.status_code, resp.text):
            body = (resp.text or "").strip()[:600]
            if body not in seen:
                seen.add(body)
    return list(seen)


class RaceConditionAgent(VulnAgent):
    name = "Race Condition Agent"
    attack_type = "race_condition"
    description = (
        "Tests state-changing endpoints for TOCTOU/double-spend races by replaying the "
        "original request concurrently and diffing the business outcomes."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if target.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return []

        # Baseline: one replay of the exact original request.
        try:
            baseline = await _send(client, target.method, target.url, target.headers, target.body)
        except Exception as exc:
            logger.debug("Race agent baseline failed", url=target.url, error=str(exc))
            return []
        if baseline is None or baseline.status_code >= 400:
            return []
        baseline_text = baseline.text or ""
        if _FAILURE_RE.search(baseline_text):
            # The original request already failed business validation — nothing to race.
            return []

        # Gate: LLM judgement, falling back to the keyword filter.
        param_names = [p.get("name", "") for p in (target.params or [])]
        keyword_hit = any(_RACE_PARAM_RE.search(name or "") for name in param_names) or bool(
            _RACE_PARAM_RE.search(target.body or "")
        )
        gate = await _llm_gate(target, baseline_text)
        if gate is not None:
            if not gate.get("worth_racing"):
                return []
            single_use = bool(gate.get("single_use"))
        else:
            if not keyword_hit:
                return []
            single_use = True  # keyword filter only fires on single-use-shaped params

        # Burst: identical concurrent replays.
        try:
            responses = list(await asyncio.gather(*[
                _send(client, target.method, target.url, target.headers, target.body)
                for _ in range(_BURST_SIZE)
            ]))
        except Exception as exc:
            logger.debug("Race agent burst failed", url=target.url, error=str(exc))
            return []
        responses = [r for r in responses if r is not None]
        for resp in responses:
            if resp.status_code == 429:
                self.observe("rate_limit", payload="", signal=f"429 during race burst on {target.path}")
                return []

        successes = [r for r in responses if _is_success(r.status_code, r.text)]
        distinct_successes = _distinct_successes(responses)

        # Deterministic confirmation: a single-use operation that succeeded more
        # than once in the burst is a double-spend by construction.
        if single_use and len(successes) >= 2 and len(distinct_successes) >= 1:
            raw_request, raw_response = _fmt_http_pair(baseline)
            probe_request, probe_response = _fmt_http_pair(successes[0])
            return [AgentFinding(
                title="Race Condition — Single-Use Operation Applied Concurrently",
                severity="high",
                cwe="CWE-362",
                attack_type="race_condition",
                evidence=(
                    f"{_BURST_SIZE} identical concurrent {target.method} requests to {target.path} "
                    f"produced {len(successes)} accepted responses for an operation the server "
                    f"should allow once ({len(distinct_successes)} distinct success bodies). "
                    f"Baseline (single request) response: {baseline.status_code}."
                ),
                payload="(concurrent replay of the original request)",
                parameter=", ".join(param_names)[:120],
                url=target.url,
                request_method=target.method,
                bypass_validation=True,  # deterministic double-spend signature
                raw_request=raw_request,
                raw_response=raw_response,
                probe_request=probe_request,
                probe_response=probe_response,
            )]

        # Ambiguous divergence: same request, different business outcomes. Let
        # the LLM decide; without a verdict we stay silent (FP bar).
        variants = sorted({(r.status_code, (r.text or "").strip()[:600]) for r in responses})
        if len(variants) < 2 or not gate:
            return []
        verdict = await _llm_verdict(baseline_text, [v[1] for v in variants], _BURST_SIZE)
        if not verdict or not verdict.get("confirmed"):
            return []
        raw_request, raw_response = _fmt_http_pair(baseline)
        return [AgentFinding(
            title="Race Condition — Divergent Outcomes For Identical Concurrent Requests",
            severity="medium",
            cwe="CWE-362",
            attack_type="race_condition",
            evidence=(
                f"{_BURST_SIZE} identical concurrent {target.method} requests to {target.path} "
                f"returned {len(variants)} distinct business outcomes (statuses: "
                f"{', '.join(str(v[0]) for v in variants)}). LLM verdict: "
                f"{str(verdict.get('reasoning', ''))[:300]}"
            ),
            payload="(concurrent replay of the original request)",
            parameter=", ".join(param_names)[:120],
            url=target.url,
            request_method=target.method,
            bypass_validation=False,  # red-team validator confirms
            raw_request=raw_request,
            raw_response=raw_response,
        )]


from dast.ai.coordinator import Coordinator
Coordinator.register(RaceConditionAgent)

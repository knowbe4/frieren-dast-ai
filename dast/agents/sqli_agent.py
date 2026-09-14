"""
SQLi agent — error-based, boolean-based, and time-based blind SQL injection.

Payloads loaded from sqli.yaml. After each blocked probe the LLM mutator
generates obfuscated variants (comment tricks, URL encoding, hex values, etc.)
targeting the specific WAF or filter observed in the response.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.mutator import build_mutator_context, next_payload
from dast.agents.block_detector import detect_block
from dast.agents.payload_filter import get_filtered_payloads
from dast.payloads.loader import get_payloads, get_signatures, get_value
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_multipart, _inject_query, _send, prepend_import_payloads, response_elapsed_ms
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

# Read timeout for time-based blind probes. A 5s SLEEP stacks on top of ambient
# latency the target is under from concurrent probing (observed >8s on a loaded
# DVWA); the response must be allowed to return so the delay is actually measured
# rather than discarded as a timeout. Kept well above max_sleep (5s) + realistic
# ambient, below the point where a truly hung endpoint would stall the scan.
_TIME_PROBE_TIMEOUT_S = 30.0


def _build_error_re() -> re.Pattern:
    sigs = get_signatures("sqli", "error_signatures")
    if not sigs:
        sigs = ["you have an error in your sql syntax", "ORA-", "SQLiteException"]
    pattern = "|".join(sigs)
    return re.compile(pattern, re.IGNORECASE)


class SqliAgent(VulnAgent):
    name = "SQLi Agent"
    attack_type = "sqli"
    description = (
        "Tests for SQL injection via error-based, boolean-based, and time-based blind probes. "
        "Uses LLM-guided mutations to bypass WAF filters."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        error_re = _build_error_re()
        time_threshold = get_value("sqli", "time_threshold_ms", 4500)

        tech_context: Optional[str] = build_mutator_context(target, "sqli")
        if target.discovery_context:
            summary = target.discovery_context.to_agent_summary()
            if summary:
                ts = target.discovery_context.tech_stack
                if ts and (ts.orm_hints or ts.database_hints):
                    logger.debug(
                        "SQLi agent: tech stack context available",
                        url=target.url,
                        orm=ts.orm_hints,
                        database=ts.database_hints,
                        framework=ts.framework,
                    )

        # Probe each parameter with error-based seeds FIRST (fast, a few requests,
        # the most reliable confirmation) and, if that misses, time-based blind on
        # the SAME parameter before moving on — then RETURN on the first hit anywhere.
        #
        # Interleaving per parameter (rather than sweeping error-based across ALL
        # params before ANY time-based probe) is what makes blind SQLi detectable
        # under load. On a blind endpoint error-based can never hit, so a full
        # error-based sweep of every parameter burns the shared per-endpoint budget
        # before time-based — the ONLY detector for blind injection — ever runs. The
        # injectable parameter is usually first, so giving it its time-based probe
        # after just its own error seeds (not the whole sweep) lets the SLEEP payload
        # land within budget. (Observed on DVWA sqli_blind: the error-based seeds on
        # 'id' then 'Submit' consumed the whole 75s budget and no SLEEP probe ever
        # ran, so a genuinely-injectable endpoint was forfeited to timeout as "safe".)
        #
        # Returning on the first confirmation also avoids grinding a non-injectable
        # parameter's LLM mutator after we already have a finding, which under the
        # coordinator's per-agent-on-return publishing would otherwise delay the
        # return past the budget and forfeit the finding in hand.
        for param in target.params:
            finding = await self._probe_error_based(target, client, param, error_re, tech_context)
            if finding:
                return [finding]
            finding = await self._probe_time_based(target, client, param, time_threshold, tech_context)
            if finding:
                return [finding]

        return findings

    async def _probe_error_based(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        error_re: re.Pattern,
        tech_context: Optional[str] = None,
    ) -> Optional[AgentFinding]:
        seed = get_filtered_payloads("sqli", target) or (
            get_payloads("sqli", "error_based")
        )
        # Remove time-based from error probe — time-based has its own method.
        seed = [p for p in seed if "SLEEP" not in p and "WAITFOR" not in p and "pg_sleep" not in p]
        # Remove boolean tautologies (' OR '1'='1, 1 AND 1=1, ...). They are VALID
        # SQL that returns rows rather than raising an error, so they can never
        # match an error signature — sending them through the error-signature probe
        # is wasted budget that (under load) starves the time-based blind probe of
        # the per-endpoint budget it needs to confirm blind injection. Boolean-based
        # detection would need its own differential-response oracle, which this probe
        # is not; until then these payloads add cost with zero error-based signal.
        boolean_payloads = set(get_payloads("sqli", "boolean_based"))
        seed = [p for p in seed if p not in boolean_payloads]
        payloads_to_try = prepend_import_payloads(list(seed), param["name"], "sqli", target)
        tried: set = set()
        mutation_iteration = 0
        block_seen = False  # did an earlier probe on this param get blocked?

        # Capture a baseline (clean) request/response pair before sending any payload.
        baseline_raw_request = ""
        baseline_raw_response = ""
        try:
            baseline_resp = await self._send_probe(target, client, param, param.get("value", "1"))
            if baseline_resp is not None:
                baseline_raw_request, baseline_raw_response = _fmt_http_pair(baseline_resp)
        except Exception:
            pass

        for iteration, payload in enumerate(payloads_to_try):
            if payload in tried:
                continue
            tried.add(payload)

            resp = await self._send_probe(target, client, param, payload)
            if resp is None:
                continue

            m = error_re.search(resp.text)
            if m:
                # If this payload landed after an earlier block, it is a proven
                # bypass — record it so later endpoints of this host try it first.
                if block_seen:
                    self.observe("waf_bypass", payload=payload, signal="payload succeeded after prior block")
                snippet = resp.text[max(0, m.start() - 30):m.end() + 60].strip()
                probe_request, probe_response = _fmt_http_pair(resp)
                return AgentFinding(
                    title="SQL Injection (Error-Based)",
                    severity="critical",
                    cwe="CWE-89",
                    attack_type="sqli",
                    evidence=f"SQL error in response: {snippet!r}",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_response_snippet=snippet,
                    raw_request=baseline_raw_request,
                    raw_response=baseline_raw_response,
                    probe_request=probe_request,
                    probe_response=probe_response,
                )

            # Record WAF/filter signal on EVERY seed response (not just the last),
            # so a block on any seed is seen. The central detector catches block
            # pages even on HTTP 200, so a WAF that hides behind a 200 still
            # surfaces as a bypass opportunity for the mutator.
            verdict = detect_block(resp.status_code, resp.text)
            if verdict.is_block and not block_seen:
                block_seen = True
                self.observe("waf_block", payload=payload, signal=verdict.signal)
            if verdict.is_rate_limit:
                self.observe("rate_limit", signal="429 Too Many Requests")

            if iteration < len(seed) - 1:
                continue

            # The LLM mutator is a WAF-BYPASS tool: it only helps when a defence
            # actually blocked a payload. If no block was observed, obfuscating a
            # payload that produced no SQL error will not produce one either —
            # mutating here just burns the per-endpoint budget and starves the
            # time-based blind probe that runs next (observed on DVWA sqli_blind:
            # the error-based mutator grind on 'id' consumed the whole budget and
            # the SLEEP probes that detect blind injection never ran, so the
            # endpoint was forfeited to timeout despite being injectable). So only
            # mutate after a block; otherwise stop and let time-based blind run.
            if not block_seen:
                break

            mutation = await next_payload(
                attack_type="sqli",
                original_payload=payload,
                parameter=param["name"],
                response_status=resp.status_code,
                response_snippet=resp.text[:600],
                iteration=mutation_iteration,
                tried_payloads=list(tried),
                tech_context=tech_context,
            )
            mutation_iteration += 1
            if mutation is None:
                break
            logger.debug(
                "SQLi mutator", param=param["name"], action=mutation.action,
                rationale=mutation.rationale,
            )
            payloads_to_try.append(mutation.payload)

        return None

    async def _probe_time_based(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        threshold_ms: float,
        tech_context: Optional[str] = None,
    ) -> Optional[AgentFinding]:
        seed = get_payloads("sqli", "time_based")  # always use full time-based group here
        payloads_to_try = prepend_import_payloads(list(seed), param["name"], "sqli", target)
        tried: set = set()
        mutation_iteration = 0
        clean_value = param.get("value", "1")

        for iteration, payload in enumerate(payloads_to_try):
            if payload in tried:
                continue
            tried.add(payload)

            # Time-based blind detection compares the SLEEP probe against a control
            # request measured IMMEDIATELY BEFORE it — not against a single baseline
            # sampled once at the start. Under the concurrent multi-agent load on a
            # single endpoint (many agents probing through the same proxy), a plain
            # localhost request can take several seconds, and that ambient latency
            # drifts burst to burst. A stale start-baseline of ~5.7s made the
            # required delay ~10.2s, so a safety-capped 5s SLEEP (which DID execute)
            # never cleared the bar and a real blind injection was missed. An
            # adjacent control shares the same ambient load as its probe, so the
            # delta isolates the injected sleep regardless of absolute contention —
            # no cross-agent lock needed. (A previous global time-probe lock made the
            # measurement quiet but serialized every SLEEP on every endpoint through
            # one gate, starving the concurrent CMDI time-based probe on a sibling
            # endpoint until the coordinator budget expired.)
            control_ms, _ = await self._timed_send(target, client, param, clean_value)
            probe_ms, resp = await self._timed_send(target, client, param, payload)

            delta_ms = probe_ms - control_ms
            # A real SLEEP also has to show up in ABSOLUTE terms (the probe itself
            # must be at least ~sleep-duration long) so a control that happened to
            # be anomalously fast cannot manufacture a large delta from noise.
            candidate = (
                resp is not None
                and delta_ms >= threshold_ms
                and probe_ms >= threshold_ms
            )
            logger.debug(
                "SQLi time-based probe",
                param=param["name"],
                payload=payload,
                control_ms=round(control_ms),
                probe_ms=round(probe_ms),
                delta_ms=round(delta_ms),
                threshold_ms=threshold_ms,
                resp=None if resp is None else resp.status_code,
                candidate=candidate,
            )

            if candidate:
                # Re-confirm with a second control/probe pair: ambient load spikes
                # are transient and rarely reproduce, but an injected SLEEP does
                # every time. Only confirm when the delay holds on the re-test.
                control2_ms, _ = await self._timed_send(target, client, param, clean_value)
                probe2_ms, resp2 = await self._timed_send(target, client, param, payload)
                delta2_ms = probe2_ms - control2_ms
                confirmed = (
                    resp2 is not None
                    and delta2_ms >= threshold_ms
                    and probe2_ms >= threshold_ms
                )
                logger.debug(
                    "SQLi time-based re-confirm",
                    param=param["name"], payload=payload,
                    control_ms=round(control2_ms), probe_ms=round(probe2_ms),
                    delta_ms=round(delta2_ms), confirmed=confirmed,
                )
                if confirmed:
                    confirm_resp = resp2 if resp2 is not None else resp
                    probe_request, probe_response = _fmt_http_pair(confirm_resp)
                    return AgentFinding(
                        title="SQL Injection (Time-Based Blind)",
                        severity="critical",
                        cwe="CWE-89",
                        attack_type="sqli",
                        evidence=(
                            f"Response to '{param['name']}' delayed {delta_ms:.0f}ms then "
                            f"{delta2_ms:.0f}ms over an adjacent control with a 5s SLEEP payload "
                            f"(control ~{control_ms:.0f}/{control2_ms:.0f}ms) — the delay reproduced, "
                            f"confirming server-side execution independent of ambient load"
                        ),
                        payload=payload,
                        parameter=param["name"],
                        url=target.url,
                        request_method=target.method,
                        bypass_validation=True,
                        probe_request=probe_request,
                        probe_response=probe_response,
                    )

            if resp is not None and iteration >= len(seed) - 1:
                # Only drive the (very expensive: ~5s/probe) time-based mutator
                # when a WAF actually blocked the standard SLEEP seeds. With no
                # block, an obfuscated SLEEP is no more likely to land than the
                # plain one, and each mutated probe costs another full delay —
                # grinding here forfeits the endpoint to the per-endpoint budget.
                verdict = detect_block(resp.status_code, resp.text)
                if not verdict.is_block:
                    break
                mutation = await next_payload(
                    attack_type="sqli",
                    original_payload=payload,
                    parameter=param["name"],
                    response_status=resp.status_code,
                    response_snippet=resp.text[:400] if resp else "",
                    iteration=mutation_iteration,
                    tried_payloads=list(tried),
                    tech_context=tech_context,
                )
                mutation_iteration += 1
                if mutation is None:
                    break
                payloads_to_try.append(mutation.payload)

        return None

    async def _timed_send(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
    ):
        """Send one probe and return (server_elapsed_ms, response). Uses httpx's
        `.elapsed` (server round-trip only) rather than wall-clock, so time spent
        waiting to acquire the shared probe semaphore under concurrent load does not
        pollute the measurement — see active_checks.response_elapsed_ms.

        Time-based probes get a generous per-request read timeout: the injected
        SLEEP delay stacks on top of whatever ambient latency the target is under
        from concurrent probing, and if the response exceeds the default client
        timeout it is discarded (resp=None) and the delay we were measuring is never
        observed. The paired-adjacent-control delta cancels the ambient component,
        but only when the probe actually returns."""
        resp = await self._send_probe(
            target, client, param, payload, timeout=_TIME_PROBE_TIMEOUT_S
        )
        return response_elapsed_ms(resp), resp

    async def _send_probe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
        timeout: "Optional[float]" = None,
    ):
        if param["location"] == "query":
            url = _inject_query(target.url, param["name"], payload)
            return await _send(client, target.method, url, target.headers, target.body, timeout=timeout)
        elif param["location"] in ("body", "body_graphql"):
            body = _inject_body(
                target.body or "", param["name"], payload,
                target.headers.get("content-type", ""),
                location=param["location"],
            )
            return await _send(client, target.method, target.url, target.headers, body, timeout=timeout)
        elif param["location"].startswith("multipart_"):
            raw = _inject_multipart(target.raw_body or b"", param["name"], payload)
            return await _send(client, target.method, target.url, target.headers, raw, timeout=timeout)
        return None


from dast.ai.coordinator import Coordinator
Coordinator.register(SqliAgent)

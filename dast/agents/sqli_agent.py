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
from dast.agents.sqli_exploit import ExploitProof, extract_db_facts
from dast.payloads.loader import get_payloads, get_signatures, get_value
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_multipart, _inject_path, _inject_query, _send, prepend_import_payloads, response_elapsed_ms, scaled_delay_variant, serialize_time_probe, zero_delay_variant
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

# Cap on how many standard time-based payloads (escape/dialect variants) are
# measured per parameter before giving up when no block was seen. Each variant
# costs a control + a full ~5s SLEEP probe (and a confirm pair on a hit), so under
# the per-endpoint budget and the serialized time-probe lock, sampling the whole
# seed list would time out before the injectable escape is reached. The seed list
# is ordered so these first few cover the common escape contexts (quote / numeric /
# bare); an un-blocked endpoint that did not delay for any of them is not
# time-injectable. A WAF block still escalates to the mutator regardless.
_MAX_TIME_PAYLOADS = 4

# sqlmap-style delay-scaling confirmation. A candidate found with the primary ~5s
# SLEEP is confirmed by re-probing with a distinct shorter sleep: a real injection's
# measured delay tracks the requested one, ambient jitter does not. The shorter
# probe must clearly delay (>= _CONFIRM_DELAY_S * _CONFIRM_FLOOR_RATIO) AND the
# primary probe must add at least _SCALING_MARGIN_MS more delay than it — proving
# the delay scales with the requested value rather than being a slow-response fluke.
_CONFIRM_DELAY_S = 2
_CONFIRM_FLOOR_RATIO = 600.0   # ms of measured delay required per requested second
_SCALING_MARGIN_MS = 1500.0    # min extra delay the primary sleep adds over the confirm


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
        except Exception as exc:
            logger.debug("failed to capture SQLi baseline request/response", error=str(exc))

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
                finding = AgentFinding(
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
                return await self._prove_impact(target, client, param, finding, payload)

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

            # Stage 1 (candidate): compare the SLEEP probe against a FALSE control
            # sent immediately before it — the same payload with the sleep zeroed
            # (SLEEP(0), sqlmap's true/false differential). Identical query-parsing
            # path and same ambient-load epoch, so the delta isolates the server-side
            # sleep. The adaptive per-host limiter keeps a saturated single-worker
            # target near-serial, so these requests stay fast and the delta clean (an
            # un-throttled target inflates every round-trip to 10-20s and buries the
            # signal). Falls back to the clean value when the payload has no
            # recognizable sleep construct (e.g. the SQLite heavy-query form).
            control_value = zero_delay_variant(payload) or clean_value
            finding = None
            # Hold the global time-probe lock across BOTH the candidate measurement
            # AND the confirmation. Releasing between them lets the confirm re-queue
            # behind other endpoints' time-probe loops on this globally-contended
            # lock; under the per-endpoint deadline it then starves and the agent
            # task is cancelled mid-confirm, silently dropping a strong candidate
            # (observed: a clean 5157ms 'id' candidate lost because its confirm
            # waited ~60s on the lock and never sent a request). The confirm adds
            # only a control + one shorter SLEEP, and only when a candidate is
            # found, so the extra hold is bounded and rare.
            async with serialize_time_probe():
                control_ms, _ = await self._timed_send(target, client, param, control_value)
                probe_ms, resp = await self._timed_send(target, client, param, payload)

                delta_ms = probe_ms - control_ms
                # The delay must show up both as a delta over the control AND in
                # absolute terms (the probe itself must be at least a sleep-duration
                # long), so an anomalously slow control cannot hide a real sleep nor
                # a fast one manufacture a delta from noise.
                candidate = (
                    resp is not None
                    and delta_ms >= threshold_ms
                    and probe_ms >= threshold_ms
                )
                logger.debug(
                    "SQLi time-based probe",
                    param=param["name"],
                    payload=payload,
                    control_value=control_value,
                    control_ms=round(control_ms),
                    probe_ms=round(probe_ms),
                    delta_ms=round(delta_ms),
                    threshold_ms=threshold_ms,
                    resp=None if resp is None else resp.status_code,
                    candidate=candidate,
                )

                if candidate:
                    finding = await self._confirm_time_scaling(
                        target, client, param, payload, control_value,
                        delta_ms, resp, threshold_ms,
                    )

            # Turn a confirmed time-based injection into proof: attempt safe,
            # read-only DBMS metadata extraction. Detection is unchanged — this
            # only enriches an already-confirmed finding and never alters the
            # verdict (a failed/blocked extraction leaves the finding intact).
            if finding is not None:
                return await self._prove_impact(target, client, param, finding, payload)

            if resp is not None and iteration >= min(len(seed), _MAX_TIME_PAYLOADS) - 1:
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

    async def _confirm_time_scaling(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
        control_value: str,
        primary_delta_ms: float,
        primary_resp: "Optional[httpx.Response]",
        threshold_ms: float,
    ) -> Optional[AgentFinding]:
        """Confirm a time-based candidate by delay scaling (sqlmap's method): a real
        injection's measured delay tracks the requested sleep. Re-probe with a
        distinct, shorter sleep and require (a) the shorter sleep to clearly delay the
        response and (b) the original (longer) sleep to add measurably MORE delay than
        it. Ambient spikes are uncorrelated with the requested delay, so they cannot
        satisfy the scaling relation — only an attacker-controlled sleep does.

        When the payload has no rewritable sleep construct (e.g. the SQLite
        heavy-query form), scaling is impossible, so fall back to reproducing the same
        delay over the zero-delay control.

        The caller invokes this while already holding the global time-probe lock
        (serialize_time_probe), so the confirmation runs atomically after the
        candidate measurement and cannot starve re-acquiring that contended lock
        under the per-endpoint deadline. Do NOT take the lock again here."""
        confirm_payload = scaled_delay_variant(payload, _CONFIRM_DELAY_S)

        if confirm_payload is None:
            control_ms, _ = await self._timed_send(target, client, param, control_value)
            probe_ms, resp = await self._timed_send(target, client, param, payload)
            reproduce_delta_ms = probe_ms - control_ms
            confirmed = (
                resp is not None
                and reproduce_delta_ms >= threshold_ms
                and probe_ms >= threshold_ms
            )
            logger.debug(
                "SQLi time-based re-confirm (reproduce)",
                param=param["name"], payload=payload,
                control_ms=round(control_ms), probe_ms=round(probe_ms),
                delta_ms=round(reproduce_delta_ms), confirmed=confirmed,
            )
            confirm_resp = resp if resp is not None else primary_resp
            evidence_tail = (
                f"the delay reproduced ({primary_delta_ms:.0f}ms then "
                f"{reproduce_delta_ms:.0f}ms), confirming server-side execution "
                f"independent of ambient load"
            )
            if not confirmed:
                return None
            return self._time_based_finding(
                target, param, payload, control_value, evidence_tail, confirm_resp
            )

        # Delay-scaling confirmation (caller holds the time-probe lock).
        control_ms, _ = await self._timed_send(target, client, param, control_value)
        confirm_ms, resp = await self._timed_send(target, client, param, confirm_payload)
        confirm_delta_ms = confirm_ms - control_ms
        confirm_floor_ms = _CONFIRM_DELAY_S * _CONFIRM_FLOOR_RATIO
        scaled = (
            resp is not None
            and confirm_delta_ms >= confirm_floor_ms          # shorter sleep clearly delayed
            and confirm_ms >= confirm_floor_ms
            and (primary_delta_ms - confirm_delta_ms) >= _SCALING_MARGIN_MS  # longer sleep added more
        )
        logger.debug(
            "SQLi time-based re-confirm (scaling)",
            param=param["name"], payload=payload, confirm_payload=confirm_payload,
            confirm_delay_s=_CONFIRM_DELAY_S, control_ms=round(control_ms),
            confirm_ms=round(confirm_ms), confirm_delta_ms=round(confirm_delta_ms),
            primary_delta_ms=round(primary_delta_ms), confirmed=scaled,
        )
        if not scaled:
            return None
        evidence_tail = (
            f"the delay scaled with the requested sleep — {primary_delta_ms:.0f}ms for a "
            f"5s SLEEP versus {confirm_delta_ms:.0f}ms for a {_CONFIRM_DELAY_S}s SLEEP over a "
            f"matched zero-delay control — proving the delay is attacker-controlled, not "
            f"ambient load"
        )
        return self._time_based_finding(
            target, param, payload, control_value, evidence_tail, resp
        )

    def _time_based_finding(
        self,
        target: "CheckTarget",
        param: dict,
        payload: str,
        control_value: str,
        evidence_tail: str,
        confirm_resp: "Optional[httpx.Response]",
    ) -> AgentFinding:
        probe_request, probe_response = _fmt_http_pair(confirm_resp)
        return AgentFinding(
            title="SQL Injection (Time-Based Blind)",
            severity="critical",
            cwe="CWE-89",
            attack_type="sqli",
            evidence=(
                f"Response to '{param['name']}' with a SLEEP payload delayed over a "
                f"matched zero-delay control ('{control_value}'): {evidence_tail}."
            ),
            payload=payload,
            parameter=param["name"],
            url=target.url,
            request_method=target.method,
            bypass_validation=True,
            probe_request=probe_request,
            probe_response=probe_response,
        )

    async def _prove_impact(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        finding: AgentFinding,
        confirmed_payload: str,
    ) -> AgentFinding:
        """Attempt safe read-only data extraction to turn detection into proof.

        On success, enrich the finding with the extracted DBMS metadata and use
        the extraction request/response as the exploit-proof pair (stronger
        evidence than the bare detection probe). Never raises — a failed or
        blocked extraction leaves the confirmed finding untouched.
        """
        dbms_hints: Optional[list] = None
        if target.discovery_context and target.discovery_context.tech_stack:
            hints = target.discovery_context.tech_stack.database_hints
            dbms_hints = list(hints) if hints else None

        async def _send(payload: str):
            return await self._send_probe(target, client, param, payload)

        try:
            proof: Optional[ExploitProof] = await extract_db_facts(
                _send, confirmed_payload, dbms_hints
            )
        except Exception as exc:
            logger.debug(
                "SQLi exploitation failed", url=target.url,
                parameter=param["name"], error=str(exc),
            )
            return finding

        if proof is None:
            return finding

        finding.extracted_data = dict(proof.facts)
        finding.evidence = f"{finding.evidence} | {proof.summary()}"
        # The extraction pair proves data exfiltration, not just an error — use
        # it as the exploit-proof shown in the dashboard.
        if proof.request:
            finding.probe_request = proof.request
        if proof.response:
            finding.probe_response = proof.response
        return finding

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
        elif param["location"] == "path":
            url = _inject_path(target.url, param.get("path_index", 0), payload)
            return await _send(client, target.method, url, target.headers, target.body, timeout=timeout)
        return None


from dast.ai.coordinator import Coordinator
Coordinator.register(SqliAgent)

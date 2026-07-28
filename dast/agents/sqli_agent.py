"""
SQLi agent — error-based, boolean-based, and time-based blind SQL injection.

Payloads loaded from sqli.yaml. After each blocked probe the LLM mutator
generates obfuscated variants (comment tricks, URL encoding, hex values, etc.)
targeting the specific WAF or filter observed in the response.
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.mutator import build_mutator_context, next_payload
from dast.agents.block_detector import detect_block
from dast.agents.payload_filter import get_filtered_payloads
from dast.payloads.loader import get_payloads, get_signatures, get_value
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_multipart, _inject_query, _send, prepend_import_payloads
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)


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

        for param in target.params:
            # Error-based first — fastest confirmation
            finding = await self._probe_error_based(target, client, param, error_re, tech_context)
            if finding:
                findings.append(finding)
                continue  # skip time-based if error-based already confirmed

            # Time-based blind — runs only when error-based found nothing
            finding = await self._probe_time_based(target, client, param, time_threshold, tech_context)
            if finding:
                findings.append(finding)

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
            get_payloads("sqli", "error_based") + get_payloads("sqli", "boolean_based")
        )
        # Remove time-based from error probe — time-based has its own method
        seed = [p for p in seed if "SLEEP" not in p and "WAITFOR" not in p and "pg_sleep" not in p]
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

            if iteration < len(seed) - 1:
                continue

            # Record WAF/filter signal before calling the mutator. The central
            # detector catches block pages even on HTTP 200, so a WAF that hides
            # behind a 200 still surfaces as a bypass opportunity for the mutator.
            verdict = detect_block(resp.status_code, resp.text)
            if verdict.is_block:
                block_seen = True
                self.observe("waf_block", payload=payload, signal=verdict.signal)
            if verdict.is_rate_limit:
                self.observe("rate_limit", signal="429 Too Many Requests")

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

        # Send one baseline request to measure normal response time and capture
        # the clean request/response pair as evidence. The probe must be at least
        # threshold_ms SLOWER than baseline — not just exceed threshold_ms absolute —
        # otherwise a naturally slow endpoint (e.g. 3 s) triggers on a 5 s SLEEP payload.
        baseline_raw_request = ""
        baseline_raw_response = ""
        baseline_elapsed_ms = 0.0
        try:
            t_base0 = time.monotonic()
            baseline_resp = await self._send_probe(target, client, param, param.get("value", "1"))
            baseline_elapsed_ms = (time.monotonic() - t_base0) * 1000
            if baseline_resp is not None:
                baseline_raw_request, baseline_raw_response = _fmt_http_pair(baseline_resp)
        except Exception:
            pass

        for iteration, payload in enumerate(payloads_to_try):
            if payload in tried:
                continue
            tried.add(payload)

            t0 = time.monotonic()
            resp = await self._send_probe(target, client, param, payload)
            elapsed_ms = (time.monotonic() - t0) * 1000

            if resp is not None and elapsed_ms >= (baseline_elapsed_ms + threshold_ms):
                probe_request, probe_response = _fmt_http_pair(resp)
                return AgentFinding(
                    title="SQL Injection (Time-Based Blind)",
                    severity="critical",
                    cwe="CWE-89",
                    attack_type="sqli",
                    evidence=f"Response delayed {elapsed_ms:.0f}ms with 5s SLEEP in '{param['name']}'",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_request=baseline_raw_request,
                    raw_response=baseline_raw_response,
                    probe_request=probe_request,
                    probe_response=probe_response,
                )

            if resp is not None and iteration >= len(seed) - 1:
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

    async def _send_probe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
    ):
        if param["location"] == "query":
            url = _inject_query(target.url, param["name"], payload)
            return await _send(client, target.method, url, target.headers, target.body)
        elif param["location"] in ("body", "body_graphql"):
            body = _inject_body(
                target.body or "", param["name"], payload,
                target.headers.get("content-type", ""),
                location=param["location"],
            )
            return await _send(client, target.method, target.url, target.headers, body)
        elif param["location"].startswith("multipart_"):
            raw = _inject_multipart(target.raw_body or b"", param["name"], payload)
            return await _send(client, target.method, target.url, target.headers, raw)
        return None


from dast.ai.coordinator import Coordinator
Coordinator.register(SqliAgent)

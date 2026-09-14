"""
Command injection agent — tests for OS command injection via multiple vectors.

Strategy:
  1. Inline output: inject `id` / `whoami` and look for uid=/username in response
  2. Time-based blind: inject `sleep 4` / `ping -c 4` and measure response delay
  3. Error-based: inject shell metacharacters and detect shell error patterns
  4. WAF bypass: encoding, whitespace variants, alternative separators

Safety: max 5s delay, detection only (id/whoami), no destructive commands.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.payloads.loader import get_payloads
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_query, _send, response_elapsed_ms, scaled_delay_variant, serialize_time_probe, zero_delay_variant
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_CMDI_OUTPUT_RE = re.compile(
    r"uid=\d+\(\w+\)|gid=\d+|root:.*:0:0:|"
    r"\\\\[a-zA-Z].*\\\\(Users|Windows)|"
    r"(nobody|www-data|apache|nginx|daemon):\w",
    re.I,
)

_WHOAMI_RE = re.compile(
    r"\b(root|www-data|apache|nginx|nobody|daemon|Administrator|SYSTEM)\b",
)

_SHELL_ERROR_RE = re.compile(
    r"(sh: \d+:|/bin/sh:|bash:.*command not found|"
    r"'.*' is not recognized as an internal|"
    r"The system cannot find|"
    r"Cannot run program|"
    r"java\.io\.IOException.*Process|"
    r"os\.popen|subprocess\.Popen|"
    r"Runtime\.getRuntime\(\)\.exec)",
    re.I,
)

# Time-based blind threshold — server must respond >3s slower than baseline
_TIME_THRESHOLD_S = 3.0
_SLEEP_DURATION = 4
# Read timeout for time-based blind probes: the injected sleep stacks on ambient
# latency under concurrent load, so the response must be allowed to return rather
# than be discarded as a timeout (see sqli_agent._TIME_PROBE_TIMEOUT_S).
_TIME_PROBE_TIMEOUT_S = 30.0
# sqlmap-style delay-scaling confirmation: re-probe with a distinct shorter sleep
# and require the measured delay to track the requested one. A real injection scales
# linearly; ambient jitter does not. The shorter probe must clearly delay AND the
# primary probe must add at least _SCALING_MARGIN_S more delay than it.
_CONFIRM_SLEEP_DURATION = 2
_CONFIRM_FLOOR_S = 1.2
_SCALING_MARGIN_S = 1.0


class CmdiAgent(VulnAgent):
    name = "Command Injection Agent"
    attack_type = "cmdi"
    description = "Tests for OS command injection via output reflection, time-based blind, and error disclosure"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        params = [p for p in target.params if p.get("type") not in ("token", "boolean")]
        if not params:
            logger.debug("cmdi: no injectable params", url=target.url)
            return []

        logger.info("cmdi: testing %d param(s) on %s", len(params), target.url)

        # Baseline response captured for content diffing in the output phases. The
        # time-based phase does NOT rely on this single baseline for timing — it
        # pairs each SLEEP probe with an adjacent control instead (see
        # _probe_time_based), which is robust to ambient-load drift.
        baseline = await _send(client, target.method, target.url, target.headers, target.body)
        if not baseline:
            return []
        baseline_body = baseline.text[:4000]

        unix_basic = get_payloads("cmdi", "unix_basic") or [";id", "|id", "$(id)", "`id`"]
        unix_blind = get_payloads("cmdi", "unix_blind_time") or [
            f";sleep {_SLEEP_DURATION}", f"|sleep {_SLEEP_DURATION}",
            f"$(sleep {_SLEEP_DURATION})", f"`sleep {_SLEEP_DURATION}`",
        ]
        bypass_payloads = get_payloads("cmdi", "bypass") or []

        probe_params = params[:5]

        # Run the FAST content-based phases (output reflection + WAF-bypass output,
        # both a handful of quick requests) across EVERY param before the expensive
        # time-based blind phase (4 x ~5s sleeps per param). The injectable param is
        # not necessarily first — with header/cookie entrypoints expanded into the
        # param list, a real one (e.g. DVWA `ip`) can sit behind several
        # non-injectable ones. If each of those ran its 20s sleep sweep first, the
        # shared per-endpoint budget would be exhausted before the injectable
        # param's instant `;id` output check ever ran, forfeiting a confirmable
        # command injection to timeout (observed on DVWA /exec/: budget spent on
        # blind sleeps, kept_findings=0). Doing all the cheap output checks first
        # confirms output-reflected CMDi regardless of param ordering; time-based
        # blind is the last resort only when nothing reflected.
        for param in probe_params:
            if not param.get("name"):
                continue
            finding = await self._probe_output(
                target, client, param, unix_basic[:8], baseline_body
            )
            if finding:
                return [finding]

        for param in probe_params:
            if not param.get("name"):
                continue
            finding = await self._probe_bypass_output(
                target, client, param, bypass_payloads[:12], baseline_body
            )
            if finding:
                return [finding]

        for param in probe_params:
            if not param.get("name"):
                continue
            finding = await self._probe_time_based(
                target, client, param, unix_blind[:4]
            )
            if finding:
                return [finding]

        return findings

    async def _probe_output(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payloads: List[str],
        baseline_body: str,
    ) -> Optional[AgentFinding]:
        """Phase 1: inject `id`/`whoami` variants and look for command output or a
        shell-error disclosure directly in the response (no delay involved)."""
        param_name = param["name"]
        for payload in payloads:
            payload = str(payload)
            resp = await self._send_probe(target, client, param, payload)
            if not resp:
                continue
            body = resp.text[:4000]

            # Skip if payload is just echoed back
            if payload in body and not _CMDI_OUTPUT_RE.search(body):
                continue

            if _CMDI_OUTPUT_RE.search(body):
                # Verify it's not in the baseline
                if _CMDI_OUTPUT_RE.search(baseline_body):
                    continue
                raw_req, raw_resp = _fmt_http_pair(resp)
                log_event("agent", "finding",
                          f"CMDi output confirmed: {param_name} on {target.url}",
                          url=target.url, finding="Command Injection", source="agent")
                return AgentFinding(
                    title="OS Command Injection — Output Reflected",
                    severity="critical",
                    cwe="CWE-78",
                    attack_type="cmdi",
                    evidence=(
                        f"Parameter '{param_name}' with payload '{payload}' returned "
                        f"command output in response: '{_CMDI_OUTPUT_RE.search(body).group(0)}'\n\n"
                        f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                    ),
                    confirmed=True,
                    payload=payload,
                    parameter=param_name,
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_request=raw_req,
                    raw_response=raw_resp[:2000],
                )

            # Shell error pattern
            if _SHELL_ERROR_RE.search(body) and not _SHELL_ERROR_RE.search(baseline_body):
                raw_req, raw_resp = _fmt_http_pair(resp)
                return AgentFinding(
                    title="OS Command Injection — Shell Error Disclosure",
                    severity="high",
                    cwe="CWE-78",
                    attack_type="cmdi",
                    evidence=(
                        f"Parameter '{param_name}' with payload '{payload}' triggered "
                        f"a shell error: '{_SHELL_ERROR_RE.search(body).group(0)}'. "
                        f"This confirms the parameter is passed to a shell command.\n\n"
                        f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                    ),
                    confirmed=True,
                    payload=payload,
                    parameter=param_name,
                    url=target.url,
                    request_method=target.method,
                    raw_request=raw_req,
                    raw_response=raw_resp[:2000],
                )
        return None

    async def _probe_bypass_output(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payloads: List[str],
        baseline_body: str,
    ) -> Optional[AgentFinding]:
        """Phase 3: encoding / whitespace (IFS) / alternative-separator variants
        that still execute `id`, detected via the same output signature. Runs after
        the direct output probes so it only matters when a naive payload was filtered."""
        param_name = param["name"]
        for payload in payloads:
            payload = str(payload)
            resp = await self._send_probe(target, client, param, payload)
            if not resp:
                continue
            body = resp.text[:4000]

            # Skip if payload is just echoed back without executing
            if payload in body and not _CMDI_OUTPUT_RE.search(body):
                continue

            if _CMDI_OUTPUT_RE.search(body) and not _CMDI_OUTPUT_RE.search(baseline_body):
                raw_req, raw_resp = _fmt_http_pair(resp)
                log_event("agent", "finding",
                          f"CMDi WAF bypass confirmed: {param_name} on {target.url}",
                          url=target.url, finding="Command Injection", source="agent")
                return AgentFinding(
                    title="OS Command Injection — WAF Bypass",
                    severity="critical",
                    cwe="CWE-78",
                    attack_type="cmdi",
                    evidence=(
                        f"Parameter '{param_name}' with bypass payload '{payload}' returned "
                        f"command output after direct payloads were filtered: "
                        f"'{_CMDI_OUTPUT_RE.search(body).group(0)}'\n\n"
                        f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                    ),
                    confirmed=True,
                    payload=payload,
                    parameter=param_name,
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_request=raw_req,
                    raw_response=raw_resp[:2000],
                )
        return None

    async def _timed_send(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        value: str,
    ) -> tuple[float, Optional["httpx.Response"]]:
        """Inject `value` into `param` and return (server_elapsed_s, response).

        Uses httpx's `.elapsed` (server round-trip only) rather than wall-clock, so
        time waiting to acquire the shared probe semaphore under concurrent load
        does not pollute timing — see active_checks.response_elapsed_ms."""
        resp = await self._send_probe(target, client, param, value, timeout=_TIME_PROBE_TIMEOUT_S)
        return response_elapsed_ms(resp) / 1000.0, resp

    async def _send_probe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
        timeout: "Optional[float]" = None,
    ) -> Optional["httpx.Response"]:
        """Inject `payload` into `param` at its recorded location and send. Body
        params (e.g. DVWA /exec/ `ip`, submitted as form fields) MUST be injected
        into the body, not the query string — the server reads them from the body, so
        query injection silently misses the vulnerable code path. Falls back to query
        injection for locations without a dedicated injector (header/cookie), which
        preserves prior behavior for those entrypoints."""
        location = param.get("location", "query")
        if location in ("body", "body_graphql"):
            body = _inject_body(
                target.body or "", param["name"], payload,
                target.headers.get("content-type", ""),
                location=location,
            )
            return await _send(
                client, target.method, target.url, target.headers, body,
                payload=payload, timeout=timeout,
            )
        url = _inject_query(target.url, param["name"], payload)
        return await _send(
            client, target.method, url, target.headers, target.body,
            payload=payload, timeout=timeout,
        )

    async def _probe_time_based(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payloads: List[str],
    ) -> Optional[AgentFinding]:
        """Phase 2: time-based blind — inject `sleep N` variants and confirm the
        response is >threshold slower than an ADJACENT control. The expensive phase
        (each probe costs a full ~5s delay), so it runs last, only when nothing
        reflected.

        Each sleep probe is compared against a FALSE control sent immediately
        before it: the same payload with the sleep duration zeroed (sqlmap's
        true/false differential). Both take the identical injection path and share
        the same ambient-load epoch, so the delta isolates the server-side sleep.
        Both the candidate pair AND the confirmation are taken under a SINGLE hold of
        the global time-probe lock so no other agent's SLEEP is in flight (a
        concurrent sleep pins a target worker and inflated round-trips to >10s,
        starving the budget) — and, critically, so the confirm cannot re-queue behind
        other endpoints' time-probe loops on this contended lock and starve until the
        per-endpoint deadline cancels the agent mid-confirm. The confirmation
        re-probes with a distinct shorter sleep and requires the measured delay to
        track the requested one (delay scaling, sqlmap's method): load spikes are
        transient and uncorrelated with the requested sleep, an injected sleep scales
        every time."""
        param_name = param["name"]
        for payload in payloads:
            payload = str(payload)
            control_value = zero_delay_variant(payload) or "1"

            confirmed = False
            confirm_payload: Optional[str] = None
            resp = resp2 = None
            delta_s = confirm_delta_s = 0.0
            evidence_tail = ""
            async with serialize_time_probe():
                control_s, _ = await self._timed_send(target, client, param, control_value)
                probe_s, resp = await self._timed_send(target, client, param, payload)
                delta_s = probe_s - control_s
                candidate = (
                    resp is not None
                    and delta_s >= _TIME_THRESHOLD_S
                    and probe_s >= _TIME_THRESHOLD_S
                )
                logger.debug(
                    "cmdi time-based probe", param=param_name, payload=payload,
                    control_value=control_value,
                    control_s=round(control_s, 2), probe_s=round(probe_s, 2),
                    delta_s=round(delta_s, 2), candidate=candidate,
                )

                if candidate:
                    # Confirm by delay scaling (sqlmap's method): re-probe with a
                    # distinct shorter sleep and require the measured delay to track
                    # the requested one. Falls back to reproducing the same delay when
                    # the payload has no rewritable sleep construct. Still under the
                    # lock held above.
                    confirm_payload = scaled_delay_variant(payload, _CONFIRM_SLEEP_DURATION)
                    if confirm_payload is None:
                        control2_s, _ = await self._timed_send(target, client, param, control_value)
                        confirm_s, resp2 = await self._timed_send(target, client, param, payload)
                        confirm_delta_s = confirm_s - control2_s
                        confirmed = (
                            resp2 is not None
                            and confirm_delta_s >= _TIME_THRESHOLD_S
                            and confirm_s >= _TIME_THRESHOLD_S
                        )
                        evidence_tail = (
                            f"delayed the response {delta_s:.1f}s then {confirm_delta_s:.1f}s "
                            f"(reproduced) over a matched zero-delay control ('{control_value}')"
                        )
                    else:
                        control2_s, _ = await self._timed_send(target, client, param, control_value)
                        confirm_s, resp2 = await self._timed_send(target, client, param, confirm_payload)
                        confirm_delta_s = confirm_s - control2_s
                        confirmed = (
                            resp2 is not None
                            and confirm_delta_s >= _CONFIRM_FLOOR_S
                            and confirm_s >= _CONFIRM_FLOOR_S
                            and (delta_s - confirm_delta_s) >= _SCALING_MARGIN_S
                        )
                        evidence_tail = (
                            f"delayed the response {delta_s:.1f}s for a {_SLEEP_DURATION}s sleep versus "
                            f"{confirm_delta_s:.1f}s for a {_CONFIRM_SLEEP_DURATION}s sleep over a matched "
                            f"zero-delay control ('{control_value}') — the delay scales with the requested "
                            f"sleep, proving it is attacker-controlled"
                        )
                    logger.debug(
                        "cmdi time-based re-confirm", param=param_name, payload=payload,
                        confirm_payload=confirm_payload, control_s=round(control2_s, 2),
                        confirm_s=round(confirm_s, 2), confirm_delta_s=round(confirm_delta_s, 2),
                        delta_s=round(delta_s, 2), confirmed=confirmed,
                    )

            if not confirmed:
                continue

            confirm_resp = resp2 if resp2 is not None else resp
            raw_req, raw_resp = _fmt_http_pair(confirm_resp)
            log_event("agent", "finding",
                      f"CMDi blind: {param_name} delayed {delta_s:.1f}s on {target.url}",
                      url=target.url, finding="Blind CMDi", source="agent")
            return AgentFinding(
                title="OS Command Injection — Time-Based Blind",
                severity="critical",
                cwe="CWE-78",
                attack_type="cmdi",
                evidence=(
                    f"Parameter '{param_name}' with payload '{payload}' {evidence_tail}.\n\n"
                    f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                ),
                confirmed=True,
                payload=payload,
                parameter=param_name,
                url=target.url,
                request_method=target.method,
                bypass_validation=True,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            )
        return None


Coordinator.register(CmdiAgent)

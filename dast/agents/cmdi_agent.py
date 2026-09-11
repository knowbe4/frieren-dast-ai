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
from dast.scanners.active_checks import _fmt_http_pair, _inject_query, _send, response_elapsed_ms, quiesce_for_time_probe
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
            param_name = param.get("name", "")
            if not param_name:
                continue
            finding = await self._probe_output(
                target, client, param_name, unix_basic[:8], baseline_body
            )
            if finding:
                return [finding]

        for param in probe_params:
            param_name = param.get("name", "")
            if not param_name:
                continue
            finding = await self._probe_bypass_output(
                target, client, param_name, bypass_payloads[:12], baseline_body
            )
            if finding:
                return [finding]

        for param in probe_params:
            param_name = param.get("name", "")
            if not param_name:
                continue
            finding = await self._probe_time_based(
                target, client, param_name, unix_blind[:4]
            )
            if finding:
                return [finding]

        return findings

    async def _probe_output(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param_name: str,
        payloads: List[str],
        baseline_body: str,
    ) -> Optional[AgentFinding]:
        """Phase 1: inject `id`/`whoami` variants and look for command output or a
        shell-error disclosure directly in the response (no delay involved)."""
        for payload in payloads:
            payload = str(payload)
            url = _inject_query(target.url, param_name, payload)
            resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
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
        param_name: str,
        payloads: List[str],
        baseline_body: str,
    ) -> Optional[AgentFinding]:
        """Phase 3: encoding / whitespace (IFS) / alternative-separator variants
        that still execute `id`, detected via the same output signature. Runs after
        the direct output probes so it only matters when a naive payload was filtered."""
        for payload in payloads:
            payload = str(payload)
            url = _inject_query(target.url, param_name, payload)
            resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
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
        param_name: str,
        value: str,
    ) -> tuple[float, Optional["httpx.Response"]]:
        """Inject `value` into `param_name` and return (server_elapsed_s, response).

        Uses httpx's `.elapsed` (server round-trip only) rather than wall-clock, so
        time waiting to acquire the shared probe semaphore under concurrent load
        does not pollute timing — see active_checks.response_elapsed_ms."""
        url = _inject_query(target.url, param_name, value)
        resp = await _send(client, target.method, url, target.headers, target.body, payload=value)
        return response_elapsed_ms(resp) / 1000.0, resp

    async def _probe_time_based(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param_name: str,
        payloads: List[str],
    ) -> Optional[AgentFinding]:
        """Phase 2: time-based blind — inject `sleep N` variants and confirm the
        response is >threshold slower than an ADJACENT control. The expensive phase
        (each probe costs a full ~5s delay), so it runs last, only when nothing
        reflected.

        Rather than comparing against the single baseline measured once at scan
        start, each SLEEP probe is paired with a clean control request sent right
        before it. Under concurrent multi-agent load on one endpoint, a plain
        request can itself take several seconds and that ambient latency drifts
        burst to burst; a stale start baseline then makes the required delay
        unreachable by a safety-capped sleep, missing a real blind injection. The
        adjacent control shares the probe's ambient load, so the delta isolates the
        injected sleep. A second control/probe pair re-confirms: load spikes are
        transient, an injected sleep reproduces every time."""
        for payload in payloads:
            payload = str(payload)

            # Hold the global time-probe lock across the measurement so no other
            # agent's SLEEP saturates the server between control and probe.
            async with quiesce_for_time_probe():
                control_s, _ = await self._timed_send(target, client, param_name, "1")
                probe_s, resp = await self._timed_send(target, client, param_name, payload)
            delta_s = probe_s - control_s
            candidate = (
                resp is not None
                and delta_s >= _TIME_THRESHOLD_S
                and probe_s >= _TIME_THRESHOLD_S
            )
            logger.debug(
                "cmdi time-based probe", param=param_name, payload=payload,
                control_s=round(control_s, 2), probe_s=round(probe_s, 2),
                delta_s=round(delta_s, 2), candidate=candidate,
            )
            if not candidate:
                continue

            async with quiesce_for_time_probe():
                control2_s, _ = await self._timed_send(target, client, param_name, "1")
                probe2_s, resp2 = await self._timed_send(target, client, param_name, payload)
            delta2_s = probe2_s - control2_s
            confirmed = (
                resp2 is not None
                and delta2_s >= _TIME_THRESHOLD_S
                and probe2_s >= _TIME_THRESHOLD_S
            )
            logger.debug(
                "cmdi time-based re-confirm", param=param_name, payload=payload,
                control_s=round(control2_s, 2), probe_s=round(probe2_s, 2),
                delta_s=round(delta2_s, 2), confirmed=confirmed,
            )
            if not confirmed:
                continue

            confirm_resp = resp2 if resp2 is not None else resp
            raw_req, raw_resp = _fmt_http_pair(confirm_resp)
            log_event("agent", "finding",
                      f"CMDi blind: {param_name} delayed {delta_s:.1f}s (x2) on {target.url}",
                      url=target.url, finding="Blind CMDi", source="agent")
            return AgentFinding(
                title="OS Command Injection — Time-Based Blind",
                severity="critical",
                cwe="CWE-78",
                attack_type="cmdi",
                evidence=(
                    f"Parameter '{param_name}' with payload '{payload}' delayed the response "
                    f"{delta_s:.1f}s then {delta2_s:.1f}s over an adjacent control "
                    f"(control ~{control_s:.1f}/{control2_s:.1f}s). The {_SLEEP_DURATION}s sleep "
                    f"reproduced server-side independent of ambient load.\n\n"
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

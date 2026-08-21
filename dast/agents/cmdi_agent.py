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
import time
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.payloads.loader import get_payloads
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _inject_query, _send
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

        # Measure baseline response time
        t0 = time.time()
        baseline = await _send(client, target.method, target.url, target.headers, target.body)
        baseline_time = time.time() - t0
        if not baseline:
            return []
        baseline_body = baseline.text[:4000]

        unix_basic = get_payloads("cmdi", "unix_basic") or [";id", "|id", "$(id)", "`id`"]
        unix_blind = get_payloads("cmdi", "unix_blind_time") or [
            f";sleep {_SLEEP_DURATION}", f"|sleep {_SLEEP_DURATION}",
            f"$(sleep {_SLEEP_DURATION})", f"`sleep {_SLEEP_DURATION}`",
        ]
        bypass_payloads = get_payloads("cmdi", "bypass") or []

        for param in params[:5]:
            param_name = param.get("name", "")
            if not param_name:
                continue

            # Phase 1: Output-based detection
            for payload in unix_basic[:8]:
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
                    findings.append(AgentFinding(
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
                    ))
                    return findings

                # Shell error pattern
                if _SHELL_ERROR_RE.search(body) and not _SHELL_ERROR_RE.search(baseline_body):
                    raw_req, raw_resp = _fmt_http_pair(resp)
                    findings.append(AgentFinding(
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
                    ))
                    return findings

            # Phase 2: Time-based blind
            for payload in unix_blind[:4]:
                payload = str(payload)
                url = _inject_query(target.url, param_name, payload)
                t0 = time.time()
                resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
                elapsed = time.time() - t0
                if not resp:
                    continue

                if elapsed > baseline_time + _TIME_THRESHOLD_S:
                    raw_req, raw_resp = _fmt_http_pair(resp)
                    log_event("agent", "finding",
                              f"CMDi blind: {param_name} delayed {elapsed:.1f}s on {target.url}",
                              url=target.url, finding="Blind CMDi", source="agent")
                    findings.append(AgentFinding(
                        title="OS Command Injection — Time-Based Blind",
                        severity="critical",
                        cwe="CWE-78",
                        attack_type="cmdi",
                        evidence=(
                            f"Parameter '{param_name}' with payload '{payload}' caused a "
                            f"{elapsed:.1f}s delay (baseline: {baseline_time:.1f}s). "
                            f"The {_SLEEP_DURATION}s sleep was executed server-side.\n\n"
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
                    ))
                    return findings

            # Phase 3: WAF bypass — encoding, whitespace (IFS), and separator
            # variants that still execute `id`, detected via the same output /
            # shell-error signatures as Phase 1. Runs after the direct probes so
            # it only fires when a naive payload was filtered.
            for payload in bypass_payloads[:12]:
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
                    findings.append(AgentFinding(
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
                    ))
                    return findings

        return findings


Coordinator.register(CmdiAgent)

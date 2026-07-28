"""
LLM injection agent — detects prompt injection, jailbreak, indirect injection,
and system prompt leakage in AI-backed endpoints.

Detection flow:
  1. Identify AI-backed parameters: URL pattern match OR param name match
     (prompt, message, input, query, text, instructions, context, system)
     OR response body signals from baseline. If coordinator selected this agent,
     skip the gate entirely and probe all text params.
  2. Probe with all payload categories: direct_injection, structural_escape,
     indirect_injection, jailbreak, behavioral_probe, indirect_rag
  3. Confirm injection via three independent vectors:
     - Exact marker (DAST_LLM_PWNED_7x9z) in response — bypass_validation=True
     - Numeric canary (3847) isolated in response — bypass_validation=True
     - Behavioral canary phrase (HOSTILE_TAKEOVER_COMPLETE, INJECTION_SUCCESSFUL_9q2z)
  4. Probe system prompt exfiltration with system_prompt_leak payloads
  5. Adaptive mutation loop when all seeds fail (LLM mutator generates bypass variants)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional
from urllib.parse import urlparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.mutator import build_mutator_context, next_payload
from dast.agents.block_detector import detect_block
from dast.payloads.loader import get_payloads, get_value
from dast.scanners.active_checks import _fmt_http_pair, _inject_body, _inject_query, _inject_multipart, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_CONFIRM_MARKER = "DAST_LLM_PWNED_7x9z"
_NUMERIC_CANARY = "3847"
_CANARY_RE = re.compile(r'(?<!\d)3847(?!\d)')


def _get_signals() -> dict:
    return get_value("llm_injection", "ai_endpoint_signals") or {}


def _is_ai_param(param_name: str) -> bool:
    """True if the parameter name suggests it carries LLM input.

    For dot-notation params (e.g. "input.prompt") only the last segment is
    checked — the parent key "input" is a structural wrapper, not a signal.
    For flat params, the full name is checked.
    """
    name_lower = param_name.lower().lstrip("_")
    # For nested params use only the last segment to avoid false matches where
    # a structural wrapper key like "input" appears in every "input.*" param.
    if "." in name_lower:
        check_name = name_lower.rsplit(".", 1)[-1]
    else:
        check_name = name_lower
    param_signals = _get_signals().get("param_name_signals", [])
    return any(s == check_name or check_name.startswith(s) for s in param_signals)


def _is_ai_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    url_patterns = _get_signals().get("url_patterns", [])
    return any(p in path for p in url_patterns)


def _is_ai_response(body: str) -> bool:
    if not body:
        return False
    body_lower = body.lower()
    response_patterns = _get_signals().get("response_patterns", [])
    return any(p.lower() in body_lower for p in response_patterns)


_INPUT_FIELD_NAMES = frozenset({
    "prompt", "input", "text", "message", "query", "instructions",
    "content", "q", "system", "user", "request", "ask",
})


def _find_in_output_fields(data: object, marker: str, injected_leaf: str) -> bool:
    """
    Recursively search JSON data for `marker` in fields that are NOT the
    injected input field. Returns True only when the marker appears in a
    field name that looks like generated output (not an echo of the input).
    """
    if isinstance(data, dict):
        for k, v in data.items():
            k_lower = k.lower()
            if isinstance(v, str) and marker in v:
                # If this key is the injected param or a known input field → echo, skip
                if k_lower == injected_leaf or k_lower in _INPUT_FIELD_NAMES:
                    continue
                return True
            elif isinstance(v, (dict, list)):
                if _find_in_output_fields(v, marker, injected_leaf):
                    return True
    elif isinstance(data, list):
        for item in data:
            if _find_in_output_fields(item, marker, injected_leaf):
                return True
    return False


def _is_confirmed(response_text: str, injected_param: str = "") -> tuple[bool, str]:
    """
    Check all confirmation vectors. Returns (confirmed, reason).

    When injected_param is given, distinguish between the marker appearing
    as an echo of the input field (false positive) vs appearing in a generated
    output field (true positive). An echo means the app stored and returned the
    payload verbatim — the LLM did NOT execute the injection.
    """
    success_signals = get_value("llm_injection", "success_signals") or [_CONFIRM_MARKER]
    injected_leaf = injected_param.rsplit(".", 1)[-1].lower() if injected_param else ""

    for sig in success_signals:
        if sig not in response_text:
            continue
        # Signal found — now check if it's an echo or real LLM output
        if injected_leaf:
            try:
                import json as _json
                data = _json.loads(response_text)
                if not _find_in_output_fields(data, sig, injected_leaf):
                    # Marker only appears in the echoed input field — not a real injection
                    continue
            except Exception:
                pass  # Non-JSON response containing marker → treat as confirmed
        return True, f"success signal {sig!r} found in LLM output field"

    if _CANARY_RE.search(response_text):
        # Numeric canary check — also verify it's not just an echo
        if injected_leaf:
            try:
                import json as _json
                data = _json.loads(response_text)
                if not _find_in_output_fields(data, _NUMERIC_CANARY, injected_leaf):
                    return False, ""
            except Exception:
                pass
        return True, f"numeric canary {_NUMERIC_CANARY!r} found isolated in response"

    return False, ""


class LlmInjectionAgent(VulnAgent):
    name = "LLM Injection Agent"
    attack_type = "llm_injection"
    description = (
        "Detects prompt injection, jailbreak, indirect injection, and system prompt "
        "leakage in AI-backed endpoints. Uses adaptive mutations when the model filters payloads."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        # Baseline response — used for AI endpoint detection and passive leak check
        baseline = await _send(client, target.method, target.url, target.headers, target.body)
        baseline_body = baseline.text if baseline else ""

        ai_url = _is_ai_url(target.url)
        ai_response = _is_ai_response(baseline_body)

        # Determine which params to probe
        # Priority: params that look like AI input fields; fall back to all text params
        # when the URL or response confirms we're on an AI endpoint.
        text_params = [
            p for p in target.params
            if p.get("location") in ("query", "body", "body_graphql")
        ]

        ai_params = [p for p in text_params if _is_ai_param(p["name"])]

        if not ai_params and not ai_url and not ai_response:
            # No signal at all — nothing to probe
            return []

        # Prefer named AI params; fall back to all text params on confirmed AI endpoint
        probe_params = ai_params if ai_params else text_params
        if not probe_params and target.body:
            probe_params = [{"name": "_body", "location": "body_raw", "value": target.body}]

        if not probe_params:
            return []

        logger.info(
            "LLM injection probing",
            url=target.url,
            ai_url=ai_url,
            ai_params=[p["name"] for p in ai_params],
        )

        findings: List[AgentFinding] = []

        # Passive leak check on baseline
        leak_finding = self._check_system_prompt_leak_passive(target, baseline_body)
        if leak_finding:
            findings.append(leak_finding)

        # Active injection probe — stop at first confirmed param
        for param in probe_params:
            finding = await self._probe_injection(target, client, param)
            if finding:
                findings.append(finding)
                break

        # System prompt exfiltration — only if no leak already found
        if not any(f.attack_type == "llm_prompt_leak" for f in findings):
            leak = await self._probe_system_prompt_leak(target, client, probe_params)
            if leak:
                findings.append(leak)

        return findings

    async def _probe_injection(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
    ) -> Optional[AgentFinding]:
        seed = (
            get_payloads("llm_injection", "direct_injection")
            + get_payloads("llm_injection", "structural_escape")
            + get_payloads("llm_injection", "obfuscation")
            + get_payloads("llm_injection", "behavioral_probe")
            + get_payloads("llm_injection", "indirect_injection")
            + get_payloads("llm_injection", "jailbreak")
            + get_payloads("llm_injection", "indirect_rag")
            + get_payloads("llm_injection", "data_exfiltration")
        )
        payloads_to_try = list(seed)
        tried: set = set()
        mutation_iteration = 0
        block_seen = False  # did an earlier probe on this param get blocked?
        tech_context = build_mutator_context(target, "llm_injection")

        for iteration, payload in enumerate(payloads_to_try):
            if payload in tried:
                continue
            tried.add(payload)

            resp = await self._send_probe(target, client, param, payload)
            if resp is None:
                continue

            confirmed, reason = _is_confirmed(resp.text, injected_param=param["name"])
            if confirmed:
                if block_seen:
                    self.observe("waf_bypass", payload=payload, signal="payload succeeded after prior block")
                raw_request, raw_response = _fmt_http_pair(resp)
                return AgentFinding(
                    title="LLM Prompt Injection",
                    severity="high",
                    cwe="CWE-1336",
                    attack_type="llm_injection",
                    evidence=f"Injection confirmed: {reason}",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=False,  # always validate via Red Team — echo FPs are common
                    raw_request=raw_request,
                    raw_response=raw_response,
                )

            # After exhausting seed payloads, enter mutation loop
            if iteration >= len(seed) - 1:
                verdict = detect_block(resp.status_code, resp.text)
                if verdict.is_block:
                    block_seen = True
                    self.observe("waf_block", payload=payload, signal=verdict.signal)
                mutation = await next_payload(
                    attack_type="llm_injection",
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
                    "LLM injection mutator",
                    param=param["name"],
                    action=mutation.action,
                    rationale=mutation.rationale,
                )
                payloads_to_try.append(mutation.payload)

        return None

    async def _probe_system_prompt_leak(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        params: list,
    ) -> Optional[AgentFinding]:
        leak_payloads = get_payloads("llm_injection", "system_prompt_leak")
        leak_sigs = get_value("llm_injection", "system_prompt_leak_signals") or []
        if not leak_sigs:
            return None
        leak_re = re.compile("|".join(re.escape(s) for s in leak_sigs), re.IGNORECASE)

        param = params[0] if params else {"name": "input", "location": "body", "value": ""}
        for payload in leak_payloads:
            resp = await self._send_probe(target, client, param, payload)
            if resp and leak_re.search(resp.text):
                snippet = resp.text[:300]
                raw_request, raw_response = _fmt_http_pair(resp)
                return AgentFinding(
                    title="LLM System Prompt Leakage",
                    severity="medium",
                    cwe="CWE-200",
                    attack_type="llm_prompt_leak",
                    evidence=f"Response to prompt-leak payload contains system instruction language: {snippet!r}",
                    payload=payload,
                    parameter=param["name"],
                    url=target.url,
                    request_method=target.method,
                    raw_request=raw_request,
                    raw_response=raw_response,
                )
        return None

    def _check_system_prompt_leak_passive(
        self, target: "CheckTarget", response_body: str
    ) -> Optional[AgentFinding]:
        if not response_body:
            return None
        leak_sigs = get_value("llm_injection", "system_prompt_leak_signals") or []
        if not leak_sigs:
            return None
        leak_re = re.compile("|".join(re.escape(s) for s in leak_sigs), re.IGNORECASE)
        m = leak_re.search(response_body)
        if m:
            snippet = response_body[max(0, m.start() - 30):m.end() + 80]
            return AgentFinding(
                title="LLM System Prompt Exposed in Baseline Response",
                severity="medium",
                cwe="CWE-200",
                attack_type="llm_prompt_leak",
                evidence=f"Baseline response contains system instruction language: {snippet!r}",
                payload="(passive — no payload injected)",
                parameter="response_body",
                url=target.url,
                request_method=target.method,
            )
        return None

    async def _send_probe(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        param: dict,
        payload: str,
    ):
        location = param.get("location", "body")
        if location == "query":
            url = _inject_query(target.url, param["name"], payload)
            return await _send(client, target.method, url, target.headers, target.body)
        elif location in ("body", "body_graphql"):
            body = _inject_body(
                target.body or "", param["name"], payload,
                target.headers.get("content-type", ""),
                location=location,
            )
            return await _send(client, target.method, target.url, target.headers, body)
        elif location.startswith("multipart_"):
            raw = _inject_multipart(target.raw_body or b"", param["name"], payload)
            return await _send(client, target.method, target.url, target.headers, raw)
        elif location == "body_raw":
            import json
            ct = target.headers.get("content-type", "")
            if "json" in ct:
                try:
                    data = json.loads(target.body or "{}")
                    if isinstance(data, dict):
                        prompt_keys = ["prompt", "message", "input", "query", "text", "content", "q"]
                        for key in prompt_keys:
                            if key in data:
                                data[key] = payload
                                return await _send(
                                    client, target.method, target.url,
                                    target.headers, json.dumps(data),
                                )
                except Exception:
                    pass
            return await _send(client, target.method, target.url, target.headers, payload)
        return None


from dast.ai.coordinator import Coordinator
Coordinator.register(LlmInjectionAgent)

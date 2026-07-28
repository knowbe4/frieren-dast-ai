"""
Secrets agent — detects credentials, tokens, and sensitive data in responses.

Deterministic pattern matching; no LLM needed. Always sets bypass_validation=True
because pattern evidence is self-confirming.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.plugins.passive_scanner import _is_presigned_url_context
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

_PATTERNS: list = [
    (
        # Negative lookahead excludes keys followed by % or / (presigned URL key+date separator)
        re.compile(r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9%/])"),
        "AWS Access Key Exposed",
        "critical",
        "CWE-312",
    ),
    (
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Private Key Exposed",
        "critical",
        "CWE-312",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "JWT Token Exposed",
        "medium",
        "CWE-312",
    ),
    (
        re.compile(
            r'"(?:password|passwd|secret|api_key|apikey|token|access_token|auth_token)"\s*:\s*"[^"]{6,}"',
            re.IGNORECASE,
        ),
        "Plaintext Credential in API Response",
        "high",
        "CWE-312",
    ),
    (
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        "Credit Card Number Exposed",
        "high",
        "CWE-312",
    ),
]


class SecretsAgent(VulnAgent):
    name = "Secrets Agent"
    attack_type = "sensitive_data"
    description = "Detects credentials, tokens, and PII exposed in API responses"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        # Use the original request (no payload injection) — scan what the server returns
        logger.debug("Secrets agent started", url=target.url)
        resp = await _send(client, target.method, target.url, target.headers, target.body)
        if resp is None:
            logger.debug("Secrets agent: no response", url=target.url)
            return []

        body = resp.text
        findings: List[AgentFinding] = []

        raw_request, raw_response = _fmt_http_pair(resp)
        for pattern, title, severity, cwe in _PATTERNS:
            m = pattern.search(body)
            if m:
                snippet = body[max(0, m.start() - 200):m.end() + 200]
                # Suppress AWS keys that appear inside presigned S3 URLs
                if "AWS" in title and _is_presigned_url_context(snippet):
                    logger.debug("Secrets agent: suppressed presigned URL false positive", title=title, url=target.url)
                    continue
                snippet = body[max(0, m.start() - 20):m.end() + 20]
                log_event("sensitive_data", "finding", f"{title} — {target.url}", url=target.url, finding=title, source="agent")
                findings.append(AgentFinding(
                    title=title,
                    severity=severity,
                    cwe=cwe,
                    attack_type="sensitive_data",
                    evidence=f"Pattern matched in response body: {snippet!r}",
                    payload="(passive — no payload injected)",
                    parameter="response_body",
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_response_snippet=snippet,
                    raw_request=raw_request,
                    raw_response=raw_response,
                ))

        logger.debug("Secrets agent done", url=target.url, findings=len(findings))
        return findings


from dast.ai.coordinator import Coordinator
Coordinator.register(SecretsAgent)

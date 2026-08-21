"""
XXE agent — XML External Entity injection for file read and OOB exfiltration.

Strategy:
  1. Detect XML-accepting endpoints (Content-Type: application/xml, text/xml, SOAP)
  2. Inline file read: inject DTD with file:/// entity, check for /etc/passwd in response
  3. OOB exfiltration: use collaborator URL in external DTD to confirm blind XXE
  4. Parameter entities: when direct entities are blocked, try %entity; in DTD
  5. SSRF via XXE: use http:// entity to probe internal services

Requires: XML-accepting endpoint or parameter injected into XML document.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.payloads.loader import get_payloads
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_FILE_READ_EVIDENCE_RE = re.compile(
    r"root:.*:0:0:|bin/(bash|sh)|/home/\w+:|"
    r"\[boot loader\]|Windows/system32|"
    r"\[extensions\]|; for 16-bit app|"
    r"daemon:.*:/usr/sbin|nobody:.*:/nonexistent",
    re.I,
)

_XXE_ERROR_RE = re.compile(
    r"(XML.*parsing.*error|entity.*not.*allowed|"
    r"DTD.*not.*allowed|unexpected.*<!DOCTYPE|"
    r"DOCTYPE.*disallowed|external.*entities.*disabled|"
    r"SAXParseException|XMLParseError|"
    r"lxml\.etree|xml\.parsers\.expat|"
    r"com\.sun\.org\.apache\.xerces)",
    re.I,
)

_XML_CONTENT_TYPES = ("application/xml", "text/xml", "application/soap+xml",
                      "application/xhtml+xml", "application/atom+xml")


def _is_xml_endpoint(target: "CheckTarget") -> bool:
    """Check if the endpoint accepts XML (from request Content-Type or body shape)."""
    ct = (target.headers.get("content-type") or "").lower()
    if any(xml_ct in ct for xml_ct in _XML_CONTENT_TYPES):
        return True
    body = (target.body or "").strip()
    if body.startswith("<?xml") or body.startswith("<!DOCTYPE") or body.startswith("<"):
        if ">" in body[:200]:
            return True
    return False


class XxeAgent(VulnAgent):
    name = "XXE Agent"
    attack_type = "xxe"
    description = "Tests for XML External Entity injection — file read, OOB exfiltration, and SSRF"

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        # If not explicitly XML, force content-type switch to XML on any POST/PUT/PATCH.
        # Many frameworks accept XML regardless of what clients normally send.
        # IMPORTANT: use a copy of headers — never mutate target.headers (shared across agents)
        _switched_ct = False
        _headers = dict(target.headers)
        if not _is_xml_endpoint(target):
            if target.method in ("POST", "PUT", "PATCH"):
                logger.info("xxe: non-XML endpoint, forcing content-type switch to application/xml on %s", target.url)
                _headers["content-type"] = "application/xml"
                _switched_ct = True
            else:
                logger.debug("xxe: GET endpoint, skipping %s", target.url)
                return []

        logger.info("xxe: testing %s%s", target.url, " (CT forced to XML)" if _switched_ct else "")

        # Payload group names must match dast/payloads/xxe.yaml exactly.
        # NOTE: the "ssrf_internal" group is intentionally not loaded here — its
        # payloads reflect internal-service responses (cloud metadata, localhost)
        # that need a dedicated signature matcher, not the file-read regex. Wiring
        # XXE-driven SSRF detection is tracked as a separate follow-up.
        file_read_payloads = get_payloads("xxe", "basic_file_read") or []
        oob_dtd_payloads = get_payloads("xxe", "oob_dtd") or []
        parameter_payloads = get_payloads("xxe", "parameter_entity") or []
        cdata_payloads = get_payloads("xxe", "cdata_bypass") or []

        # Split by delivery model: payloads carrying the CALLBACK_URL placeholder
        # exfiltrate out-of-band (need a collaborator); the rest reflect the file
        # content inline in the response body.
        inline_payloads = [
            payload for payload in (file_read_payloads + parameter_payloads)
            if "CALLBACK_URL" not in str(payload)
        ]
        oob_payloads = [
            payload for payload in (oob_dtd_payloads + parameter_payloads + cdata_payloads)
            if "CALLBACK_URL" in str(payload)
        ]

        # Phase 1: Inline file read (basic entities + inline parameter-entity variants)
        for payload in inline_payloads[:10]:
            payload = str(payload).strip()
            if not payload:
                continue

            resp = await _send(client, target.method, target.url, _headers, payload, payload=payload)
            if not resp:
                continue

            body = resp.text[:8000]

            if _FILE_READ_EVIDENCE_RE.search(body):
                raw_req, raw_resp = _fmt_http_pair(resp)
                file_match = _FILE_READ_EVIDENCE_RE.search(body).group(0)
                log_event("agent", "finding",
                          f"XXE file read confirmed on {target.url}",
                          url=target.url, finding="XXE file read", source="agent")
                findings.append(AgentFinding(
                    title="XML External Entity (XXE) — Arbitrary File Read",
                    severity="critical",
                    cwe="CWE-611",
                    attack_type="xxe",
                    evidence=(
                        f"XXE payload with file:/// entity returned local file content: "
                        f"'{file_match}'. The XML parser processes external entities.\n\n"
                        f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                    ),
                    confirmed=True,
                    payload=payload[:200],
                    parameter="XML body",
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                    raw_request=raw_req,
                    raw_response=raw_resp[:2000],
                ))
                return findings

            # Check for XXE error (parser detected the attempt)
            if _XXE_ERROR_RE.search(body):
                raw_req, raw_resp = _fmt_http_pair(resp)
                findings.append(AgentFinding(
                    title="XXE — XML Parser Error Disclosure",
                    severity="medium",
                    cwe="CWE-611",
                    attack_type="xxe",
                    evidence=(
                        f"XXE payload triggered XML parser error: "
                        f"'{_XXE_ERROR_RE.search(body).group(0)}'. "
                        f"External entities may be disabled but the parser processes DTDs — "
                        f"parameter entity or SSRF variants may still work.\n\n"
                        f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                    ),
                    payload=payload[:200],
                    parameter="XML body",
                    url=target.url,
                    request_method=target.method,
                    raw_request=raw_req,
                    raw_response=raw_resp[:2000],
                ))

        # Phase 2: OOB exfiltration via collaborator
        if collaborator and collaborator.url:
            collab_url = collaborator.url
            for payload_template in oob_payloads[:6]:
                payload = str(payload_template).replace("CALLBACK_URL", collab_url)
                if collab_url not in payload:
                    continue

                resp = await _send(client, target.method, target.url, _headers, payload, payload=payload[:100])
                if not resp:
                    continue

            # Check for OOB hit
            import asyncio
            await asyncio.sleep(3)
            if await collaborator.poll():
                log_event("agent", "finding",
                          f"XXE OOB exfiltration confirmed on {target.url}",
                          url=target.url, finding="XXE OOB", source="agent")
                findings.append(AgentFinding(
                    title="XML External Entity (XXE) — Out-of-Band Exfiltration",
                    severity="critical",
                    cwe="CWE-611",
                    attack_type="xxe",
                    evidence=(
                        f"XXE payload with external DTD pointing to {collab_url} triggered "
                        f"an OOB callback. The XML parser fetches external resources, "
                        f"confirming blind XXE. Data exfiltration is possible via parameter entities."
                    ),
                    confirmed=True,
                    payload="[OOB DTD payload]",
                    parameter="XML body",
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=True,
                ))
                return findings

        if not findings:
            logger.info("xxe: no XXE found on %s", target.url)
        return findings


Coordinator.register(XxeAgent)

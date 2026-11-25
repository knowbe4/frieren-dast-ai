"""HTTP/2 agent — h2 support detection and CL/DATA desync probing.

Round 4-D. Requires the ``h2`` dependency (pure-Python HTTP/2 framing; the
dependency decision from the roadmap is: ADOPTED — no server-side emulation is
shipped, the probe speaks h2 client-side only).

Checks (direct socket to the target — the MITM speaks HTTP/1.1, so h2 probes
bypass it exactly like the smuggling/CSWSH raw agents):

1. **ALPN detection**: TLS handshake advertising ``h2`` — if the server
   negotiates h2, the endpoint is a candidate for HTTP/2 attacks
   (informational, low).
2. **CL/DATA desync**: the classic h2 smuggling shape — HEADERS declaring
   ``content-length: 0`` followed by a DATA frame carrying an entire smuggled
   ``GET … HTTP/1.1`` request. RFC 7540 forbids a body beyond the declared
   length: a compliant server answers PROTOCOL_ERROR once. A server that
   forwards the DATA downstream as a second request answers with a SECOND
   response whose status/body references the smuggled path — the desync
   (CWE-444, critical, confirmed by the smuggled marker).

Safety: the smuggled request is a benign GET to a random path — nothing
mutated, nothing poisoned. Read counts only; no rapid-reset floods (explicitly
out of scope — that is a DoS, not a finding).
"""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import TYPE_CHECKING, List, Optional, Set, Tuple
from urllib.parse import urlparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.proxy.plugin_manager import log_event
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

_CONNECT_TIMEOUT_S = 10.0
_READ_TIMEOUT_S = 8.0
_H2_ALPN = "h2"
_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_CLIENT_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

# h2 handling is a per-HOST property (ALPN + the framing pipeline are
# server-level, not per-endpoint). With the https dispatch rule live, every
# endpoint of a host would otherwise re-run the TLS handshake and re-emit the
# duplicate "HTTP/2 Enabled" marker — probe once per (host, port) instead.
# A transient first-probe failure is not retried (same trade as the refresh
# breaker); the next scan run gets a fresh process.
_PROBED_HOSTS: Set[Tuple[str, int]] = set()


def _reset_probe_memo() -> None:
    """Test isolation for the per-host probe memo."""
    _PROBED_HOSTS.clear()


def _alpn_supports_h2(host: str, port: int) -> Optional[bool]:
    """One TLS handshake advertising h2 — True/False; None on failure
    (plain-http targets never negotiate ALPN → None, not a finding)."""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    ssl_ctx.set_alpn_protocols([_H2_ALPN, "http/1.1"])
    import socket as _socket

    try:
        with _socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_S) as sock:
            with ssl_ctx.wrap_socket(sock) as tls:
                proto = tls.selected_alpn_protocol()
                return proto == _H2_ALPN
    except Exception as exc:  # noqa: BLE001 — detection is best-effort
        logger.debug("http2: ALPN handshake failed", host=host, error=str(exc)[:160])
        return None


def _frame(ftype: int, flags: int, stream: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) \
        + stream.to_bytes(4, "big") + payload


def _build_smuggled_probe(target_url: str, marker_path: str) -> Optional[bytes]:
    """Build the h2 byte stream: preface + SETTINGS + HEADERS(CL:0) + DATA with
    an embedded HTTP/1.1 smuggled GET. Hand-crafted framing with ``hpack`` for
    the header block — the ``h2`` client library REFUSES to send DATA beyond
    the declared length (it is RFC-compliant), which would defeat the probe.
    Returns None when the dependency or URL is unusable."""
    try:
        import hpack
    except ImportError:
        return None
    parsed = urlparse(target_url)
    path = parsed.path or "/"
    authority = parsed.netloc
    if not authority:
        return None

    smuggled = (
        f"GET {marker_path} HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    encoder = hpack.Encoder()
    header_block = encoder.encode([
        (b":method", b"GET"),
        (b":path", path),
        (b":scheme", parsed.scheme or "https"),
        (b":authority", authority),
        (b"content-length", b"0"),
    ])
    out = bytearray(_PREFACE)
    out += _CLIENT_SETTINGS
    out += _frame(0x01, 0x04, 1, header_block)         # HEADERS, END_HEADERS
    out += _frame(0x00, 0x01, 1, smuggled.encode("latin-1"))  # DATA, END_STREAM
    return bytes(out)


async def _read_h2_exchange(host: str, port: int, use_tls: bool,
                            payload: bytes) -> Optional[bytes]:
    """Send the probe, read everything until close/deadline (same idiom as the
    smuggling transport). Never raises."""
    ssl_ctx = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        ssl_ctx.set_alpn_protocols([_H2_ALPN])
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx),
            timeout=_CONNECT_TIMEOUT_S,
        )
        writer.write(payload)
        await writer.drain()
        data = b""
        deadline = time.monotonic() + _READ_TIMEOUT_S
        while time.monotonic() < deadline and len(data) < 262144:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(16384), timeout=max(0.1, deadline - time.monotonic()))
            except (asyncio.TimeoutError, ConnectionError, OSError):
                break
            if not chunk:
                break
            data += chunk
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return data
    except Exception as exc:  # noqa: BLE001 — probing is best-effort, never crash
        logger.debug("http2: exchange failed", host=host, error=str(exc)[:160])
        return None


class Http2Agent(VulnAgent):
    name = "HTTP/2 Agent"
    attack_type = "http2"
    description = (
        "HTTP/2 surface: ALPN support detection and the CL/DATA desync probe "
        "(HEADERS content-length:0 followed by a smuggled DATA request)"
    )

    async def run(
        self,
        target: "CheckTarget",
        client=None,  # unused — raw sockets bypass the shared client
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        parsed = urlparse(target.url)
        host = parsed.hostname or ""
        if not host:
            return []
        use_tls = parsed.scheme in ("https", "wss")
        port = parsed.port or (443 if use_tls else 80)
        memo_key = (host, port)
        if memo_key in _PROBED_HOSTS:
            return []
        _PROBED_HOSTS.add(memo_key)
        findings: List[AgentFinding] = []

        # 1) ALPN detection (TLS only).
        if use_tls:
            alpn = await asyncio.to_thread(_alpn_supports_h2, host, port)
            if alpn:
                findings.append(AgentFinding(
                    title="HTTP/2 Enabled (ALPN negotiates h2)",
                    severity="low",
                    cwe="CWE-444",
                    attack_type="http2",
                    evidence=(
                        "The server negotiates HTTP/2 via ALPN. h2-facing surfaces "
                        "are candidates for desync and Rapid-Reset-class issues — "
                        "this entry is a detection marker, not an exploit."
                    ),
                    confirmed=False,
                    payload="ALPN: h2",
                    parameter="alpn",
                    url=target.url,
                    request_method="GET",
                    bypass_validation=False,
                ))

        # 2) CL/DATA desync probe.
        marker_path = f"/dast-h2-{int(time.time())}"
        payload = _build_smuggled_probe(target.url, marker_path)
        if payload is None:
            return findings
        data = await _read_h2_exchange(host, port, use_tls, payload)
        if not data:
            return findings

        # A compliant server answers PROTOCOL_ERROR once and closes. The desync
        # signature: a PLAINTEXT HTTP/1.x response inside the exchange — the
        # DATA frame was forwarded downstream as a fresh request and the
        # backend answered in HTTP/1.1 — ideally echoing our marker path.
        plaintext_responses = data.count(b"HTTP/1.")
        smuggled_answered = marker_path.encode() in data
        if plaintext_responses < 1:
            return findings

        # Confirmed desync requires a STRONG signal: either our smuggled marker
        # path was echoed back (the DATA frame was processed as a real request),
        # or there are >= 2 plaintext HTTP/1 responses on the one connection (a
        # legit response PLUS one from the forwarded DATA). A single plaintext
        # response with no marker echo is almost always the server rejecting the
        # malformed h2 with a plaintext `HTTP/1.1 400` — NOT a desync, so it is
        # downgraded (informational, not confirmed) rather than flagged critical.
        raw = data.decode("latin-1", errors="replace")[:3000]
        confirmed = smuggled_answered or plaintext_responses >= 2
        if confirmed:
            log_event("agent", "finding",
                      f"HTTP/2 CL/DATA desync confirmed on {target.url}",
                      url=target.url, finding="H2 desync", source="agent")
            findings.append(AgentFinding(
                title="HTTP/2 CL/DATA Desync — DATA Frame Forwarded as a Second Request",
                severity="critical",
                cwe="CWE-444",
                attack_type="http2",
                evidence=(
                    f"HEADERS declared content-length: 0 yet the DATA frame's "
                    f"embedded request was processed by the backend: "
                    f"{plaintext_responses} plaintext responses on one connection"
                    + (f" and the smuggled path '{marker_path}' was echoed"
                       if smuggled_answered else "") + ".\n\n"
                    f"Exchange:\n{raw}"
                ),
                confirmed=True,
                payload=f"h2 HEADERS(CL:0) + DATA[{marker_path}]",
                parameter="h2-frames",
                url=target.url,
                request_method="GET",
                bypass_validation=True,
                raw_request=payload.decode("latin-1", errors="replace")[:2000],
                raw_response=raw,
            ))
        else:
            findings.append(AgentFinding(
                title="HTTP/2 CL/DATA Probe — Single Plaintext Response (Inconclusive)",
                severity="low",
                cwe="CWE-444",
                attack_type="http2",
                evidence=(
                    "The malformed h2 frame (HEADERS content-length: 0 + DATA) "
                    "drew a single plaintext HTTP/1 response with no echo of the "
                    "smuggled marker path. This is consistent with the server "
                    "rejecting the frame (e.g. a plaintext 400) and is NOT proof "
                    "of a desync — reported as a surface marker only.\n\n"
                    f"Exchange:\n{raw}"
                ),
                confirmed=False,
                payload=f"h2 HEADERS(CL:0) + DATA[{marker_path}]",
                parameter="h2-frames",
                url=target.url,
                request_method="GET",
                bypass_validation=False,
                raw_request=payload.decode("latin-1", errors="replace")[:2000],
                raw_response=raw,
            ))
        return findings


from dast.ai.coordinator import Coordinator  # noqa: E402

Coordinator.register(Http2Agent)

"""
HTTP/HTTPS proxy server with full MITM interception.

HTTP:  forwards via httpx, records full req/resp in SessionStore.
HTTPS: on CONNECT, responds 200 then upgrades the browser connection to TLS
       using a per-domain cert signed by the Frieren DAST-AI CA. The decrypted request
       is forwarded to the real server over a separate TLS connection, response
       returned and recorded in SessionStore.

The CA cert must be installed once in the browser/OS trust store:
  - Path printed at startup
  - macOS:  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.dast-ai/ca.crt
  - Firefox: about:preferences#privacy → Certificates → Import
  - Chrome/Edge: uses OS trust store (macOS command above covers it)
"""

import asyncio
import ssl
import tempfile
import os
import time
from typing import Optional

import httpx

from dast.proxy.cert_authority import CertAuthority
from dast.proxy.session_store import SessionStore
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
    # httpx decompresses automatically — strip so browser doesn't double-decode
    "content-encoding",
    # Strip so origin always returns plain identity-encoded body
    "accept-encoding",
    # Strip so Firefox never upgrades to HTTP/3 (QUIC/UDP) which bypasses proxy
    "alt-svc",
}

# Internal headers injected by internal tools; stripped before forwarding to origin
_CRAWLER_HEADER  = "x-dast-crawler"
_SOURCE_HEADER   = "x-dast-source"    # "scanner" | "passive" — set by active_checks/_send
_PAYLOAD_HEADER  = "x-dast-payload"   # injected payload string for history display

# Strip from requests so the server always returns a full 200 instead of 304.
# Firefox may have a cached gzip-encoded version from before the proxy was
# active — a 304 would tell it to use that stale cache, causing decode errors.
_STRIP_FROM_REQUEST = {
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "if-match",
}


class ProxyServer:
    def __init__(
        self,
        store: SessionStore,
        ca: CertAuthority,
        settings=None,
        host: str = "127.0.0.1",
        port: int = 8080,
        intercept_store=None,
    ):
        self._store = store
        self._ca = ca
        self._settings = settings
        self._host = host
        self._port = port
        self._intercept_store = intercept_store
        self._server: Optional[asyncio.Server] = None
        # In-flight connection handler tasks. Tracked so stop() can cancel them:
        # long-lived CONNECT tunnels never close on their own, and on Python 3.12+
        # Server.wait_closed() blocks until every connection is gone — so without
        # this, Ctrl+C would hang forever and leave the port bound.
        self._conn_tasks: set[asyncio.Task] = set()

    async def start(self, max_port_attempts: int = 10) -> None:
        """
        Bind the proxy listener, falling back to the next port if the
        requested one is already in use (e.g. a previous run of this same
        proxy still shutting down, or another instance already running).

        The browser's manual-proxy setting is not auto-updated, so a silent
        fallback would break interception without any visible sign of why —
        the caller must surface the effective port (self._port after this
        returns) to the user loudly.
        """
        requested_port = self._port
        last_error: Optional[OSError] = None
        for attempt in range(max_port_attempts):
            port = requested_port + attempt
            try:
                self._server = await asyncio.start_server(
                    self._handle_connection, self._host, port
                )
                self._port = port
                if attempt > 0:
                    logger.warning(
                        "Proxy port was busy — fell back to next free port",
                        requested_port=requested_port, actual_port=port,
                    )
                else:
                    logger.info("Proxy listening", host=self._host, port=self._port)
                return
            except OSError as exc:
                last_error = exc
                logger.warning(
                    "Proxy port unavailable, trying next", port=port, error=str(exc)
                )
        raise OSError(
            f"Could not bind proxy to any port in range "
            f"{requested_port}-{requested_port + max_port_attempts - 1}"
        ) from last_error

    async def stop(self) -> None:
        if not self._server:
            return
        self._server.close()
        # Cancel any in-flight connections (open CONNECT tunnels would otherwise
        # keep wait_closed() blocked forever) before waiting, with a hard ceiling
        # so shutdown can never hang and strand the listening port.
        for task in list(self._conn_tasks):
            task.cancel()
        try:
            await asyncio.wait_for(self._server.wait_closed(), timeout=3.0)
        except (asyncio.TimeoutError, Exception) as exc:
            logger.warning("Proxy listener close timed out", error=str(exc))
        self._server = None

    # ------------------------------------------------------------------
    # Connection dispatcher
    # ------------------------------------------------------------------

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        current = asyncio.current_task()
        if current is not None:
            self._conn_tasks.add(current)
        try:
            request_line = await reader.readline()
            if not request_line:
                logger.debug("Empty request line", peer=peer)
                return

            line = request_line.decode("utf-8", errors="replace").strip()
            parts = line.split(" ", 2)
            if len(parts) < 2:
                logger.debug("Malformed request line", line=line, peer=peer)
                return

            method, target = parts[0], parts[1]
            headers = await _read_headers(reader)
            logger.info("Request received", method=method, target=target, peer=peer)

            if method == "CONNECT":
                await self._handle_connect(reader, writer, target, headers)
            else:
                await self._handle_http(reader, writer, method, target, headers)

        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError) as e:
            logger.debug("Connection closed by client", peer=peer, error=str(e))
        except Exception as e:
            logger.warning("Proxy connection error", peer=peer, error=str(e), exc_info=True)
        finally:
            if current is not None:
                self._conn_tasks.discard(current)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Plain HTTP
    # ------------------------------------------------------------------

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        url: str,
        headers: dict,
        scheme: str = "http",
    ) -> None:
        content_length = int(headers.get("content-length", 0))
        body = await reader.read(content_length) if content_length > 0 else None

        from urllib.parse import urlparse as _urlparse
        _path = _urlparse(url).path

        # ── Intercept mode ─────────────────────────────────────────────────
        # Pause the request and wait for user action (forward/drop/edit).
        # Only intercepts in-scope, non-scanner, non-hidden requests.
        _ic = self._intercept_store
        if (
            _ic is not None
            and _ic.enabled
            and method != "CONNECT"
            and headers.get(_SOURCE_HEADER) is None   # skip agent/scanner probes
            and headers.get(_CRAWLER_HEADER) is None  # skip SPA crawler
            and not (self._settings and self._settings.is_hidden(_path))
            and (not self._settings or self._settings.is_in_scope(url))
        ):
            _ic_host = _urlparse(url).netloc
            pending = _ic.add(method, url, _ic_host, _path, headers, body)
            try:
                await asyncio.wait_for(pending._event.wait(), timeout=300.0)
            except asyncio.TimeoutError:
                pending.action = "drop"

            if pending.action == "drop":
                logger.info("Intercepted request dropped", url=url)
                try:
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"content-type: text/plain\r\n"
                        b"content-length: 0\r\n"
                        b"connection: close\r\n\r\n"
                    )
                    await writer.drain()
                except Exception:
                    pass
                return

            # Apply user edits — may have changed method, url, headers, body
            method  = pending.method
            url     = pending.url
            headers = pending.headers
            body    = pending.body
            _path   = _urlparse(url).path
            logger.info("Intercepted request forwarded", url=url, modified=(pending.action == "forward_modified"))
            _pending_req = pending  # keep reference for response phase
        else:
            _pending_req = None
        # ── End request intercept ──────────────────────────────────────────

        # ── Match & Replace (request phase) ───────────────────────────────────
        if self._settings and headers.get(_SOURCE_HEADER) is None and headers.get(_CRAWLER_HEADER) is None:
            url, headers, body = self._settings.apply_to_request(url, headers, body)
            _path = _urlparse(url).path
        # ── End Match & Replace ────────────────────────────────────────────────

        hidden = self._settings and self._settings.is_hidden(_path)
        out_of_scope = self._settings and not self._settings.is_in_scope(url)
        # Internal x-dast-source header overrides the entry source tag
        dast_source = headers.get(_SOURCE_HEADER, None)
        # x-dast-crawler header marks entries from the SPA crawler
        is_crawler = headers.get(_CRAWLER_HEADER) is not None
        if hidden:
            entry_id = None
        elif out_of_scope:
            entry_id = self._store.new_entry(
                method, url, dict(headers), body, source="out-of-scope"
            )
        else:
            source = "crawler" if is_crawler else (dast_source or "proxy")
            entry_id = self._store.new_entry(
                method, url, dict(headers), body, source=source
            )

        forward_headers = {
            k: v for k, v in headers.items()
            if k not in _HOP_BY_HOP and k not in _STRIP_FROM_REQUEST
            and k not in (_CRAWLER_HEADER, _SOURCE_HEADER, _PAYLOAD_HEADER)  # strip internal tags before forwarding
        }
        start = time.time()
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=httpx.Timeout(connect=10, read=60, write=10, pool=10),
                verify=False,
            ) as client:
                async with client.stream(
                    method=method, url=url,
                    headers=forward_headers, content=body,
                ) as resp:
                    # SSE: pipe directly without buffering so the browser receives
                    # events in real time and feature-flag SDKs work correctly.
                    if "text/event-stream" in resp.headers.get("content-type", ""):
                        resp_header_pairs = [
                            (k, v) for k, v in resp.headers.multi_items()
                            if k.lower() not in _HOP_BY_HOP
                        ]
                        resp_header_pairs.append(("connection", "close"))
                        header_lines = "\r\n".join(f"{k}: {v}" for k, v in resp_header_pairs)
                        writer.write(
                            f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\r\n"
                            f"{header_lines}\r\n\r\n".encode()
                        )
                        await writer.drain()
                        async for chunk in resp.aiter_bytes():
                            if chunk:
                                writer.write(chunk)
                                await writer.drain()
                        return

                    body_bytes = await resp.aread()

            duration_ms = (time.time() - start) * 1000
            logger.debug("Response", method=method, url=url, status=resp.status_code, ms=round(duration_ms))

            resp_status = resp.status_code
            resp_reason = resp.reason_phrase

            # ── Match & Replace (response phase) ──────────────────────────────
            if self._settings and headers.get(_SOURCE_HEADER) is None:
                resp_headers_dict = dict(resp.headers.multi_items())
                resp_headers_dict, body_bytes = self._settings.apply_to_response(resp_headers_dict, body_bytes)
            # ── End Match & Replace ────────────────────────────────────────────

            # ── Response intercept phase ───────────────────────────────────────
            if (
                _ic is not None
                and _ic.enabled
                and _ic.intercept_response
                and _pending_req is not None
                and headers.get(_SOURCE_HEADER) is None
                and headers.get(_CRAWLER_HEADER) is None
            ):
                resp_headers_for_ic = dict(resp.headers.multi_items())
                pending_resp = _ic.begin_response_intercept(
                    _pending_req, resp_status, resp_headers_for_ic, body_bytes
                )
                try:
                    await asyncio.wait_for(pending_resp._resp_event.wait(), timeout=300.0)
                except asyncio.TimeoutError:
                    pending_resp.resp_action = "forward"

                if pending_resp.resp_action != "drop":
                    resp_status  = pending_resp.resp_status or resp_status
                    resp_reason  = "OK"
                    body_bytes   = pending_resp.resp_body or body_bytes
                    # Rebuild resp headers from the (possibly edited) dict
                    resp.headers._list = [  # type: ignore[attr-defined]
                        (k.encode(), v.encode())
                        for k, v in pending_resp.resp_headers.items()
                    ]
                    logger.info("Intercepted response forwarded", url=url, modified=(pending_resp.resp_action == "forward_modified"))
            # ── End response intercept ─────────────────────────────────────────

            if entry_id:
                # Build headers dict preserving multiple set-cookie values as a list
                # so the session store cookie jar sees all of them.
                resp_headers_for_store: dict = {}
                set_cookies = []
                for k, v in resp.headers.multi_items():
                    if k.lower() == "set-cookie":
                        set_cookies.append(v)
                    else:
                        resp_headers_for_store[k.lower()] = v
                if set_cookies:
                    resp_headers_for_store["set-cookie"] = set_cookies
                self._store.complete_entry(
                    entry_id,
                    status=resp_status,
                    response_headers=resp_headers_for_store,
                    response_body=body_bytes,
                    duration_ms=duration_ms,
                )

            # Use multi_items() to preserve duplicate headers (e.g. Set-Cookie).
            # A plain dict comprehension would collapse them, dropping all but
            # the last — which breaks CSRF tokens and CloudFront cookies.
            # Always strip content-length: httpx decompresses the body so the
            # original length is wrong, and we append our own correct value below.
            resp_header_pairs = [
                (k, v) for k, v in resp.headers.multi_items()
                if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"
            ]
            # 304/204/1xx must not carry a body or content-length
            no_body = resp_status in (204, 304) or 100 <= resp_status < 200
            if not no_body:
                resp_header_pairs.append(("content-length", str(len(body_bytes))))
            resp_header_pairs.append(("connection", "close"))
            header_lines = "\r\n".join(f"{k}: {v}" for k, v in resp_header_pairs)
            writer.write(
                f"HTTP/1.1 {resp_status} {resp_reason}\r\n"
                f"{header_lines}\r\n\r\n".encode()
            )
            if not no_body:
                writer.write(body_bytes)
            await writer.drain()

        except Exception as e:
            logger.debug("HTTP forward error", url=url, error=str(e))
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n")
                await writer.drain()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # HTTPS MITM via CONNECT
    # ------------------------------------------------------------------

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
        headers: dict,
    ) -> None:
        host = target.split(":")[0]
        try:
            port = int(target.split(":")[1]) if ":" in target else 443
        except ValueError:
            port = 443

        logger.info("CONNECT tunnel", host=host, port=port)

        # Bypassed hosts: raw TCP pipe, no MITM
        if self._settings and self._settings.is_bypassed(host):
            logger.debug("Bypassing host", host=host)
            await self._tcp_tunnel(reader, writer, host, port)
            return

        # Acknowledge the CONNECT tunnel
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        logger.debug("CONNECT 200 sent", host=host)

        # Pause reading so the browser's TLS ClientHello (sent right after the
        # 200) stays in the kernel buffer during the executor call.  start_tls()
        # internally resumes reading, which delivers those bytes to SSLProtocol.
        writer.transport.pause_reading()

        # Build per-domain SSL context (CPU-bound, run in thread pool).
        cert_pem, key_pem = self._ca.get_leaf_cert(host)
        loop = asyncio.get_running_loop()
        ssl_ctx = await loop.run_in_executor(
            None, _build_server_ssl_ctx, cert_pem, key_pem
        )
        logger.debug("SSL context ready", host=host)

        # Upgrade the existing TCP transport to TLS in-place via start_tls().
        # A fresh StreamReaderProtocol+StreamReader pair receives decrypted bytes.
        # start_tls() returns the application-level SSL transport we write through.
        tls_reader = asyncio.StreamReader()
        tls_proto = _TLSReaderProtocol(tls_reader)
        try:
            logger.info("Starting TLS handshake", host=host)
            ssl_transport = await loop.start_tls(
                writer.transport,
                tls_proto,
                ssl_ctx,
                server_side=True,
                ssl_handshake_timeout=15,
            )
            logger.info("TLS handshake complete", host=host)
        except Exception as e:
            logger.warning("TLS handshake failed", host=host, error=str(e))
            return

        tls_writer = asyncio.StreamWriter(ssl_transport, tls_proto, tls_reader, loop)

        try:
            await self._handle_https_session(tls_reader, tls_writer, host, port)
        finally:
            try:
                tls_writer.close()
                await tls_writer.wait_closed()
            except Exception:
                pass

    async def _handle_https_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """Handle one or more HTTP requests inside a decrypted TLS tunnel."""
        request_count = 0
        while True:
            try:
                request_line = await asyncio.wait_for(reader.readline(), timeout=30)
            except asyncio.TimeoutError:
                logger.debug("HTTPS session timeout", host=host, requests=request_count)
                break
            except Exception as e:
                logger.debug("HTTPS session read error", host=host, error=str(e))
                break

            if not request_line or request_line == b"\r\n":
                logger.debug("HTTPS session closed", host=host, requests=request_count)
                break

            line = request_line.decode("utf-8", errors="replace").strip()
            parts = line.split(" ", 2)
            if len(parts) < 2:
                logger.debug("Malformed HTTPS request line", host=host, line=line)
                break

            method, path = parts[0], parts[1]
            headers = await _read_headers(reader)
            request_count += 1

            scheme = "https"
            url = f"{scheme}://{host}{':' + str(port) if port != 443 else ''}{path}"
            logger.info("HTTPS request", method=method, url=url)

            await self._handle_http(reader, writer, method, url, headers, scheme="https")

            conn = headers.get("connection", "").lower()
            if conn == "close" or parts[2:] == ["HTTP/1.0"]:
                break

    async def _tcp_tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """Raw TCP pipe for bypassed hosts — no MITM, no recording."""
        try:
            rem_reader, rem_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            logger.debug("Bypass tunnel connect failed", host=host, error=str(e))
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n")
            await writer.drain()
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        async def pipe(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            pipe(reader, rem_writer),
            pipe(rem_reader, writer),
            return_exceptions=True,
        )
        try:
            rem_writer.close()
            await rem_writer.wait_closed()
        except Exception:
            pass


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

async def _read_headers(reader: asyncio.StreamReader) -> dict:
    headers: dict = {}
    while True:
        hline = await reader.readline()
        if hline in (b"\r\n", b"\n", b""):
            break
        if b":" in hline:
            k, _, v = hline.decode("utf-8", errors="replace").partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


def _build_server_ssl_ctx(cert_pem: bytes, key_pem: bytes) -> ssl.SSLContext:
    """Build an SSLContext for the proxy-to-browser TLS connection."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Force HTTP/1.1 — we don't implement HTTP/2 framing, so if the browser
    # negotiates h2 via ALPN it would send binary frames we can't parse.
    ctx.set_alpn_protocols(["http/1.1"])
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert_pem)
        cert_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(key_pem)
        key_path = kf.name
    try:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)
    return ctx


class _TLSReaderProtocol(asyncio.StreamReaderProtocol):
    """StreamReaderProtocol that returns None from eof_received().

    asyncio.StreamReaderProtocol.eof_received() returns True, which tells the
    SSL layer to keep the transport open after the peer sends close_notify.
    The SSL layer logs a warning when this happens.  Returning None (falsy)
    lets SSL close the transport normally.
    """

    def eof_received(self):
        super().eof_received()
        return None


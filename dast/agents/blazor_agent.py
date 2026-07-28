"""
Blazor security agent — targets vulnerabilities specific to Blazor WebAssembly
and Blazor Server applications.

Attack surface:
  WASM-specific:
    - Assembly enumeration via blazor.boot.json
    - Downloadable .NET DLL exposure (MZ header confirmation)
    - appsettings.json shipped to browser (client-side secrets)
    - Route constraint bypass (constraints validated client-side only)
    - MarkupString / RenderFragment XSS (developer bypass of Blazor encoding)

  Server-specific:
    - SignalR hub method enumeration (/_blazor endpoint)
    - Unauthenticated hub negotiation (/_blazor/negotiate without auth)
    - Hub invocation without [Authorize] (missing attribute on component/hub)
    - Blazor circuit exhaustion probe (concurrent negotiate requests)

  Both:
    - Exposed debug / development build artefacts (.pdb files, debug boot config)
    - CascadingAuthenticationState bypass (passing auth state as parameter)
    - Component route parameter injection (IDOR via route segment)
    - SSRF via hub invocation targeting internal hosts
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING, List, Optional
from urllib.parse import urlparse, urlunparse

from dast.ai.agent_base import AgentFinding, VulnAgent
from dast.payloads.loader import get_payloads
from dast.proxy.plugin_manager import log_event
from dast.scanners.active_checks import _fmt_http_pair, _send
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    import httpx
    from dast.scanners.active_checks import CheckTarget
    from dast.scanners.collaborator import CollaboratorService

logger = get_logger(__name__)

# SignalR text-protocol record separator
_SIGNALR_SEP = "\x1e"

# MZ header — confirms a .NET PE assembly
_MZ_HEADER = b"\x4d\x5a"

# Patterns that confirm a Blazor application
_BLAZOR_WASM_RE = re.compile(
    r"_framework/blazor\.webassembly\.js|blazor\.boot\.json",
    re.IGNORECASE,
)
_BLAZOR_SERVER_RE = re.compile(
    r"_framework/blazor\.server\.js|/_blazor",
    re.IGNORECASE,
)

# SignalR negotiate success marker
_NEGOTIATE_RE = re.compile(r'"connectionId"\s*:', re.IGNORECASE)

# Sensitive fields in JSON responses from hub methods
_SENSITIVE_RE = re.compile(
    r'"(password|secret|token|apikey|connectionstring|privatekey|accesskey)"'
    r'\s*:\s*"([^"]{4,})"',
    re.IGNORECASE,
)

# Blazor exception patterns in hub error responses
_EXCEPTION_RE = re.compile(
    r"Exception|at\s+\w+\.\w+\.\w+|Object\s+reference|NullReferenceException"
    r"|ArgumentException|InvalidOperationException",
    re.IGNORECASE,
)

# Maximum DLL size to probe (skip extremely large files)
_MAX_DLL_SIZE = 20_000_000  # 20 MB


def _base_url(url: str) -> str:
    """Return scheme + host from a URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _make_url(base: str, path: str) -> str:
    """Join base URL with an absolute path."""
    base_parsed = urlparse(base)
    return urlunparse(base_parsed._replace(path=path, query="", fragment=""))


def _build_signalr_message(target: str, arguments: list) -> bytes:
    """Encode a SignalR text-protocol type-1 (invocation) message."""
    msg = json.dumps({
        "type": 1,
        "target": target,
        "arguments": arguments,
        "invocationId": "dast-1",
    })
    return (msg + _SIGNALR_SEP).encode("utf-8")


def _build_signalr_handshake() -> bytes:
    """Encode the SignalR text-protocol handshake request."""
    return (json.dumps({"protocol": "json", "version": 1}) + _SIGNALR_SEP).encode()


async def _get_html_body(
    client: "httpx.AsyncClient",
    target: "CheckTarget",
) -> Optional[str]:
    """Fetch the base URL and return decoded body text, or None on error."""
    try:
        resp = await _send(client, "GET", target.url, target.headers, None)
        if resp and resp.status_code == 200:
            return resp.text
    except Exception as exc:
        logger.debug("Blazor: failed to fetch base HTML", url=target.url, error=str(exc))
    return None


class BlazorAgent(VulnAgent):
    name = "Blazor Agent"
    attack_type = "blazor"
    description = (
        "Tests for vulnerabilities specific to Blazor WebAssembly and Blazor "
        "Server: DLL exposure, appsettings secrets, SignalR hub enumeration, "
        "unauthenticated circuit negotiation, route injection, and debug artefacts."
    )

    async def run(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        collaborator: Optional["CollaboratorService"] = None,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        base = _base_url(target.url)

        log_event(
            "blazor", "info",
            f"Blazor agent started — {target.method} {target.url}",
            url=target.url, source="agent",
        )

        # Determine Blazor variant from existing app profile hint or probe base URL
        blazor_type = await self._detect_variant(target, client, base)
        if not blazor_type:
            logger.debug("Blazor agent: no Blazor detected, skipping", url=target.url)
            return []

        logger.info("Blazor agent: variant detected", variant=blazor_type, url=target.url)

        # Run probes in parallel for efficiency
        probe_results = await asyncio.gather(
            self._probe_boot_manifest(target, client, base, blazor_type),
            self._probe_config_files(target, client, base),
            self._probe_signalr_negotiate(target, client, base, blazor_type),
            self._probe_debug_artefacts(target, client, base, blazor_type),
            self._probe_route_injection(target, client),
            self._probe_signalr_token_in_url(target),
            self._probe_cswsh(target, client, base, blazor_type),
            self._probe_compression_misconfiguration(target, client, base, blazor_type),
            return_exceptions=True,
        )

        for result in probe_results:
            if isinstance(result, Exception):
                logger.warning("Blazor probe error", error=str(result))
            elif isinstance(result, list):
                findings.extend(result)

        # SignalR hub enumeration + circuit fuzzing only for Server variant
        if blazor_type in ("server", "unknown"):
            hub_findings, fuzz_findings = await asyncio.gather(
                self._probe_signalr_hub(target, client, base),
                self._probe_circuit_fuzzer(target, client, base, blazor_type),
                return_exceptions=True,
            )
            if isinstance(hub_findings, list):
                findings.extend(hub_findings)
            if isinstance(fuzz_findings, list):
                findings.extend(fuzz_findings)

        logger.info(
            "Blazor agent complete",
            url=target.url,
            variant=blazor_type,
            findings=len(findings),
        )
        return findings

    # ── Variant detection ─────────────────────────────────────────────────

    async def _detect_variant(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
    ) -> Optional[str]:
        """
        Detect Blazor WASM vs Server vs neither from:
          1. app_profile_hint (already synthesised by AppContextWorker)
          2. body of the current response (if HTML)
          3. Probe the base URL for fingerprints
        """
        hint = (target.app_profile_hint or "").lower()
        if "blazor" in hint:
            if "wasm" in hint or "webassembly" in hint:
                return "wasm"
            if "server" in hint:
                return "server"
            return "unknown"

        # Check if the current request body looks like Blazor
        html = await _get_html_body(client, target)
        if html:
            if _BLAZOR_WASM_RE.search(html):
                return "wasm"
            if _BLAZOR_SERVER_RE.search(html):
                return "server"

        # Check if the path itself is a Blazor framework resource
        path = urlparse(target.url).path.lower()
        if "_framework" in path or "_blazor" in path:
            return "unknown"

        return None

    # ── Boot manifest + DLL enumeration ──────────────────────────────────

    async def _probe_boot_manifest(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
        blazor_type: str,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        if blazor_type not in ("wasm", "unknown"):
            return findings

        manifest_url = _make_url(base, "/_framework/blazor.boot.json")
        resp = await _send(client, "GET", manifest_url, target.headers, None)
        if not resp or resp.status_code != 200:
            return findings

        raw_req, raw_resp = _fmt_http_pair(resp)
        logger.info("Blazor boot manifest accessible", url=manifest_url)
        log_event(
            "blazor", "finding",
            f"blazor.boot.json accessible — assembly list exposed",
            url=manifest_url, finding="Blazor Boot Manifest", source="agent",
        )

        # Parse manifest to find assembly names.
        # .NET 6-7: resources.assembly keys end with .dll
        # .NET 8+:  Webcil format — resources.assembly keys end with .wasm
        #           The underlying content is still a .NET PE assembly (not native WASM).
        dll_names: List[str] = []
        wasm_names: List[str] = []
        dotnet_version: str = "unknown"
        try:
            manifest = resp.json()
            resources = manifest.get("resources", {})
            assembly_dict = (
                resources.get("assembly", {})
                or resources.get("lazyAssembly", {})
                or {}
            )
            for k in assembly_dict.keys():
                if k.endswith(".dll"):
                    dll_names.append(k)
                elif k.endswith(".wasm") and not k.startswith("dotnet"):
                    # Webcil-wrapped assemblies in .NET 8+ have .wasm extension
                    # but are distinguishable from the runtime by not starting with "dotnet"
                    wasm_names.append(k)
            # Detect .NET version hint from config key
            config = manifest.get("config", [])
            dotnet_version = "8+" if wasm_names and not dll_names else ("6-7" if dll_names else "unknown")
        except Exception:
            pass

        all_assemblies = dll_names + wasm_names
        format_note = (
            "Webcil-wrapped .wasm (decompilable, .NET 8+ format)" if wasm_names
            else ".dll (directly decompilable)" if dll_names
            else "unknown format"
        )

        findings.append(AgentFinding(
            title="Blazor Boot Manifest Exposes Assembly List",
            severity="medium",
            cwe="CWE-200",
            attack_type="blazor",
            evidence=(
                f"blazor.boot.json is accessible and lists {len(all_assemblies)} .NET assemblies "
                f"({format_note}). "
                f"All assemblies can be downloaded and decompiled with dnSpy/ILSpy to recover "
                f"source code, hardcoded secrets, and internal API endpoints."
                + (f" Samples: {', '.join(all_assemblies[:8])}{'...' if len(all_assemblies) > 8 else ''}" if all_assemblies else "")
            ),
            payload="GET /_framework/blazor.boot.json",
            parameter="",
            url=manifest_url,
            request_method="GET",
            bypass_validation=True,
            raw_request=raw_req,
            raw_response=raw_resp[:4000],
        ))

        # Probe up to 3 named assemblies to confirm they are downloadable
        if all_assemblies:
            download_findings = await self._confirm_dll_downloads(
                target, client, base, all_assemblies[:3]
            )
            findings.extend(download_findings)

        return findings

    async def _confirm_dll_downloads(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
        dll_names: List[str],
    ) -> List[AgentFinding]:
        """
        Confirm that named assemblies are downloadable.

        Accepts both:
          - .dll files  (.NET 6-7): confirmed by MZ PE header (0x4D5A)
          - .wasm files (.NET 8+ Webcil): confirmed by WASM magic bytes (0x00 0x61 0x73 0x6D)
            or the 4-byte Webcil header ('WebC' = 0x57 0x65 0x62 0x43)
        """
        # WASM magic: \0asm
        _WASM_MAGIC = b"\x00\x61\x73\x6d"
        # Webcil header prefix
        _WEBCIL_MAGIC = b"\x57\x65\x62\x43"

        findings: List[AgentFinding] = []
        for dll_name in dll_names:
            dll_url = _make_url(base, f"/_framework/{dll_name}")
            try:
                resp = await _send(client, "GET", dll_url, target.headers, None)
            except Exception:
                continue
            if not resp or resp.status_code != 200:
                continue
            content = resp.content
            is_pe = content[:2] == _MZ_HEADER
            is_wasm = content[:4] == _WASM_MAGIC or content[:4] == _WEBCIL_MAGIC
            if not (is_pe or is_wasm):
                continue
            fmt = "Webcil (.NET 8+ assembly)" if is_wasm else ".NET PE assembly"

            raw_req, raw_resp = _fmt_http_pair(resp)
            logger.warning(
                "Blazor DLL downloadable", dll=dll_name, url=dll_url,
                size_kb=len(content) // 1024,
            )
            log_event(
                "blazor", "finding",
                f"Downloadable .NET assembly: {dll_name} ({len(content)//1024} KB)",
                url=dll_url, finding=".NET DLL Exposure", source="agent",
            )
            findings.append(AgentFinding(
                title=f".NET Assembly Downloadable: {dll_name}",
                severity="high",
                cwe="CWE-200",
                attack_type="blazor",
                evidence=(
                    f"Assembly {dll_name} ({len(content) // 1024} KB) is downloadable "
                    f"({fmt}). Decompile with dnSpy/ILSpy to recover source code and secrets."
                ),
                payload=f"GET /_framework/{dll_name}",
                parameter="",
                url=dll_url,
                request_method="GET",
                bypass_validation=True,
                raw_request=raw_req,
                raw_response=f"HTTP/1.1 200\ncontent-length: {len(content)}\n\n[binary: {len(content)} bytes, {fmt} header confirmed]",
            ))
            # One confirmed download is sufficient evidence
            break

        return findings

    # ── appsettings.json exposure ─────────────────────────────────────────

    async def _probe_config_files(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        config_paths = get_payloads("blazor", "config_paths")
        for path in config_paths:
            config_url = _make_url(base, path)
            resp = await _send(client, "GET", config_url, target.headers, None)
            if not resp or resp.status_code != 200:
                continue

            try:
                body = resp.text
            except Exception:
                continue

            # Only process JSON-like responses
            if not body.strip().startswith("{"):
                continue

            raw_req, raw_resp = _fmt_http_pair(resp)

            # Look for sensitive keys
            matches = _SENSITIVE_RE.findall(body)
            if matches:
                keys_found = list({k for k, _ in matches})
                logger.warning(
                    "Blazor config with sensitive keys",
                    path=path, keys=keys_found,
                )
                log_event(
                    "blazor", "finding",
                    f"Sensitive keys in Blazor config {path}: {', '.join(keys_found)}",
                    url=config_url, finding="Blazor Config Secret Exposure", source="agent",
                )
                findings.append(AgentFinding(
                    title="Blazor Configuration File Exposes Secrets to Browser",
                    severity="critical",
                    cwe="CWE-200",
                    attack_type="blazor",
                    evidence=(
                        f"Configuration file at {path} is accessible from the browser "
                        f"and contains sensitive keys: {', '.join(keys_found)}. "
                        f"These values are exposed to any visitor."
                    ),
                    payload=f"GET {path}",
                    parameter="",
                    url=config_url,
                    request_method="GET",
                    bypass_validation=True,
                    raw_request=raw_req,
                    raw_response=raw_resp[:4000],
                ))
            else:
                # Config accessible but no obvious secrets — lower severity
                logger.info("Blazor config file accessible", path=path, url=config_url)
                findings.append(AgentFinding(
                    title="Blazor Configuration File Accessible from Browser",
                    severity="medium",
                    cwe="CWE-200",
                    attack_type="blazor",
                    evidence=(
                        f"Configuration file at {path} is accessible. "
                        f"No obvious secrets detected, but the file reveals application "
                        f"settings, environment names, and service endpoints."
                    ),
                    payload=f"GET {path}",
                    parameter="",
                    url=config_url,
                    request_method="GET",
                    bypass_validation=False,
                    raw_request=raw_req,
                    raw_response=raw_resp[:4000],
                ))
            # Stop after first confirmed config file
            break

        return findings

    # ── SignalR negotiate probe ───────────────────────────────────────────

    async def _probe_signalr_negotiate(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
        blazor_type: str,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        negotiate_url = _make_url(base, "/_blazor/negotiate?negotiateVersion=1")
        resp = await _send(client, "POST", negotiate_url, target.headers, None)
        if not resp:
            return findings

        if resp.status_code not in (200, 400) or not _NEGOTIATE_RE.search(resp.text):
            return findings

        # Accessible negotiate endpoint — check if it requires auth
        stripped_headers = {
            k: v for k, v in target.headers.items()
            if k.lower() not in ("authorization", "cookie", "x-auth-token", "x-api-key")
        }
        resp_unauth = await _send(
            client, "POST", negotiate_url, stripped_headers, None
        )

        raw_req, raw_resp = _fmt_http_pair(resp)

        if resp_unauth and _NEGOTIATE_RE.search(resp_unauth.text):
            # Negotiate succeeds without auth headers
            logger.warning(
                "Blazor SignalR negotiate accessible without auth",
                url=negotiate_url,
            )
            log_event(
                "blazor", "finding",
                "SignalR negotiate accessible unauthenticated",
                url=negotiate_url,
                finding="Unauthenticated SignalR Negotiate",
                source="agent",
            )
            probe_req, probe_resp = _fmt_http_pair(resp_unauth)
            findings.append(AgentFinding(
                title="Blazor SignalR Hub Negotiate Accessible Without Authentication",
                severity="high",
                cwe="CWE-306",
                attack_type="blazor",
                evidence=(
                    "The SignalR negotiate endpoint (/_blazor/negotiate) returns a "
                    "connectionId without authentication headers. An attacker can "
                    "establish a WebSocket circuit and attempt to invoke hub methods."
                ),
                payload="POST /_blazor/negotiate (no auth headers)",
                parameter="Authorization",
                url=negotiate_url,
                request_method="POST",
                bypass_validation=True,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
                probe_request=probe_req,
                probe_response=probe_resp[:2000],
            ))
        else:
            # Negotiate requires auth — still note it as accessible
            findings.append(AgentFinding(
                title="Blazor SignalR Hub Negotiate Endpoint Accessible",
                severity="low",
                cwe="CWE-284",
                attack_type="blazor",
                evidence=(
                    "The SignalR negotiate endpoint (/_blazor/negotiate) is accessible "
                    "and returned a connectionId. Authentication appears to be required. "
                    "Verify that individual hub methods enforce [Authorize] server-side."
                ),
                payload="POST /_blazor/negotiate",
                parameter="",
                url=negotiate_url,
                request_method="POST",
                bypass_validation=False,
                raw_request=raw_req,
                raw_response=raw_resp[:2000],
            ))

        return findings

    # ── SignalR hub method enumeration ────────────────────────────────────

    async def _probe_signalr_hub(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
    ) -> List[AgentFinding]:
        """
        Send SignalR handshake + method invocations directly over HTTP POST
        (SignalR fallback transport — longPolling) to enumerate hub methods
        and detect missing [Authorize] on server-side hub methods.

        Note: full WebSocket enumeration requires a WS client. This probe
        uses the HTTP long-polling fallback which is always available.
        """
        findings: List[AgentFinding] = []

        # Attempt hub HTTP long-poll — POST to /_blazor with connection ID
        negotiate_url = _make_url(base, "/_blazor/negotiate?negotiateVersion=1")
        neg_resp = await _send(client, "POST", negotiate_url, target.headers, None)
        if not neg_resp or not _NEGOTIATE_RE.search(neg_resp.text):
            return findings

        try:
            connection_id = neg_resp.json().get("connectionId", "")
        except Exception:
            return findings

        if not connection_id:
            return findings

        hub_url = _make_url(base, f"/_blazor?id={connection_id}")
        headers = dict(target.headers)
        headers["content-type"] = "text/plain;charset=UTF-8"

        # Send handshake
        await _send(client, "POST", hub_url, headers, _build_signalr_handshake().decode())

        # Enumerate hub methods with payloads from YAML
        method_payloads = get_payloads("blazor", "signalr_invoke")
        for payload_str in method_payloads[:6]:
            try:
                payload_obj = json.loads(payload_str)
            except Exception:
                continue

            method_name = payload_obj.get("target", "")
            message_bytes = _build_signalr_message(
                method_name, payload_obj.get("arguments", [])
            )
            resp = await _send(
                client, "POST", hub_url, headers, message_bytes.decode("utf-8", errors="replace")
            )
            if not resp:
                continue

            body = resp.text
            if not body:
                continue

            # Look for successful type-3 completion with data
            for segment in body.split(_SIGNALR_SEP):
                if not segment.strip():
                    continue
                try:
                    msg = json.loads(segment)
                except Exception:
                    continue

                if msg.get("type") == 3:
                    error = msg.get("error", "")
                    result = msg.get("result")

                    if error and _EXCEPTION_RE.search(error):
                        log_event(
                            "blazor", "finding",
                            f"SignalR hub method '{method_name}' returned .NET exception",
                            url=hub_url, finding="SignalR Exception Disclosure", source="agent",
                        )
                        findings.append(AgentFinding(
                            title=f"SignalR Hub Exception Disclosure: {method_name}",
                            severity="medium",
                            cwe="CWE-209",
                            attack_type="blazor",
                            evidence=(
                                f"Hub method '{method_name}' returned a .NET exception: "
                                f"{error[:400]}"
                            ),
                            payload=payload_str,
                            parameter="SignalR target",
                            url=hub_url,
                            request_method="POST",
                            bypass_validation=False,
                        ))

                    elif result is not None:
                        result_str = json.dumps(result)
                        sensitive = _SENSITIVE_RE.findall(result_str)
                        if sensitive:
                            keys_found = list({k for k, _ in sensitive})
                            log_event(
                                "blazor", "finding",
                                f"SignalR hub method '{method_name}' returned sensitive data",
                                url=hub_url, finding="SignalR Sensitive Data", source="agent",
                            )
                            findings.append(AgentFinding(
                                title=f"SignalR Hub Returns Sensitive Data: {method_name}",
                                severity="high",
                                cwe="CWE-200",
                                attack_type="blazor",
                                evidence=(
                                    f"Hub method '{method_name}' returned sensitive fields "
                                    f"without requiring authorization: {', '.join(keys_found)}"
                                ),
                                payload=payload_str,
                                parameter="SignalR target",
                                url=hub_url,
                                request_method="POST",
                                bypass_validation=True,
                            ))
                        else:
                            logger.debug(
                                "SignalR method responded", method=method_name, url=hub_url
                            )

        return findings

    # ── Debug artefacts ───────────────────────────────────────────────────

    async def _probe_debug_artefacts(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
        blazor_type: str,
    ) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        if blazor_type not in ("wasm", "unknown"):
            return findings

        # Probe for .pdb symbol files alongside .dll files
        # Boot manifest probe reveals assembly names; here we use known patterns
        pdb_candidates = [
            "/_framework/System.Private.CoreLib.pdb",
            "/_framework/Microsoft.AspNetCore.Components.pdb",
        ]
        for pdb_path in pdb_candidates:
            pdb_url = _make_url(base, pdb_path)
            resp = await _send(client, "GET", pdb_url, target.headers, None)
            if resp and resp.status_code == 200 and len(resp.content) > 100:
                raw_req, raw_resp = _fmt_http_pair(resp)
                logger.warning("Blazor PDB symbol file exposed", url=pdb_url)
                log_event(
                    "blazor", "finding",
                    f"PDB symbol file accessible: {pdb_path}",
                    url=pdb_url, finding="PDB Symbol Exposure", source="agent",
                )
                findings.append(AgentFinding(
                    title="Blazor PDB Debug Symbol File Exposed",
                    severity="medium",
                    cwe="CWE-200",
                    attack_type="blazor",
                    evidence=(
                        f"PDB symbol file at {pdb_path} is accessible ({len(resp.content)} bytes). "
                        f"Symbol files expose exact source file paths, line numbers, "
                        f"variable names, and enable precise stack trace reconstruction."
                    ),
                    payload=f"GET {pdb_path}",
                    parameter="",
                    url=pdb_url,
                    request_method="GET",
                    bypass_validation=True,
                    raw_request=raw_req,
                    raw_response=f"HTTP/1.1 200\ncontent-length: {len(resp.content)}\n\n[binary PDB data]",
                ))
                break

        return findings

    # ── Route parameter injection ─────────────────────────────────────────

    async def _probe_route_injection(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
    ) -> List[AgentFinding]:
        """
        Test Blazor route parameters for server-side validation bypass.

        Blazor WASM validates route constraints ({id:int}, {guid:guid}) on the
        client side only. If the underlying API endpoint does not re-validate
        on the server, injecting unexpected values can cause IDOR or crashes.
        """
        findings: List[AgentFinding] = []

        # Only probe paths that look like Blazor component routes
        # (path segments with an ID-like segment)
        path = urlparse(target.url).path
        path_segments = [s for s in path.split("/") if s]
        if not path_segments:
            return findings

        # Look for numeric or GUID path segments to probe
        id_segment_re = re.compile(
            r"^(\d{1,18}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
            re.IGNORECASE,
        )

        route_payloads = get_payloads("blazor", "route_injection")
        baseline_resp = await _send(client, target.method, target.url, target.headers, target.body)
        if not baseline_resp:
            return findings

        for i, segment in enumerate(path_segments):
            if not id_segment_re.match(segment):
                continue

            for payload in route_payloads[:5]:
                new_segments = list(path_segments)
                new_segments[i] = payload
                new_path = "/" + "/".join(new_segments)
                probe_url = urlunparse(
                    urlparse(target.url)._replace(path=new_path)
                )
                resp = await _send(client, target.method, probe_url, target.headers, target.body)
                if not resp:
                    continue

                # A 200 with non-trivial body when a path-traversal payload was injected
                # suggests the server did not validate the route constraint
                if (
                    resp.status_code == 200
                    and len(resp.text) > 50
                    and resp.status_code == baseline_resp.status_code
                    and abs(len(resp.text) - len(baseline_resp.text)) > 50
                ):
                    raw_req, raw_resp = _fmt_http_pair(resp)
                    findings.append(AgentFinding(
                        title="Blazor Route Constraint Bypass (Server-Side Validation Missing)",
                        severity="medium",
                        cwe="CWE-20",
                        attack_type="blazor",
                        evidence=(
                            f"Route segment '{segment}' replaced with '{payload}' returned "
                            f"HTTP {resp.status_code} with {len(resp.text)} chars "
                            f"(baseline: {len(baseline_resp.text)} chars). "
                            f"Server does not re-validate route constraints."
                        ),
                        payload=payload,
                        parameter=f"route:{segment}",
                        url=probe_url,
                        request_method=target.method,
                        bypass_validation=False,
                        raw_request=raw_req,
                        raw_response=raw_resp[:4000],
                    ))
                    break

        return findings

    # ── SignalR access_token in URL ───────────────────────────────────────

    async def _probe_signalr_token_in_url(
        self,
        target: "CheckTarget",
    ) -> List[AgentFinding]:
        """
        Detect SignalR access tokens transmitted in URL query strings.

        When SignalR uses WebSocket or SSE transport with JWT authentication,
        the bearer token is appended as ?access_token=<jwt> in the WebSocket
        upgrade URL. ASP.NET Core logs all request URLs by default — the token
        is written to server logs in cleartext.

        Detection: look for access_token in the current target URL (proxy
        already captured it) or in the request headers we received.
        """
        findings: List[AgentFinding] = []

        from urllib.parse import parse_qs
        parsed = urlparse(target.url)
        qs = parse_qs(parsed.query)

        token_value = None
        if "access_token" in qs:
            token_value = qs["access_token"][0]

        if not token_value:
            return findings

        # Confirm it looks like a JWT (three base64url segments)
        _JWT_RE = re.compile(
            r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
        )
        is_jwt = bool(_JWT_RE.match(token_value))

        logger.warning(
            "SignalR access_token in URL", url=target.url, is_jwt=is_jwt
        )
        log_event(
            "blazor", "finding",
            "SignalR bearer token exposed in URL query string",
            url=target.url, finding="SignalR Token in URL", source="agent",
        )
        findings.append(AgentFinding(
            title="SignalR Bearer Token Exposed in URL Query String",
            severity="high",
            cwe="CWE-598",
            attack_type="blazor",
            evidence=(
                f"The SignalR WebSocket upgrade request contains an access_token "
                f"parameter in the URL query string{' (JWT confirmed)' if is_jwt else ''}. "
                f"ASP.NET Core logs all request URLs by default — this token is written "
                f"to server logs, Nginx/IIS access logs, and any proxy sitting in front "
                f"of the application. An attacker with log access can extract and replay "
                f"the token."
            ),
            payload=f"access_token={token_value[:30]}...",
            parameter="access_token",
            url=target.url,
            request_method=target.method,
            bypass_validation=True,
        ))
        return findings

    # ── Cross-site WebSocket hijacking (CSWSH) ────────────────────────────

    async def _probe_cswsh(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
        blazor_type: str,
    ) -> List[AgentFinding]:
        """
        Test for Cross-Site WebSocket Hijacking (CSWSH) on the SignalR hub.

        CORS protections do not apply to WebSocket upgrade requests — browsers
        send cookies with WebSocket upgrades regardless of the Origin header.
        If the server does not validate the Origin header on the negotiate
        endpoint, an attacker can lure a victim to a malicious page that
        connects to the hub and reads hub messages using the victim's session.

        Probe: send a negotiate POST with a clearly attacker-controlled Origin
        and check whether the server issues a connectionId (accepts any origin).
        """
        findings: List[AgentFinding] = []

        if blazor_type not in ("server", "unknown"):
            return findings

        negotiate_url = _make_url(base, "/_blazor/negotiate?negotiateVersion=1")
        attacker_origin = "https://evil.attacker.com"

        headers_with_evil_origin = dict(target.headers)
        headers_with_evil_origin["origin"] = attacker_origin
        headers_with_evil_origin["referer"] = attacker_origin + "/"

        resp = await _send(client, "POST", negotiate_url, headers_with_evil_origin, None)
        if not resp:
            return findings

        if not _NEGOTIATE_RE.search(resp.text):
            return findings

        # Server accepted a cross-origin negotiate request.
        # Now check exploitability: CSWSH is only exploitable if session cookies
        # are sent cross-origin by browsers (i.e. no SameSite=Strict/Lax).
        # If all observed session cookies have SameSite=Strict/Lax, the attack
        # is blocked at the browser level and this is a false positive.
        host_intel = getattr(target, "host_intel", None)
        cookies_exploitable = (
            host_intel is None  # no data — conservatively assume exploitable
            or getattr(host_intel, "cookies_exploitable_cross_origin", True)
        )

        if not cookies_exploitable:
            logger.info(
                "Blazor CSWSH: negotiate accepted cross-origin but all session cookies "
                "have SameSite=Strict/Lax — not exploitable in modern browsers",
                url=negotiate_url,
            )
            return findings

        raw_req, raw_resp = _fmt_http_pair(resp)
        logger.warning(
            "Blazor CSWSH: cross-origin negotiate accepted",
            origin=attacker_origin, url=negotiate_url,
        )
        log_event(
            "blazor", "finding",
            "Cross-site WebSocket hijacking: negotiate accepted from attacker origin",
            url=negotiate_url, finding="CSWSH on Blazor SignalR", source="agent",
        )
        findings.append(AgentFinding(
            title="Cross-Site WebSocket Hijacking (CSWSH) on Blazor SignalR Hub",
            severity="high",
            cwe="CWE-346",
            attack_type="blazor",
            evidence=(
                f"The SignalR negotiate endpoint accepted a cross-origin POST "
                f"(Origin: {attacker_origin}) and returned a connectionId. "
                f"Session cookies observed without SameSite=Strict/Lax — browsers "
                f"will send them cross-origin, allowing an attacker to establish a "
                f"hub connection using the victim's session. "
                f"Mitigation: configure AllowedOrigins in MapBlazorHub() to restrict "
                f"accepted origins, AND set SameSite=Strict on session cookies."
            ),
            payload=f"Origin: {attacker_origin}",
            parameter="Origin",
            url=negotiate_url,
            request_method="POST",
            bypass_validation=True,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        ))
        return findings

    # ── WebSocket compression misconfiguration (CRIME/BREACH risk) ────────

    async def _probe_compression_misconfiguration(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
        blazor_type: str,
    ) -> List[AgentFinding]:
        """
        Detect Blazor Server with WebSocket compression enabled and no
        frame-ancestors CSP restriction (the documented Microsoft mitigation).

        Blazor Server enables WebSocket compression by default
        (DisableWebSocketCompression = false). When compression is on, the
        app is vulnerable to CRIME/BREACH-style side-channel attacks if an
        attacker can control part of the reflected SignalR payload. Microsoft
        recommends setting CSP frame-ancestors to 'self' as a default safeguard.

        Probe: fetch the base HTML page and check:
          1. blazor.server.js is loaded (Server variant confirmed)
          2. Content-Security-Policy header is absent or lacks frame-ancestors
        """
        findings: List[AgentFinding] = []

        if blazor_type not in ("server", "unknown"):
            return findings

        resp = await _send(client, "GET", base, target.headers, None)
        if not resp or resp.status_code != 200:
            return findings

        body = resp.text
        # Confirm Blazor Server (compression applies only to Server)
        if not re.search(r"blazor\.server\.js|_framework/blazor\.server", body, re.IGNORECASE):
            return findings

        csp = resp.headers.get("content-security-policy", "").lower()
        has_frame_ancestors = "frame-ancestors" in csp

        if has_frame_ancestors:
            # Mitigation is in place — no finding
            return findings

        raw_req, raw_resp = _fmt_http_pair(resp)
        logger.info(
            "Blazor Server: compression on, no frame-ancestors CSP", url=base
        )
        log_event(
            "blazor", "finding",
            "Blazor Server compression enabled with no frame-ancestors CSP",
            url=base, finding="CRIME/BREACH Risk — Missing frame-ancestors CSP", source="agent",
        )
        findings.append(AgentFinding(
            title="Blazor Server WebSocket Compression Enabled Without frame-ancestors CSP",
            severity="medium",
            cwe="CWE-311",
            attack_type="blazor",
            evidence=(
                "Blazor Server is confirmed (blazor.server.js loaded). WebSocket "
                "compression is enabled by default (DisableWebSocketCompression=false). "
                "The response lacks a Content-Security-Policy frame-ancestors directive, "
                "which is Microsoft's documented default mitigation against CRIME/BREACH-style "
                "TLS side-channel attacks on the compressed SignalR channel. "
                "An attacker who can embed the app in a cross-origin iframe can observe "
                "compressed response sizes and potentially recover sensitive data. "
                "Fix: add 'Content-Security-Policy: frame-ancestors self' to all "
                "Blazor Server responses."
            ),
            payload="(missing CSP frame-ancestors on Blazor Server page)",
            parameter="Content-Security-Policy",
            url=base,
            request_method="GET",
            bypass_validation=False,
            raw_request=raw_req,
            raw_response=raw_resp[:2000],
        ))
        return findings


    # ── Circuit fuzzer ────────────────────────────────────────────────────

    async def _probe_circuit_fuzzer(
        self,
        target: "CheckTarget",
        client: "httpx.AsyncClient",
        base: str,
        blazor_type: str,
    ) -> List[AgentFinding]:
        """
        Fuzz the Blazor Server SignalR circuit via HTTP long-polling.

        Steps:
          1. Negotiate a new circuit (POST /_blazor/negotiate)
          2. Send handshake ({"protocol":"blazorpack","version":1})
          3. Fuzz with two attack classes in parallel:
             a) eventHandlerId IDOR — replay observed handler IDs ± offsets
                to invoke C# event handlers that belong to other components
                or users (if the circuit belongs to someone else's session)
             b) DispatchEventAsync injection — send XSS/SSTI payloads as the
                value of a synthetic input event to probe server-side rendering
                of user-supplied data without client-side encoding

        Both use the msgpack binary protocol (blazorpack) so frames are
        correctly framed and the server actually processes them.
        """
        import msgpack

        findings: List[AgentFinding] = []
        if blazor_type not in ("server", "unknown"):
            return findings

        # ── 1. Negotiate circuit ──────────────────────────────────────────
        neg_url = _make_url(base, "/_blazor/negotiate?negotiateVersion=1")
        neg_resp = await _send(client, "POST", neg_url, target.headers, None)
        if not neg_resp or not _NEGOTIATE_RE.search(neg_resp.text):
            return findings
        try:
            connection_id = neg_resp.json().get("connectionId", "")
        except Exception:
            return findings
        if not connection_id:
            return findings

        hub_url = _make_url(base, f"/_blazor?id={connection_id}")
        mp_headers = dict(target.headers)
        mp_headers["content-type"] = "text/plain;charset=UTF-8"

        def _mp_frame(obj) -> bytes:
            payload = msgpack.packb(obj, use_bin_type=True)
            n, varint = len(payload), b""
            while True:
                b = n & 0x7f; n >>= 7
                varint += bytes([b | (0x80 if n else 0)])
                if not n:
                    break
            return varint + payload

        # ── 2. Handshake (blazorpack) ─────────────────────────────────────
        handshake = json.dumps({"protocol": "blazorpack", "version": 1}) + _SIGNALR_SEP
        await _send(client, "POST", hub_url, mp_headers, handshake)

        # ── 3a. eventHandlerId fuzzing ────────────────────────────────────
        # Use handler IDs observed in intercepted traffic (via BlazorDetectorPlugin
        # → SessionIntelligence). Fall back to a seed range if none are available yet.
        observed_ids: List[int] = []
        observed_input_fields: List[str] = []
        if target.service_context and hasattr(target, "_session_intel_ref"):
            pass  # not wired this way — use session_intelligence directly
        try:
            # session_intelligence is passed to run_active_checks and stored on the
            # coordinator run context. Access via the collaborator service if available.
            if collaborator and hasattr(collaborator, "_session_intelligence"):
                si = collaborator._session_intelligence
            else:
                # Fallback: access via the global store reference on the entry host
                from dast.proxy.session_store import SessionStore as _SS
                si = None
                for obj in _SS.__subclasses__():
                    pass  # not reliable — use the hint approach below
                si = None
        except Exception:
            si = None

        # Better path: session_intelligence is passed into run_active_checks and
        # forwarded to agents via CheckTarget.app_profile_hint (text) — but for
        # structured data we need to access it differently.
        # The coordinator passes it in as a kwarg; access via the target's hint.
        # For now extract from the hint string if the plugin already serialised it,
        # otherwise fall back to parsing the app_profile_hint text.
        hint = target.app_profile_hint or ""
        for m in re.finditer(r"blazor_handler_ids?:\s*([\d,\s]+)", hint, re.IGNORECASE):
            for tok in m.group(1).split(","):
                tok = tok.strip()
                if tok.isdigit():
                    observed_ids.append(int(tok))
        for m in re.finditer(r"blazor_input_fields?:\s*([^\n]+)", hint, re.IGNORECASE):
            for tok in m.group(1).split(","):
                tok = tok.strip()
                if tok:
                    observed_input_fields.append(tok)

        if observed_ids:
            logger.info(
                "Blazor agent: using observed handler IDs",
                count=len(observed_ids),
                ids=observed_ids[:5],
                url=target.url,
            )
        else:
            logger.debug("Blazor agent: no observed handler IDs yet, using seed range", url=target.url)
            observed_ids = list(range(1, 8))

        fuzz_ids = set()
        for hid in observed_ids[:5]:
            for offset in (-10, -5, -1, 0, 1, 5, 10, 50, 100):
                candidate = hid + offset
                if candidate > 0:
                    fuzz_ids.add(candidate)

        marker = "DAST_BLAZOR_IDOR"
        handler_hit_ids: List[int] = []

        for handler_id in sorted(fuzz_ids)[:30]:
            event_payload = json.dumps([
                {"eventHandlerId": handler_id, "eventName": "click", "eventFieldInfo": None},
                {"detail": 1, "screenX": 0, "screenY": 0, "clientX": 0, "clientY": 0,
                 "button": 0, "buttons": 0, "ctrlKey": False, "shiftKey": False,
                 "altKey": False, "metaKey": False, "type": "click"},
            ])
            msg = [1, {}, None, "BeginInvokeDotNetFromJS",
                   [str(handler_id), None, "DispatchEventAsync", 0, event_payload]]
            frame = _mp_frame(msg)
            resp = await _send(
                client, "POST", hub_url, mp_headers,
                frame.decode("latin-1"),
            )
            if not resp:
                continue

            # A non-error response to an out-of-range handler ID is the signal.
            # Errors look like: completion with resultKind=1 (error) containing
            # "There is no event handler with id" or similar.
            body = resp.content
            body_str = body.decode("utf-8", errors="replace") if body else ""
            if body and len(body) > 2:
                # Check for success (no error) vs "no event handler" error
                is_error = "There is no event handler" in body_str or "InvalidOperationException" in body_str
                if not is_error and len(body) > 4:
                    handler_hit_ids.append(handler_id)
                    logger.debug(
                        "Blazor handler ID responded",
                        handler_id=handler_id, url=hub_url,
                    )

        if handler_hit_ids:
            log_event(
                "blazor", "finding",
                f"Blazor event handler IDOR candidates: IDs {handler_hit_ids[:5]}",
                url=hub_url, finding="Blazor Event Handler IDOR", source="agent",
            )
            findings.append(AgentFinding(
                title="Blazor Event Handler IDOR — Server Accepts Arbitrary Handler IDs",
                severity="medium",
                cwe="CWE-639",
                attack_type="blazor",
                evidence=(
                    f"The server responded to DispatchEventAsync with handler IDs "
                    f"{handler_hit_ids[:8]} without returning 'no event handler' errors. "
                    f"If these IDs belong to other components or user sessions, this may "
                    f"allow invoking C# event handlers without UI authorization. "
                    f"Manual verification required: replay with a second authenticated session."
                ),
                payload=f"eventHandlerId={handler_hit_ids[0]}",
                parameter="eventHandlerId",
                url=hub_url,
                request_method="POST",
                bypass_validation=False,
            ))

        # ── 3b. DispatchEventAsync injection fuzzing ──────────────────────
        # Inject payloads into a synthetic input event.
        # The value field flows into the component's bound parameter —
        # if Blazor renders it back via @((MarkupString)value) it causes XSS.
        injection_payloads = [
            ("<script>alert('DAST_BLAZOR_XSS')</script>",           "xss"),
            ("<img src=x onerror=alert('DAST_BLAZOR_XSS')>",        "xss"),
            ("{{7*7}}",                                              "ssti"),
            ("${7*7}",                                               "ssti"),
            ("' OR '1'='1",                                         "sqli"),
            ("../../../../etc/passwd",                               "lfi"),
            (f"{marker}",                                            "marker"),
        ]

        seed_handler_id = observed_ids[0] if observed_ids else 1
        # Use observed input field names, fall back to "value" (most common Blazor binding)
        fuzz_fields = observed_input_fields[:3] if observed_input_fields else ["value"]

        for payload_str, ptype in injection_payloads:
            # Build event data dict with all observed field names set to the payload
            event_data: dict = {"type": "change"}
            for field_name in fuzz_fields:
                event_data[field_name] = payload_str
            event_payload = json.dumps([
                {"eventHandlerId": seed_handler_id, "eventName": "change",
                 "eventFieldInfo": {"fieldValue": payload_str}},
                event_data,
            ])
            msg = [1, {}, None, "BeginInvokeDotNetFromJS",
                   [str(seed_handler_id), None, "DispatchEventAsync", 0, event_payload]]
            frame = _mp_frame(msg)
            resp = await _send(
                client, "POST", hub_url, mp_headers,
                frame.decode("latin-1"),
            )
            if not resp or not resp.content:
                continue

            body_str = resp.content.decode("utf-8", errors="replace")

            if ptype == "xss" and (payload_str in body_str or "DAST_BLAZOR_XSS" in body_str):
                log_event(
                    "blazor", "finding",
                    f"Blazor XSS via DispatchEventAsync — payload reflected in hub response",
                    url=hub_url, finding="Blazor SignalR XSS", source="agent",
                )
                findings.append(AgentFinding(
                    title="Blazor Server XSS via DispatchEventAsync Input Injection",
                    severity="high",
                    cwe="CWE-79",
                    attack_type="blazor",
                    evidence=(
                        f"XSS payload '{payload_str}' was reflected in the SignalR hub "
                        f"response after injection into a DispatchEventAsync input event. "
                        f"This indicates the component renders user-supplied input without "
                        f"encoding (likely via @((MarkupString)value) or similar)."
                    ),
                    payload=payload_str,
                    parameter="eventFieldInfo.fieldValue",
                    url=hub_url,
                    request_method="POST",
                    bypass_validation=True,
                ))
                break

            if ptype == "ssti" and "49" in body_str and payload_str not in body_str:
                findings.append(AgentFinding(
                    title="Blazor Server SSTI via DispatchEventAsync Input",
                    severity="critical",
                    cwe="CWE-94",
                    attack_type="blazor",
                    evidence=(
                        f"Template expression '{payload_str}' evaluated to '49' in hub "
                        f"response, indicating server-side template injection."
                    ),
                    payload=payload_str,
                    parameter="eventFieldInfo.fieldValue",
                    url=hub_url,
                    request_method="POST",
                    bypass_validation=True,
                ))
                break

        return findings


from dast.ai.coordinator import Coordinator
Coordinator.register(BlazorAgent)

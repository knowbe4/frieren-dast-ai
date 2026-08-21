"""
Blazor framework detector and SignalR decoder plugin.

Passive-only — no extra requests sent.

Responsibilities:
  1. Fingerprint Blazor WASM vs Blazor Server from HTTP traffic.
  2. Decode and record SignalR text-protocol messages (record-separator 0x1e
     delimited JSON) so the HTTP history panel shows human-readable hub
     invocations instead of raw WebSocket frames.
  3. Detect secrets and sensitive values in Blazor WASM configuration files
     (blazor.boot.json, appsettings.json) that are shipped to the browser.
  4. Flag .NET assembly responses (MZ header) for decompilation risk.
  5. Enrich CheckTarget with a Blazor-specific tech hint so the Blazor agent
     gets priority selection from the LLM planner.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Dict, List, Tuple

from dast.proxy.plugin_base import ProxyPlugin
from dast.proxy.plugin_manager import log_event
from dast.proxy.signalr import MZ_HEADER, SIGNALR_SEPARATOR, is_signalr_binary, read_varint
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

# SignalR text protocol record separator (0x1e)
_SIGNALR_SEP = SIGNALR_SEPARATOR

# MZ header — marks a Windows PE / .NET assembly
_MZ_HEADER = MZ_HEADER

# Blazor WASM fingerprint patterns (response body)
_WASM_BODY_RE = re.compile(
    r"_framework/blazor\.webassembly\.js"
    r"|blazor\.boot\.json"
    r"|_framework/dotnet\.",
    re.IGNORECASE,
)

# Blazor Server fingerprint (response body)
_SERVER_BODY_RE = re.compile(
    r"_framework/blazor\.server\.js",
    re.IGNORECASE,
)

# SignalR negotiate response body
_SIGNALR_NEGOTIATE_RE = re.compile(
    r'"connectionId"\s*:',
    re.IGNORECASE,
)

# Sensitive key patterns inside appsettings / config JSON
_SENSITIVE_KEY_RE = re.compile(
    r'"(ConnectionString|Password|Secret|ApiKey|Token|Key|ClientSecret|PrivateKey|AccessKey)"'
    r'\s*:\s*"([^"]{4,})"',
    re.IGNORECASE,
)

# Paths that indicate Blazor framework requests
_FRAMEWORK_PATH_RE = re.compile(
    r"/_framework/"
    r"|/_blazor"
    r"|/appsettings\.json"
    r"|/appsettings\.\w+\.json",
    re.IGNORECASE,
)

# DLL / WASM path extension
_ASSEMBLY_PATH_RE = re.compile(r"\.(dll|pdb)$", re.IGNORECASE)


def _decode_signalr_messages(raw: bytes) -> List[dict]:
    """
    Decode a SignalR text protocol stream into a list of message dicts.

    The SignalR text protocol delimits messages with 0x1e (record separator).
    Each segment is a JSON object. Messages with type 6 (ping) are omitted.
    """
    messages: List[dict] = []
    try:
        text = raw.decode("utf-8", errors="replace")
        for segment in text.split(_SIGNALR_SEP):
            segment = segment.strip()
            if not segment:
                continue
            try:
                msg = json.loads(segment)
                if isinstance(msg, dict) and msg.get("type") != 6:
                    messages.append(msg)
            except (json.JSONDecodeError, ValueError):
                continue
    except Exception as exc:
        logger.debug("SignalR decode error", error=str(exc))
    return messages


def _extract_signalr_findings(
    messages: List[dict],
    entry: "ProxyEntry",
) -> List[Tuple[str, str, str, str]]:
    """
    Analyse decoded SignalR messages for security-relevant patterns.

    Returns list of (title, severity, cwe, evidence).
    """
    results: List[Tuple[str, str, str, str]] = []

    for msg in messages:
        msg_type = msg.get("type")
        target = msg.get("target", "")
        error = msg.get("error", "")
        result_value = msg.get("result")

        # Type 3 = completion with error — may expose internal .NET exception
        if msg_type == 3 and error:
            if re.search(
                r"Exception|stack\s+trace|at\s+\w+\.\w+|Object\s+reference",
                error,
                re.IGNORECASE,
            ):
                results.append((
                    "SignalR Hub Exception Disclosure",
                    "medium",
                    "CWE-209",
                    f"Hub method '{target}' returned an internal .NET exception: "
                    f"{error[:300]}",
                ))

        # Type 1 = invocation with sensitive target name
        if msg_type == 1 and target:
            if re.search(r"admin|config|secret|password|token|key|user|auth", target, re.IGNORECASE):
                results.append((
                    "SignalR Sensitive Hub Method Invocation",
                    "low",
                    "CWE-200",
                    f"Hub method '{target}' invoked — may expose privileged data if "
                    f"authorization is not enforced server-side",
                ))

        # Type 3 = completion where result contains sensitive-looking data
        if msg_type == 3 and isinstance(result_value, (dict, list)):
            result_str = json.dumps(result_value, ensure_ascii=False)
            m = _SENSITIVE_KEY_RE.search(result_str)
            if m:
                key_name = m.group(1)
                results.append((
                    "Sensitive Data Returned via SignalR Hub",
                    "high",
                    "CWE-200",
                    f"Hub completion result contains sensitive field '{key_name}' "
                    f"— verify that authorization is required to invoke this method",
                ))

    return results


def _parse_blazor_request_body(raw: bytes) -> List[dict]:
    """
    Parse a Blazor POST body and extract event handler observations.

    Returns list of dicts:
      {handler_id, event_name, component, input_fields}

    Handles:
      - blazorpack (msgpack varint-framed): BeginInvokeDotNetFromJS frames
      - text protocol (0x1e-delimited): JSON invocations
    """
    results: List[dict] = []

    # ── msgpack (blazorpack) ──────────────────────────────────────────────
    try:
        import msgpack as _mp

        # Check if this looks like msgpack (varint + fixarray)
        if is_signalr_binary(raw):
            # Parse all frames
            pos = 0
            while pos < len(raw):
                frame_len, pos = read_varint(raw, pos)
                if frame_len == 0 or pos + frame_len > len(raw):
                    break
                frame = raw[pos:pos+frame_len]; pos += frame_len
                try:
                    msg = _mp.unpackb(frame, raw=False, strict_map_key=False)
                except Exception:
                    continue
                if not isinstance(msg, (list, tuple)) or len(msg) < 5:
                    continue
                if msg[0] != 1:  # only Invocation type
                    continue
                target = msg[3] if len(msg) > 3 else ""
                args = msg[4] if len(msg) > 4 else None

                if target == "BeginInvokeDotNetFromJS" and isinstance(args, (list, tuple)) and len(args) >= 5:
                    # args = [callId, assembly, method, dotNetObjectId, argsJson]
                    args_json_str = args[4]
                    try:
                        event_args = json.loads(args_json_str) if isinstance(args_json_str, str) else args_json_str
                    except Exception:
                        continue
                    if not isinstance(event_args, (list, tuple)):
                        continue

                    # First element is the event descriptor
                    descriptor = event_args[0] if event_args else {}
                    if not isinstance(descriptor, dict):
                        continue

                    handler_id = descriptor.get("eventHandlerId")
                    event_name = descriptor.get("eventName", "")
                    if not isinstance(handler_id, int):
                        continue

                    # Second element may contain input field values
                    input_fields: List[str] = []
                    if len(event_args) > 1 and isinstance(event_args[1], dict):
                        event_data = event_args[1]
                        # For change/input events, "value" is the user-typed content
                        if "value" in event_data:
                            input_fields.append("value")
                        # For custom events, collect all string-valued keys
                        for k, v in event_data.items():
                            if isinstance(v, str) and k not in ("type",) and k not in input_fields:
                                input_fields.append(k)

                    results.append({
                        "handler_id": handler_id,
                        "event_name": event_name,
                        "component": "",
                        "input_fields": input_fields,
                    })
            return results
    except ImportError:
        pass

    # ── text protocol (0x1e-delimited JSON) ──────────────────────────────
    _SEP = SIGNALR_SEPARATOR
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return results

    for segment in text.split(_SEP):
        segment = segment.strip()
        if not segment:
            continue
        json_start = next((i for i, c in enumerate(segment) if c in ('{', '[')), -1)
        if json_start == -1:
            continue
        try:
            msg = json.loads(segment[json_start:])
        except Exception:
            continue
        if not isinstance(msg, dict) or msg.get("type") != 1:
            continue
        target = msg.get("target", "")
        args = msg.get("arguments", [])
        if target != "BeginInvokeDotNetFromJS" or not isinstance(args, list) or len(args) < 5:
            continue
        try:
            event_args = json.loads(args[4]) if isinstance(args[4], str) else args[4]
        except Exception:
            continue
        if not isinstance(event_args, list) or not event_args:
            continue
        descriptor = event_args[0] if isinstance(event_args[0], dict) else {}
        handler_id = descriptor.get("eventHandlerId")
        event_name = descriptor.get("eventName", "")
        if not isinstance(handler_id, int):
            continue
        input_fields = []
        if len(event_args) > 1 and isinstance(event_args[1], dict):
            if "value" in event_args[1]:
                input_fields.append("value")
        results.append({
            "handler_id": handler_id,
            "event_name": event_name,
            "component": "",
            "input_fields": input_fields,
        })

    return results


class BlazorDetectorPlugin(ProxyPlugin):
    name = "Blazor Detector"
    description = (
        "Fingerprints Blazor WASM and Server applications, decodes SignalR "
        "text-protocol messages, and detects .NET assembly exposure and "
        "sensitive configuration shipped to the browser."
    )
    version = "1.0.0"
    author = "Frieren DAST-AI"

    def __init__(self) -> None:
        # Track which hosts have been fingerprinted to avoid duplicate info findings
        self._fingerprinted: Dict[str, str] = {}  # host → "wasm" | "server" | "unknown"

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        if entry.response_status is None or entry.method == "CONNECT":
            return

        await self._fingerprint_blazor(entry, store)
        await self._check_assembly_exposure(entry, store)
        await self._check_config_exposure(entry, store)
        await self._decode_signalr(entry, store)
        await self._extract_blazor_intel(entry, store)

    # ── Fingerprinting ────────────────────────────────────────────────────

    async def _fingerprint_blazor(
        self, entry: "ProxyEntry", store: "SessionStore"
    ) -> None:
        if entry.host in self._fingerprinted:
            return

        ct = (entry.content_type or "").lower()
        if "html" not in ct:
            return
        if not entry.response_body:
            return

        try:
            body = entry.response_body[:32768].decode("utf-8", errors="replace")
        except Exception:
            return

        if _WASM_BODY_RE.search(body):
            self._fingerprinted[entry.host] = "wasm"
            log_event(
                self.name, "info",
                f"Blazor WebAssembly detected on {entry.host}",
                url=entry.url, source="plugin",
            )
            logger.info("Blazor WASM detected", host=entry.host, url=entry.url)
        elif _SERVER_BODY_RE.search(body):
            self._fingerprinted[entry.host] = "server"
            log_event(
                self.name, "info",
                f"Blazor Server detected on {entry.host}",
                url=entry.url, source="plugin",
            )
            logger.info("Blazor Server detected", host=entry.host, url=entry.url)

    # ── .NET assembly exposure ────────────────────────────────────────────

    async def _check_assembly_exposure(
        self, entry: "ProxyEntry", store: "SessionStore"
    ) -> None:
        if entry.response_status != 200:
            return
        if not entry.response_body:
            return
        if not _ASSEMBLY_PATH_RE.search(entry.path or ""):
            return

        # Confirm by checking for MZ (PE) header in response
        if not entry.response_body[:2] == _MZ_HEADER:
            return

        logger.info("Blazor DLL exposed", url=entry.url)
        log_event(
            self.name, "finding",
            f"Exposed .NET assembly: {entry.path}",
            url=entry.url, finding=".NET Assembly Exposure", source="plugin",
        )
        store.add_finding(
            entry.id,
            {
                "title": ".NET Assembly (DLL) Exposed and Downloadable",
                "severity": "high",
                "cwe": "CWE-200",
                "attack_type": "blazor_dll_exposure",
                "evidence": (
                    f"Assembly at {entry.path} returned HTTP 200 with a valid .NET "
                    f"PE header (MZ). It can be decompiled with dnSpy or ILSpy to "
                    f"recover source code, hardcoded secrets, and internal endpoints."
                ),
                "confirmed": True,
                "validated_by": ["pattern"],
            },
            "vulnerable",
        )

    # ── appsettings / config exposure ─────────────────────────────────────

    async def _check_config_exposure(
        self, entry: "ProxyEntry", store: "SessionStore"
    ) -> None:
        if entry.response_status != 200:
            return
        if not entry.response_body:
            return

        path = (entry.path or "").lower()
        if "appsettings" not in path and "blazor.boot.json" not in path:
            return

        try:
            body_text = entry.response_body[:65536].decode("utf-8", errors="replace")
        except Exception:
            return

        # Scan for sensitive keys in config JSON
        matches = _SENSITIVE_KEY_RE.findall(body_text)
        if matches:
            keys_found = list({k for k, _ in matches})
            logger.warning(
                "Sensitive keys in Blazor config", path=entry.path, keys=keys_found
            )
            log_event(
                self.name, "finding",
                f"Sensitive config keys exposed in {entry.path}: {', '.join(keys_found)}",
                url=entry.url, finding="Blazor Sensitive Config Exposure", source="plugin",
            )
            store.add_finding(
                entry.id,
                {
                    "title": "Blazor Configuration File Exposes Sensitive Keys",
                    "severity": "high",
                    "cwe": "CWE-200",
                    "attack_type": "blazor_config_exposure",
                    "evidence": (
                        f"Configuration file at {entry.path} contains sensitive keys "
                        f"shipped to the browser: {', '.join(keys_found)}"
                    ),
                    "confirmed": True,
                    "validated_by": ["pattern"],
                },
                "vulnerable",
            )
        elif "blazor.boot.json" in path:
            # Even without secrets, the boot manifest is worth flagging once per host
            if entry.host not in self._fingerprinted:
                store.add_finding(
                    entry.id,
                    {
                        "title": "Blazor Boot Manifest Accessible",
                        "severity": "medium",
                        "cwe": "CWE-200",
                        "attack_type": "blazor_assembly_enumeration",
                        "evidence": (
                            f"blazor.boot.json at {entry.path} lists all .NET assemblies. "
                            f"Use this manifest to enumerate and download DLLs for decompilation."
                        ),
                        "confirmed": True,
                        "validated_by": ["pattern"],
                    },
                    "vulnerable",
                )

    # ── SignalR decoder ───────────────────────────────────────────────────

    async def _decode_signalr(
        self, entry: "ProxyEntry", store: "SessionStore"
    ) -> None:
        """
        Decode SignalR text-protocol messages in responses that match:
          - path contains _blazor or negotiate
          - content-type: application/json with record-separator character

        Decoded messages are stored in entry findings as informational items
        so the HTTP history panel can show human-readable hub invocations.
        """
        if not entry.response_body:
            return

        path = (entry.path or "").lower()
        is_hub_response = (
            "_blazor" in path
            or "negotiate" in path
            or _SIGNALR_NEGOTIATE_RE.search(
                entry.response_body[:512].decode("utf-8", errors="replace")
            )
        )
        has_record_sep = _SIGNALR_SEP.encode() in entry.response_body

        if not (is_hub_response or has_record_sep):
            return

        messages = _decode_signalr_messages(entry.response_body)
        if not messages:
            return

        logger.debug(
            "SignalR messages decoded", count=len(messages), url=entry.url
        )

        # Check for security-relevant hub invocations
        sec_findings = _extract_signalr_findings(messages, entry)
        for title, severity, cwe, evidence in sec_findings:
            log_event(
                self.name, "finding", title,
                url=entry.url, finding=title, source="plugin",
            )
            store.add_finding(
                entry.id,
                {
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "attack_type": "blazor_signalr",
                    "evidence": evidence,
                    "confirmed": True,
                    "validated_by": ["pattern"],
                },
                "vulnerable",
            )

        # Annotate the entry with decoded hub messages as a single informational
        # finding so operators can read the SignalR traffic without specialist tools.
        if messages:
            hub_summary = []
            for m in messages[:20]:
                msg_type = m.get("type")
                if msg_type == 1:
                    hub_summary.append(
                        f"→ invoke '{m.get('target', '?')}' "
                        f"args={json.dumps(m.get('arguments', []))[:120]}"
                    )
                elif msg_type == 3:
                    err = m.get("error", "")
                    if err:
                        hub_summary.append(f"← error: {err[:120]}")
                    else:
                        res = json.dumps(m.get("result", ""))[:120]
                        hub_summary.append(f"← result: {res}")
                elif msg_type == 2:
                    items = m.get("item", "")
                    hub_summary.append(f"← stream item: {json.dumps(items)[:120]}")

            if hub_summary:
                store.add_finding(
                    entry.id,
                    {
                        "title": "SignalR Hub Traffic Decoded",
                        "severity": "info",
                        "cwe": "CWE-200",
                        "attack_type": "blazor_signalr_decoded",
                        "evidence": (
                            "Decoded SignalR text-protocol messages:\n"
                            + "\n".join(hub_summary)
                        ),
                        "confirmed": True,
                        "validated_by": ["passive"],
                    },
                    "safe",
                )

    # ── Session intelligence extraction ──────────────────────────────────

    async def _extract_blazor_intel(
        self, entry: "ProxyEntry", store: "SessionStore"
    ) -> None:
        """
        Parse intercepted Blazor request bodies to extract event handler IDs,
        event names, and input field names — then feed them into SessionIntelligence
        so the Blazor agent can fuzz with real, observed values instead of blind guesses.

        Handles both:
          - blazorpack (msgpack): POST /_blazor with BeginInvokeDotNetFromJS frames
          - text protocol: JSON+0x1e
        """
        path = (entry.path or "").lower()
        if "_blazor" not in path:
            return

        body = entry.request_body
        if not body or len(body) < 4:
            return

        intel_host = store.session_intelligence.get(entry.host) if store.session_intelligence else None
        if not intel_host:
            return

        # Extract connectionId from query string for correlation
        connection_id = ""
        if "id=" in (entry.url or ""):
            import re as _re
            m = _re.search(r"[?&]id=([^&]+)", entry.url)
            if m:
                connection_id = m.group(1)

        observations = _parse_blazor_request_body(body)
        for obs in observations:
            intel_host.record_blazor_observation(
                handler_id=obs["handler_id"],
                event_name=obs["event_name"],
                component=obs.get("component", ""),
                input_fields=obs.get("input_fields", []),
                connection_id=connection_id,
            )

        if observations:
            logger.debug(
                "Blazor intel extracted",
                host=entry.host,
                observations=len(observations),
                handler_ids=[o["handler_id"] for o in observations],
            )

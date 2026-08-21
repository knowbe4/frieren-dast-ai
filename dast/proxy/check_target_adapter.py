"""
CheckTarget adapter — converts an intercepted ProxyEntry into the CheckTarget
the active scanner consumes.

This is the pure request-shaping layer between the proxy session and the scan
pipeline: it extracts fuzzable parameters (query string, JSON/form body,
multipart file parts, GraphQL variables, import hints), skips
session-destructive paths, and enriches the target with the four intelligence
layers (service graph, discovery, app profile, threat model, code hints) when a
SessionStore is available. It holds no scan state and sends no requests.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry

logger = get_logger(__name__)


# Path segments where sending a payload would destroy session state or
# application data. Matched against the last path segment so /auth/logout,
# /api/v1/logout, etc. are all caught.
_DANGEROUS_SEGMENTS = frozenset({
    # Session termination
    "logout", "logoff", "log-out", "log_out", "signout", "sign-out", "sign_out",
    "end-session", "endsession", "invalidate-session", "revoke-session",
    # Account / data destruction
    "delete-account", "deleteaccount", "deactivate", "deactivate-account",
    "close-account", "closeaccount", "cancel-account", "cancelaccount",
    "unsubscribe",
    # Password / credential reset (sending a payload here corrupts the reset flow)
    "reset-password", "resetpassword", "change-password", "changepassword",
})


def _entry_to_check_target(entry: "ProxyEntry", store=None):
    """Convert a ProxyEntry into a CheckTarget for the active scanner."""
    from urllib.parse import parse_qs, urlparse
    import json as _json
    from dast.scanners.active_checks import CheckTarget, ServiceContext

    if entry.method == "CONNECT":
        return None

    parsed = urlparse(entry.url)

    # Skip paths that would destroy session state or application data.
    # Match the last path segment to catch /auth/logout, /api/v1/logout, etc.
    _last_seg = parsed.path.lower().rstrip("/").rsplit("/", 1)[-1]
    if _last_seg in _DANGEROUS_SEGMENTS:
        logger.debug("Scan skipped — session-destructive path", url=entry.url, segment=_last_seg)
        return None
    params = []

    for name, values in parse_qs(parsed.query).items():
        params.append({"name": name, "location": "query", "value": values[0] if values else ""})

    content_type = entry.request_headers.get("content-type", "").lower()

    # Only text-based content types can carry injectable parameters.
    # Binary bodies (images, audio, video, archives, protobuf, etc.) must never be
    # modified — doing so corrupts uploads and produces no useful security signal.
    _FUZZABLE_CT = (
        "application/json",
        "application/x-www-form-urlencoded",
        "application/graphql",
        "text/",
        "application/xml",
        "application/soap+xml",
    )
    _is_fuzzable_ct = any(content_type.startswith(ct) or ct in content_type for ct in _FUZZABLE_CT)
    _is_multipart = "multipart/form-data" in content_type

    raw_body: Optional[bytes] = None
    body_str = ""

    # For imported entries whose LLM-inferred body is prose (not real structured data),
    # try to borrow the real body from a browse/proxy entry on the same host + path.
    # This gives agents real parameter values and IDs instead of fictional placeholder text.
    if entry.source == "imported" and store is not None and entry.method in ("POST", "PUT", "PATCH"):
        _current_body_str = (entry.request_body or b"").decode("utf-8", errors="replace").strip()
        _body_looks_fake = (
            not _current_body_str
            or (not _current_body_str.startswith("{")
                and not _current_body_str.startswith("[")
                and "=" not in _current_body_str[:100])
        )
        if _body_looks_fake:
            try:
                from urllib.parse import urlparse as _up_borrow
                _borrow_path = _up_borrow(entry.url).path
                _borrow_segs = [s for s in _borrow_path.split("/") if s]
                _borrow_prefix = "/" + "/".join(_borrow_segs[:-1]) if len(_borrow_segs) > 1 else _borrow_path
                for _be in reversed(store.all_entries()):
                    if _be.source in ("agent", "imported"):
                        continue
                    if _be.host != entry.host:
                        continue
                    if _be.method != entry.method:
                        continue
                    if not _be.request_body:
                        continue
                    _be_path = _up_borrow(_be.url).path
                    if _be_path == _borrow_path or _be_path.startswith(_borrow_prefix):
                        _bs = _be.request_body[:200].decode("utf-8", errors="replace").strip()
                        if _bs.startswith("{") or _bs.startswith("[") or "=" in _bs[:80]:
                            entry.request_body = _be.request_body
                            _borrowed_ct = _be.request_headers.get("content-type", "")
                            if _borrowed_ct and not entry.request_headers.get("content-type"):
                                entry.request_headers = dict(entry.request_headers)
                                entry.request_headers["content-type"] = _borrowed_ct
                            content_type = _borrowed_ct.lower()
                            logger.debug(
                                "imported entry: borrowed real body from browse",
                                url=entry.url,
                                donor=_be_path,
                                body_len=len(_be.request_body),
                            )
                            break
            except Exception as _borrow_exc:
                logger.debug("imported entry: body borrow failed", error=str(_borrow_exc))

    if entry.request_body and (_is_fuzzable_ct or _is_multipart or not content_type):
        body_raw = entry.request_body
        body_str = body_raw.decode("utf-8", errors="replace")

        if _is_multipart or "webkitformboundary" in body_str[:200].lower():
            raw_body = body_raw  # kept for agents to inject into

            # Extract each file part's filename and Content-Type as fuzzable params.
            # Param name encodes both the field kind and the form-field name so the
            # injector knows which MIME header to rewrite, e.g.:
            #   multipart_filename:artwork   → rewrites  filename="..."
            #   multipart_ct:artwork         → rewrites  Content-Type: ...
            # The binary payload between CRLFCRLF and the next boundary is never touched.
            for m in re.finditer(
                r'Content-Disposition:[^\r\n]*?name="([^"]+)"'
                r'(?:[^\r\n]*?;\s*filename="([^"]*)")?'
                r'[^\r\n]*\r?\n(?:Content-Type:\s*([^\r\n]+))?',
                body_str,
            ):
                part_name = m.group(1)
                filename = m.group(2)
                part_ct = m.group(3)
                if filename is not None:
                    params.append({
                        "name": f"multipart_filename:{part_name}",
                        "location": "multipart_filename",
                        "value": filename,
                    })
                    # File parts: allow agents to replace the entire content
                    # (e.g. replace image bytes with an XSS probe or SSRF URL)
                    params.append({
                        "name": f"multipart_body:{part_name}",
                        "location": "multipart_body",
                        "value": "",
                    })
                if part_ct:
                    params.append({
                        "name": f"multipart_ct:{part_name}",
                        "location": "multipart_ct",
                        "value": part_ct.strip(),
                    })

            # Also parse the `operations` field for GraphQL variables (GraphQL-over-multipart)
            ops_match = re.search(
                r'name=["\']operations["\']\r?\n\r?\n(\{.*?\})\r?\n--',
                body_str, re.DOTALL,
            )
            body_str = ops_match.group(1) if ops_match else ""

    if body_str:
        try:
            data = _json.loads(body_str)
            if isinstance(data, dict):
                # GraphQL: extract variables as the actual parameters to fuzz.
                # Top-level keys (query, operationName, variables) are structural —
                # injecting payloads into the raw `query` string breaks GraphQL syntax.
                if "query" in data and isinstance(data.get("variables"), dict):
                    def _flatten_vars(obj: dict, prefix: str) -> None:
                        for k, v in obj.items():
                            full_key = f"{prefix}.{k}" if prefix else k
                            if isinstance(v, dict):
                                _flatten_vars(v, full_key)
                            elif isinstance(v, (str, int, float, bool)):
                                params.append({"name": full_key, "location": "body_graphql", "value": str(v)[:200]})
                    _flatten_vars(data["variables"], "")
                else:
                    # Flatten nested objects so nested fields are individually testable
                    # e.g. {"address":{"city":"x"}} → param "address.city" with value "x"
                    def _flatten_json(obj: dict, prefix: str) -> None:
                        for k, v in obj.items():
                            full_key = f"{prefix}.{k}" if prefix else k
                            if isinstance(v, dict):
                                _flatten_json(v, full_key)
                            elif isinstance(v, list):
                                params.append({"name": full_key, "location": "body", "value": str(v)[:200]})
                            else:
                                params.append({"name": full_key, "location": "body", "value": str(v) if v is not None else ""})
                    _flatten_json(data, "")
        except Exception:
            for part in body_str.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    params.append({"name": k, "location": "body", "value": v})

    # For GET entries with no detected params, try to extract params from import_hints
    # (e.g. code hypotheses where suggested_payload = "username=victim@example.com")
    if not params and entry.method == "GET":
        for hint in (entry.import_hints or []):
            raw_payload = hint.get("payload", "") or ""
            # Extract "key=value" pairs from the payload string
            for part in raw_payload.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    k = k.strip().lstrip("?")
                    if k:
                        params.append({"name": k, "location": "query", "value": v.strip()})
            param_name = hint.get("parameter", "")
            if param_name and not any(p["name"] == param_name for p in params):
                params.append({"name": param_name, "location": "query", "value": ""})
        # Still no params — skip (nothing for agents to fuzz)
        if not params:
            return None

    # Build service context (Layer 2) from the service graph if available
    service_context = None
    if store is not None:
        group = store.service_graph.group_for_host(entry.host)
        if group and len(group.hosts) > 1:
            service_context = ServiceContext(
                group_id=group.id,
                sibling_hosts=[h for h in group.hosts if h != entry.host],
                shared_tokens=list(group.shared_tokens),
                shared_cookies=dict(group.shared_cookies),
            )

    # Build discovery context (Layer 3) — tech stack, JS endpoints, call chains
    discovery_context = None
    if store is not None:
        discovery_context = store.discovery_engine.enrich_target(entry.host, entry.url, params)

    # Build app profile hint (Layer 4) — LLM-synthesised app intelligence
    app_profile_hint = ""
    if store is not None:
        profile = store.discovery_engine.get_app_profile(entry.host)
        if profile:
            hint = profile.to_coordinator_hint()
            if hint:
                app_profile_hint = hint

    # Append Blazor circuit intelligence so the Blazor agent can fuzz with
    # real handler IDs observed in intercepted traffic (via BlazorDetectorPlugin).
    if store is not None and store.session_intelligence is not None:
        try:
            host_intel = store.session_intelligence.get(entry.host)
            handler_ids = host_intel.get_blazor_handler_ids()
            input_fields = host_intel.get_blazor_input_fields()
            if handler_ids:
                ids_str = ",".join(str(h) for h in handler_ids[:30])
                app_profile_hint += f"\nblazor_handler_ids: {ids_str}"
            if input_fields:
                app_profile_hint += f"\nblazor_input_fields: {','.join(input_fields[:10])}"
        except Exception:
            pass

    # Build threat model hint — architectural constraints for red-team validator
    threat_model_hint = ""
    if store is not None:
        threat_model = store.discovery_engine.get_threat_model(entry.host)
        if threat_model:
            hint = threat_model.to_validator_hint()
            if hint:
                threat_model_hint = hint

    # Build code hint — source code snippets relevant to this URL path
    code_hint = ""
    try:
        from urllib.parse import urlparse as _urlparse
        from dast.code_analysis import lookup_code_for_path
        _url_path = _urlparse(entry.url).path
        if _url_path and _url_path != "/":
            code_hint = lookup_code_for_path(_url_path)
    except Exception:
        pass

    named_sessions = store.get_named_sessions() if store is not None else []

    return CheckTarget(
        method=entry.method,
        url=entry.url,
        headers=dict(entry.request_headers),
        body=body_str or None,
        params=params,
        raw_body=raw_body,
        service_context=service_context,
        discovery_context=discovery_context,
        app_profile_hint=app_profile_hint,
        threat_model_hint=threat_model_hint,
        code_hint=code_hint,
        import_hints=list(entry.import_hints) if entry.import_hints else None,
        named_sessions=named_sessions if named_sessions else None,
    )

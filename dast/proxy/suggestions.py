"""
AI scan suggestions produced by recon: content-discovery hits and hidden
parameters found by param mining. No vulnerability is inferred from a path or
a parameter name alone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from dast.proxy.session_store import ProxyEntry

from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import SessionStore

logger = get_logger(__name__)


def record_discovery_hit(store: "SessionStore", hit: dict, headers: dict, llm_attack_type: Optional[str] = None) -> None:
    """
    Turn a single content-discovery hit into a synthetic sitemap entry and
    an AI scan suggestion. Reuses the synthetic-entry pattern from
    ai_routes.py and the suggestion shape from app_context.py.

    Classification (per plan): dir/file hits are neutral "recon" suggestions
    (no vulnerability inferred from a path); GraphQL hits get
    "graphql_injection". ``llm_attack_type`` is the optional LLM refinement,
    computed by the caller off the event loop (discovery_llm_classify flag).
    """
    import time
    import uuid
    from urllib.parse import urlparse

    from dast.proxy.plugin_manager import log_event

    url = hit["url"]
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = hit["path"] or "/"
    method = hit.get("method", "GET")

    # ── synthetic sitemap entry (only if not already present) ──────────
    already = any(
        e.host == host and e.path == path and e.method == method
        for e in store.all_entries()
    )
    if not already:
        synthetic_id = f"disc-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
        entry = ProxyEntry(
            id=synthetic_id,
            method=method,
            url=url,
            host=host,
            path=path,
            request_headers=dict(headers),
            request_body=None,
            response_status=hit.get("status"),
            content_type=hit.get("content_type", ""),
            source="discovery",
        )
        store.add_synthetic_entry(entry)

    # ── classification ────────────────────────────────────────────────
    kind = hit.get("kind", "file")
    if kind == "graphql":
        attack_type = "graphql_injection"
        rationale = f"GraphQL endpoint discovered via forced browsing (HTTP {hit.get('status')})"
    else:
        attack_type = "recon"
        rationale = (
            f"{kind.capitalize()} discovered via forced browsing "
            f"(HTTP {hit.get('status')}, {hit.get('length', 0)} bytes) — review to decide what to test"
        )

    # Optional LLM refinement of the attack_type (opt-in, degrades to recon).
    if attack_type == "recon" and llm_attack_type:
        attack_type = llm_attack_type
        rationale = f"{rationale} | LLM-inferred candidate: {llm_attack_type}"

    # ── AI scan suggestion (dedup on host/endpoint/attack_type) ────────
    suggestions = getattr(store, "active_suggestions", None)
    if suggestions is not None:
        endpoint = f"{method} {path}"
        key = (host, endpoint, attack_type)
        if key not in {(s["host"], s["endpoint"], s["attack_type"]) for s in suggestions}:
            auto_scan = getattr(store, "auto_scan_suggestions", False)
            suggestions.append({
                "host": host,
                "endpoint": endpoint,
                "method": method,
                "path": path,
                "attack_type": attack_type,
                "parameter": "",
                "hypothesis": rationale,
                "severity": "info",
                "source": "content-discovery",
                "rationale": rationale,
                "priority": "info",
                "status": "queued" if auto_scan else "pending",
                "body_preview": "",
                "ts": time.time(),
            })
            log_event("content-discovery", "finding",
                      f"Discovered {kind}: {path} (HTTP {hit.get('status')})",
                      url=url, source="agent")


def classify_discovery_hit_with_llm(hit: dict) -> Optional[str]:
    """
    Ask the fast-tier LLM to infer a likely attack_type for a discovered
    path. Returns a lowercase attack_type string or None. Never raises —
    any failure degrades to None (caller keeps the generic "recon" type).
    """
    try:
        from dast.ai import bedrock_client
        from dast.ai.prompt_safety import wrap_untrusted, UNTRUSTED_CONTENT_DIRECTIVE

        system = (
            "You are a web security triage assistant. Given a discovered URL path, "
            "return the single most likely vulnerability class to test for it, chosen "
            "from: idor, lfi, sqli, xss, ssrf, open_redirect, auth_bypass, "
            "info_disclosure, recon. Answer with just the label.\n"
            + UNTRUSTED_CONTENT_DIRECTIVE
        )
        user = wrap_untrusted(
            f"path={hit.get('path')} status={hit.get('status')} "
            f"content_type={hit.get('content_type')}",
            "discovered_path",
        )
        result = bedrock_client.invoke_json(
            system=system,
            user=user,
            schema={
                "type": "object",
                "properties": {"attack_type": {"type": "string"}},
                "required": ["attack_type"],
            },
            model_id=bedrock_client.get_fast_model(),
            temperature=0,
        )
        candidate = str(result.get("attack_type", "")).strip().lower()
        _allowed = {
            "idor", "lfi", "sqli", "xss", "ssrf", "open_redirect",
            "auth_bypass", "info_disclosure",
        }
        return candidate if candidate in _allowed else None
    except Exception as exc:
        logger.warning("LLM discovery classification failed", error=str(exc))
        return None


def record_param_hit(store: "SessionStore", hit: dict) -> None:
    """
    Turn a discovered hidden parameter into an AI scan suggestion. Reuses the
    suggestion shape from record_discovery_hit — a hidden parameter is fresh
    attack surface, so it is queued as a neutral "recon" suggestion carrying
    the parameter name; no vulnerability is inferred from the name alone (per
    CLAUDE.md: understand before testing).
    """
    import time
    from urllib.parse import urlparse

    from dast.proxy.plugin_manager import log_event

    url = hit.get("url", "")
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    method = hit.get("method", "GET")
    parameter = hit.get("parameter", "")
    location = hit.get("location", "query")
    reason = hit.get("reason", "")
    if not parameter:
        return

    rationale = (
        f"Hidden parameter '{parameter}' ({location}) discovered via param mining "
        f"[{reason}] — unlinked attack surface, test for injection/access-control"
    )

    suggestions = getattr(store, "active_suggestions", None)
    if suggestions is None:
        return
    endpoint = f"{method} {path}"
    attack_type = "recon"
    key = (host, endpoint, attack_type, parameter)
    existing_keys = {
        (s["host"], s["endpoint"], s["attack_type"], s.get("parameter", ""))
        for s in suggestions
    }
    if key in existing_keys:
        return
    auto_scan = getattr(store, "auto_scan_suggestions", False)
    suggestions.append({
        "host": host,
        "endpoint": endpoint,
        "method": method,
        "path": path,
        "attack_type": attack_type,
        "parameter": parameter,
        "hypothesis": rationale,
        "severity": "info",
        "source": "param-discovery",
        "rationale": rationale,
        "priority": "info",
        "status": "queued" if auto_scan else "pending",
        "body_preview": "",
        "ts": time.time(),
    })
    log_event("param-mining", "finding",
              f"Hidden parameter: {parameter} ({location}, {reason})",
              url=url, source="agent")

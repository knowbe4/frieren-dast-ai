"""
Proxy core routes: entries, scan, scan-queue, clear, overview, hosts, ca.crt.
"""

from __future__ import annotations

import json
from html import escape as _esc
from importlib.metadata import version as _pkg_version
from urllib.parse import parse_qsl

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, Response

from dast.proxy.api.context import DashboardContext
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_APP_VERSION = _pkg_version("dast-ai")

# Headers a normal browser navigation/form-submit already manages itself —
# anything outside this set (Authorization, X-CSRF-Token, custom API keys,
# etc.) cannot be replicated by opening a link, so we warn instead of
# silently dropping it.
_BROWSER_MANAGED_HEADERS = frozenset({
    "host", "cookie", "connection", "content-length", "content-type",
    "accept", "accept-encoding", "accept-language", "user-agent",
    "cache-control", "pragma", "referer", "origin",
    "upgrade-insecure-requests", "dnt", "te", "priority",
})

# HTML forms can only submit as GET or POST — PUT/PATCH/DELETE have no
# faithful browser-navigation equivalent.
_FORM_SUBMITTABLE_METHODS = frozenset({"GET", "POST"})


def _unreproducible_headers(request_headers: dict) -> list:
    return [
        k for k in (request_headers or {})
        if k.lower() not in _BROWSER_MANAGED_HEADERS
        and not k.lower().startswith("sec-")
    ]


def _form_fields_from_body(body: str) -> tuple:
    """Best-effort decomposition of a request body into form fields.

    Returns (fields, warnings). A JSON body is flattened to its top-level
    scalar keys (nested values are dropped and reported as a warning) since
    an HTML form can only submit as application/x-www-form-urlencoded or
    multipart — never raw JSON.
    """
    if not body:
        return [], []
    try:
        data = json.loads(body)
    except Exception:
        return parse_qsl(body, keep_blank_values=True), []

    if not isinstance(data, dict):
        return [], ["The original body was JSON but not an object, so it cannot be "
                     "represented as form fields — reproduction will send no body."]

    fields, dropped = [], []
    for key, value in data.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            fields.append((key, "" if value is None else str(value)))
        else:
            dropped.append(key)

    warning = ("The original body was JSON — it is submitted here as form-encoded "
               "data instead, so the Content-Type the server receives will differ "
               "from the original request.")
    if dropped:
        warning += f" Nested fields were dropped: {', '.join(dropped)}."
    return fields, [warning]


def _build_reproduce_html(entry_dict: dict) -> str:
    method = (entry_dict.get("method") or "GET").upper()
    url = entry_dict.get("url") or ""
    body = entry_dict.get("request_body") or ""
    headers = entry_dict.get("request_headers") or {}

    warnings: list = []
    extra_headers = _unreproducible_headers(headers)
    if extra_headers:
        warnings.append(
            "This request also relied on custom headers a browser navigation "
            "cannot send: " + ", ".join(extra_headers) +
            ". Use \"Copy as cURL\" for an exact reproduction of those."
        )

    is_get_like = method in ("GET", "HEAD")
    warning_html = "".join(f'<li>{_esc(w)}</li>' for w in warnings)
    warning_block = (
        f'<ul class="warn">{warning_html}</ul>' if warnings else ""
    )

    if is_get_like:
        body_html = ""
        action_html = f'<a class="go" href="{_esc(url)}">OK — go to URL</a>'
    else:
        if method not in _FORM_SUBMITTABLE_METHODS:
            warnings.append(
                f"This was a {method} request. Browser forms can only send GET or "
                "POST — it will be submitted as POST, which the server may reject "
                "or misinterpret. Use \"Copy as cURL\" for an exact reproduction."
            )
            warning_html = "".join(f'<li>{_esc(w)}</li>' for w in warnings)
            warning_block = f'<ul class="warn">{warning_html}</ul>'
        fields, body_warnings = _form_fields_from_body(body)
        for w in body_warnings:
            warning_block += f'<ul class="warn"><li>{_esc(w)}</li></ul>'
        inputs = "".join(
            f'<input type="hidden" name="{_esc(k)}" value="{_esc(v)}">'
            for k, v in fields
        )
        form_method = "POST" if method not in _FORM_SUBMITTABLE_METHODS else method
        body_html = (
            f'<form id="repro-form" method="{form_method}" action="{_esc(url)}">'
            f'{inputs}</form>'
        )
        action_html = '<button class="go" onclick="document.getElementById(\'repro-form\').submit()">OK — submit request</button>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Reproducing request</title>
<style>
  body {{ font-family: -apple-system, sans-serif; background:#1a1a1a; color:#ddd; padding:32px; }}
  code {{ background:#2a2a2a; padding:2px 6px; border-radius:3px; }}
  ul.warn {{ background:#332b00; border:1px solid #665500; color:#ffd866; padding:10px 16px; border-radius:4px; }}
  a.go, button.go {{ display:inline-block; margin-top:16px; padding:8px 16px; background:#3a7; color:#fff;
                      text-decoration:none; border:none; border-radius:4px; cursor:pointer; font-size:13px; }}
</style></head>
<body>
  <p>Reproducing: <code>{_esc(method)} {_esc(url)}</code></p>
  {warning_block}
  {body_html}
  <p>{action_html}</p>
</body></html>"""


def make_router(ctx: DashboardContext) -> APIRouter:
    router = APIRouter()
    store = ctx.store
    scan_queue = ctx.scan_queue
    scan_queue_state = ctx.scan_queue_state

    @router.get("/api/version")
    async def get_version():
        return {"version": _APP_VERSION}

    @router.get("/ca.crt")
    async def download_ca():
        if ctx.ca is None:
            return JSONResponse({"error": "CA not available"}, status_code=404)
        return Response(
            content=ctx.ca.ca_cert_pem,
            media_type="application/x-x509-ca-cert",
            headers={"Content-Disposition": "attachment; filename=dast-ai-ca.crt"},
        )

    @router.post("/api/client-error")
    async def client_error(body: dict):
        from dast.utils.logger import get_logger
        logger = get_logger(__name__)
        logger.error(
            "Dashboard JS error",
            message=body.get("message", ""),
            source=body.get("source", ""),
            line=body.get("line", 0),
            col=body.get("col", 0),
            stack=body.get("stack", ""),
        )
        return JSONResponse({"ok": True})

    @router.get("/api/overview")
    async def get_overview():
        all_entries = [e for e in store.all_entries() if e.source != "out-of-scope"]
        all_findings = [f for e in all_entries for f in e.findings if not f.get("dismissed")]

        _seen: set = set()
        _recent_deduped = []
        for e in all_entries:
            for f in e.findings:
                if not f.get("title"):
                    continue
                if f.get("dismissed"):
                    continue
                key = (f.get("title", ""), e.host, e.path, f.get("parameter", ""), f.get("attack_type", ""))
                if key in _seen:
                    continue
                _seen.add(key)
                _recent_deduped.append({
                    "title":        f.get("title", ""),
                    "severity":     f.get("severity", "info"),
                    "cwe":          f.get("cwe", ""),
                    "host":         e.host,
                    "path":         e.path,
                    "entry_id":     e.id,
                    "validated_by": f.get("validated_by") or [],
                    "validated_at": f.get("validated_at"),
                })

        sev_counts: dict = {}
        for f in _recent_deduped:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        recent = sorted(_recent_deduped, key=lambda x: _sev_rank.get(x["severity"], 5))[:20]

        # Active scan detection methods — findings produced by agent probing, not passive rules.
        _ACTIVE_METHODS = frozenset({
            "ai", "browser", "time_based", "oob_callback",
            "error_pattern", "file_match", "secret_pattern", "response_diff",
        })

        def _vby_methods(f: dict) -> set:
            """Return validated_by as a set, normalising legacy strings and lists."""
            raw = f.get("validated_by")
            if not raw:
                return set()
            if isinstance(raw, list):
                # Flatten in case a nested list slipped through
                result = set()
                for v in raw:
                    if isinstance(v, str):
                        result.add(v)
                return result
            if isinstance(raw, str):
                return {raw}
            return set()

        ai_scanned   = len([e for e in all_entries if e.scan_result in ("vulnerable", "safe", "error")])
        ai_confirmed = sum(1 for f in all_findings if _vby_methods(f) & _ACTIVE_METHODS and f.get("confirmed"))
        ai_rejected  = sum(1 for e in all_entries if e.scan_result == "safe" and not any(
            _vby_methods(f) & _ACTIVE_METHODS for f in e.findings))
        passive_findings = sum(1 for f in all_findings if "passive" in _vby_methods(f))
        unique_hosts = len({e.host for e in all_entries if e.source not in ("imported", "agent")})

        return {
            "total_requests":   len(all_entries),
            "unique_hosts":     unique_hosts,
            "total_findings":   len(all_findings),
            "sev_counts":       sev_counts,
            "recent_findings":  recent,
            "ai_scanned":       ai_scanned,
            "ai_confirmed":     ai_confirmed,
            "ai_rejected":      ai_rejected,
            "passive_findings": passive_findings,
            "pending_imports":  len(store.pending_import_findings),
        }

    @router.get("/api/hosts")
    async def get_hosts():
        from collections import Counter
        from urllib.parse import urlparse as _up
        counts: Counter = Counter()
        for e in store.all_entries():
            if e.source in ("imported", "out-of-scope"):
                continue
            p = _up(e.url)
            if p.scheme and p.netloc:
                counts[f"{p.scheme}://{p.netloc}"] += 1
        settings = ctx.settings
        result = []
        for base_url, count in counts.most_common():
            in_scope = settings.is_in_scope(base_url + "/") if settings else True
            result.append({"base_url": base_url, "count": count, "in_scope": in_scope})
        return result

    @router.get("/api/entries")
    async def get_entries():
        return [e.to_dict() for e in store.all_entries()]

    @router.get("/api/entry/{entry_id}")
    async def get_entry(entry_id: str):
        e = store.get_entry(entry_id)
        if not e:
            return JSONResponse({"error": "not found"}, status_code=404)
        return e.to_dict(include_bodies=True)

    @router.get("/api/reproduce/{entry_id}")
    async def reproduce_entry(entry_id: str):
        """
        Serve an HTML page that reproduces a captured request as a real browser
        navigation — GET redirects immediately, POST auto-submits a form. Both
        run in the browser's own tab, so session cookies (including SameSite)
        are sent exactly as they would be for a normal click-through, which a
        fetch()-from-JS or copy-paste cURL cannot replicate for CSRF-style PoCs.
        """
        e = store.get_entry(entry_id)
        if not e:
            return JSONResponse({"error": "not found"}, status_code=404)
        html = _build_reproduce_html(e.to_dict(include_bodies=True))
        logger.info("reproduce-in-browser page served", entry_id=entry_id, method=e.method, url=e.url)
        return HTMLResponse(content=html)

    @router.post("/api/scan")
    async def queue_scan(body: dict):
        import re as _re
        import json as _json

        if body.get("scan_all"):
            entries = [e for e in store.all_entries() if not e.queued_for_scan]
        else:
            ids = body.get("ids", [])
            entries = [store.get_entry(i) for i in ids if store.get_entry(i)]

        queued = 0
        for e in entries:
            if e and not e.queued_for_scan:
                e.queued_for_scan = True
                # Explicit user action — allow a deliberate re-scan by bypassing
                # dedup. This does NOT bypass the ai_mode gate: active agents are
                # the AI feature, so with AI mode off the scan worker skips this
                # entry (only passive plugins ran on the wire). It also does not
                # bypass scope. The worker enforces both.
                e.ai_queued = True
                if scan_queue_state:
                    operation = ""
                    if e.request_body:
                        try:
                            body_text = e.request_body.decode("utf-8", errors="replace")
                            data = _json.loads(body_text)
                            if isinstance(data, dict) and "query" in data:
                                op = data.get("operationName")
                                if op:
                                    operation = str(op)
                                else:
                                    m = _re.search(r'\b(query|mutation|subscription)\s+(\w+)', data.get("query", ""))
                                    if m:
                                        operation = f"{m.group(1)} {m.group(2)}"
                        except Exception:
                            pass
                    scan_queue_state.enqueue(e.id, e.method, e.url, e.host, operation=operation)
                await scan_queue.put(e.id)
                queued += 1

        return {"queued": queued}

    @router.get("/api/scan-queue")
    async def get_scan_queue():
        if not scan_queue_state:
            return {"paused": False, "pending": [], "running": [], "completed": [],
                    "pending_count": 0, "running_count": 0, "completed_count": 0}
        return scan_queue_state.to_dict()

    @router.post("/api/scan-queue/pause")
    async def pause_scan_queue():
        if scan_queue_state:
            scan_queue_state.pause()
        return {"ok": True, "paused": True}

    @router.post("/api/scan-queue/resume")
    async def resume_scan_queue():
        if scan_queue_state:
            scan_queue_state.resume()
        return {"ok": True, "paused": False}

    @router.post("/api/scan-queue/cancel")
    async def cancel_scan_item(body: dict):
        entry_id = str(body.get("id", "")).strip()
        if scan_queue_state and entry_id:
            scan_queue_state.cancel(entry_id)
        return {"ok": True}

    @router.post("/api/scan-queue/stop")
    async def stop_running_scan(body: dict):
        entry_id = str(body.get("id", "")).strip()
        stopped = False
        if scan_queue_state and entry_id:
            stopped = scan_queue_state.stop_running(entry_id)
        return {"ok": True, "stopped": stopped}

    @router.post("/api/scan-queue/cancel-all")
    async def cancel_all_pending():
        if scan_queue_state:
            scan_queue_state.cancel_all_pending()
        return {"ok": True}

    @router.post("/api/scan-queue/clear-completed")
    async def clear_completed():
        if scan_queue_state:
            scan_queue_state.completed.clear()
            scan_queue_state.clear_cancelled()
        return {"ok": True}

    @router.post("/api/manual/send-to-ai")
    async def manual_send_to_ai(body: dict):
        entry_id = str(body.get("entry_id", "")).strip()
        note = str(body.get("note", "")).strip()
        entry = store.get_entry(entry_id)
        if not entry:
            return JSONResponse({"error": "entry not found"}, status_code=404)
        entry.ai_queued = True
        entry.manual_note = note or None
        if not entry.queued_for_scan:
            entry.queued_for_scan = True
            if scan_queue_state:
                scan_queue_state.enqueue(entry.id, entry.method, entry.url, entry.host)
            await scan_queue.put(entry.id)
        store._notify(entry)
        return {"ok": True, "entry_id": entry_id}

    @router.post("/api/findings/validate")
    async def validate_finding_with_ai(body: dict):
        """
        Run the Red-Team Validator on a specific finding that was detected by
        pattern/passive means and has not yet been validated by the LLM.

        Body: { entry_id, finding_index }
        Returns: { confirmed, confidence, reasoning, validated_by }
        """
        from dast.ai.agent_base import AgentFinding
        from dast.scanners.active_checks import CheckTarget
        from dast.ai import red_team

        entry_id = str(body.get("entry_id", "")).strip()
        finding_index = body.get("finding_index")
        if finding_index is None:
            return JSONResponse({"error": "finding_index required"}, status_code=400)

        entry = store.get_entry(entry_id)
        if not entry:
            return JSONResponse({"error": "entry not found"}, status_code=404)

        findings = entry.findings or []
        try:
            fidx = int(finding_index)
            finding_dict = findings[fidx]
        except (IndexError, TypeError, ValueError):
            return JSONResponse({"error": "finding not found"}, status_code=404)

        # Reconstruct a minimal AgentFinding from the stored dict
        af = AgentFinding(
            title=finding_dict.get("title", ""),
            severity=finding_dict.get("severity", "medium"),
            cwe=finding_dict.get("cwe", ""),
            attack_type=finding_dict.get("attack_type", ""),
            evidence=finding_dict.get("evidence", ""),
            payload=finding_dict.get("payload", ""),
            parameter=finding_dict.get("parameter", ""),
            url=entry.url,
            request_method=entry.method,
            reasoning=finding_dict.get("reasoning", ""),
            raw_response_snippet=finding_dict.get("snippet", ""),
        )

        # Build a minimal CheckTarget from the entry
        from urllib.parse import urlparse, parse_qs
        _parsed = urlparse(entry.url)
        _params = [
            {"name": k, "location": "query", "value": v[0]}
            for k, v in parse_qs(_parsed.query).items()
        ]
        target = CheckTarget(
            method=entry.method,
            url=entry.url,
            headers=dict(entry.request_headers or {}),
            body=entry.request_body.decode("utf-8", errors="replace") if entry.request_body else None,
            params=_params,
        )

        # Attach app/threat-model hints if available
        if store.discovery_engine:
            host = entry.host
            profile = store.discovery_engine.get_app_profile(host)
            if profile:
                hint = profile.to_coordinator_hint() if hasattr(profile, "to_coordinator_hint") else ""
                if hint:
                    target.app_profile_hint = hint
            threat = store.discovery_engine.get_threat_model(host)
            if threat:
                hint = threat.to_validator_hint() if hasattr(threat, "to_validator_hint") else ""
                if hint:
                    target.threat_model_hint = hint

        confidence_threshold = ctx._scan_cfg.get("confidence_threshold", 0.5)

        confirmed, confidence, reasoning = await red_team.validate(
            finding=af,
            target=target,
            confidence_threshold=confidence_threshold,
        )

        # Update the stored finding in-place
        vby = finding_dict.get("validated_by", "pattern")
        existing = vby if isinstance(vby, list) else [vby]
        if "ai" not in existing:
            existing.append("ai")
        finding_dict["validated_by"] = existing
        finding_dict["confirmed"] = confirmed
        finding_dict["confidence"] = round(confidence, 3)
        if reasoning:
            finding_dict["reasoning"] = reasoning

        store._notify(entry)

        return {
            "ok": True,
            "confirmed": confirmed,
            "confidence": round(confidence, 3),
            "reasoning": reasoning,
            "validated_by": existing,
        }

    @router.get("/api/mode")
    async def get_mode():
        return {"ai_mode": store.ai_mode}

    @router.post("/api/mode")
    async def set_mode(body: dict):
        store.ai_mode = bool(body.get("ai_mode", False))
        return {"ai_mode": store.ai_mode}

    @router.post("/api/clear")
    async def clear():
        store.clear()
        return {"ok": True}

    @router.post("/api/search")
    async def search_entries(body: dict):
        """
        Full-text search across request and/or response bodies.

        Body params:
          query   — search string (required, case-insensitive)
          scope   — "all" | "request" | "response" (default "all")
          regex   — bool, treat query as regex (default false)
          host    — optional host filter

        Returns list of matching entry summaries with match context.
        """
        import re as _re

        query = (body.get("query") or "").strip()
        if not query:
            return []

        scope  = body.get("scope", "all")   # "all" | "request" | "response"
        use_re = bool(body.get("regex", False))
        host_filter = body.get("host", "")

        # Compile pattern
        try:
            flags = _re.IGNORECASE | _re.DOTALL
            pattern = _re.compile(query if use_re else _re.escape(query), flags)
        except _re.error as exc:
            return JSONResponse({"error": f"Invalid regex: {exc}"}, status_code=400)

        results = []
        for entry in store.all_entries():
            if host_filter and entry.host != host_filter:
                continue

            matches = []

            # Search request body
            if scope in ("all", "request") and entry.request_body:
                try:
                    req_text = entry.request_body.decode("utf-8", errors="replace")
                except Exception:
                    req_text = ""
                for m in pattern.finditer(req_text):
                    start = max(0, m.start() - 60)
                    snippet = req_text[start:m.end() + 60].replace("\n", " ").strip()
                    matches.append({"scope": "request", "snippet": snippet[:200]})
                    if len(matches) >= 3:
                        break

            # Search response body
            if scope in ("all", "response") and entry.response_body:
                try:
                    resp_text = entry.response_body.decode("utf-8", errors="replace")
                except Exception:
                    resp_text = ""
                for m in pattern.finditer(resp_text):
                    start = max(0, m.start() - 60)
                    snippet = resp_text[start:m.end() + 60].replace("\n", " ").strip()
                    matches.append({"scope": "response", "snippet": snippet[:200]})
                    if len(matches) >= 3:
                        break

            if matches:
                results.append({
                    "id":       entry.id,
                    "method":   entry.method,
                    "url":      entry.url,
                    "host":     entry.host,
                    "path":     entry.path,
                    "status":   entry.response_status,
                    "source":   entry.source,
                    "matches":  matches,
                })

            if len(results) >= 500:
                break

        return results

    return router

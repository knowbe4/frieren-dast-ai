"""
Standalone report validator — runs Frieren DAST-AI agents against a live target
without starting the proxy.

Usage examples:

  # Basic — cookie from browser DevTools
  uv run python scripts/validate_report.py \\
      --report path/to/report.md \\
      --target https://app.example.com \\
      --cookie ".AspNetCore.Cookies=abc123"

  # Open browser for manual login (captures cookies automatically)
  uv run python scripts/validate_report.py \\
      --report path/to/report.md \\
      --target https://app.example.com \\
      --browse

  # Headless login with credentials
  uv run python scripts/validate_report.py \\
      --report path/to/report.md \\
      --target https://app.example.com \\
      --auth-url https://app.example.com/login \\
      --username user@example.com \\
      --password secret

  # Limit to specific attack types
  uv run python scripts/validate_report.py \\
      --report path/to/report.md \\
      --target https://app.example.com \\
      --cookie "..." --only idor nosql

  # Save JSON results
  uv run python scripts/validate_report.py \\
      --report path/to/report.md \\
      --target https://app.example.com \\
      --cookie "..." --output results.json

Or via make:
  make validate REPORT=path/to/report.md TARGET=https://app.example.com BROWSE=1
  make validate REPORT=... TARGET=... AUTH_URL=... USERNAME=... PASSWORD=...
  make validate REPORT=... TARGET=... COOKIE="..."
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Validate security report findings against a live target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage examples:")[1] if "Usage examples:" in __doc__ else "",
    )
    p.add_argument("--report", required=True, help="Path to security report (.md or .json)")
    p.add_argument("--target", required=True, help="Base URL, e.g. https://app.example.com")

    auth = p.add_argument_group("authentication (pick one)")
    auth.add_argument("--cookie", default="", help="Session cookie string from browser DevTools")
    auth.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                      help="Extra request header (repeat for multiple)")
    auth.add_argument("--browse", action="store_true",
                      help="Open a visible browser — log in manually, cookies captured automatically")
    auth.add_argument("--auth-url", default="", help="Login page URL for headless credential login")
    auth.add_argument("--username", default="", help="Username for headless login")
    auth.add_argument("--password", default="", help="Password for headless login")

    p.add_argument("--only", nargs="*", default=[], metavar="TYPE",
                   help="Limit to attack types: idor nosql xss sqli ssrf etc.")
    p.add_argument("--output", default="", help="Write JSON results to this file")
    p.add_argument("--confidence", type=float, default=0.5,
                   help="Confidence threshold for red-team validator (default: 0.5)")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="Per-request timeout in seconds (default: 15)")
    p.add_argument("--login-timeout", type=int, default=300,
                   help="Seconds to wait for browser login (default: 300)")

    code = p.add_argument_group("source code context (optional — improves agent accuracy)")
    code.add_argument("--source", action="append", default=[], metavar="PATH_OR_URL",
                      help="Local path or GitLab URL to index for code context (repeat for multiple)")
    code.add_argument("--gitlab-token", default="", metavar="TOKEN",
                      help="GitLab personal access token (needed for private repos)")

    return p


async def _capture_cookies_via_browser(target: str, headless: bool = False,
                                       timeout_seconds: int = 300) -> Dict[str, str]:
    """
    Open a visible Chromium window pointed at target.
    Captures auth headers and detects the app's API base path prefix (e.g. /app)
    by observing real API calls the app makes after login, then waits for Enter.
    Returns auth_headers dict plus "x-dast-base-path" if a prefix is detected.
    """
    from playwright.async_api import async_playwright
    import re as _re

    auth_headers: Dict[str, str] = {}
    target_host = urlparse(target).netloc
    observed_api_paths: list = []
    last_request_time: list = [0.0]  # mutable for closure

    def _on_request(request) -> None:
        last_request_time[0] = time.monotonic()
        for k, v in (request.headers or {}).items():
            if k.lower() in ("authorization", "x-auth-token", "x-api-key", "x-session-token"):
                auth_headers[k.lower()] = v
        req_url = request.url or ""
        if target_host in req_url:
            path = urlparse(req_url).path
            if "/api/" in path and path not in observed_api_paths:
                observed_api_paths.append(path)
                print(f"[browser] {request.method} {path}", file=sys.stderr)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=False,
            args=["--ignore-certificate-errors", "--window-size=1440,900"],
        )
        context = await browser.new_context(ignore_https_errors=True,
                                            viewport={"width": 1440, "height": 900})
        context.on("request", _on_request)
        page = await context.new_page()

        print(f"\n[*] Browser opened at {target}", file=sys.stderr)
        try:
            await page.goto(target, timeout=20000, wait_until="domcontentloaded")
        except Exception as e:
            print(f"[warn] Initial navigation: {e}", file=sys.stderr)

        print("[*] Log in and select your profile. Waiting for app to load...", file=sys.stderr)

        # Auto-detect when app has finished loading: wait until API calls have been
        # seen AND there have been no new API calls for 3 seconds.
        # Falls back to prompting Enter after timeout_seconds if never stabilises.
        deadline = time.monotonic() + timeout_seconds
        stable_for = 3.0
        notified = False
        while time.monotonic() < deadline:
            await asyncio.sleep(1)
            idle = time.monotonic() - last_request_time[0]
            if observed_api_paths and idle >= stable_for:
                break
            if not notified and observed_api_paths:
                notified = True
                print("[*] App loading... waiting for activity to settle", file=sys.stderr)
        else:
            print(f"[warn] Timeout — capturing what was collected so far", file=sys.stderr)

        # Allow manual override: if nothing was detected, ask user to confirm
        if not observed_api_paths:
            print("\n" + "=" * 60, file=sys.stderr)
            print("  No API calls detected. Log in, then press Enter.", file=sys.stderr)
            print("=" * 60, file=sys.stderr)

            def _wait_for_enter() -> None:
                try:
                    with open("/dev/tty") as tty:
                        tty.readline()
                except OSError:
                    sys.stdin.readline()

            loop = asyncio.get_event_loop()
            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, _wait_for_enter),
                    timeout=float(timeout_seconds),
                )
            except asyncio.TimeoutError:
                pass

        print(f"[*] Captured {len(observed_api_paths)} unique API path(s)", file=sys.stderr)
        all_cookies = await context.cookies()
        await browser.close()

    if not all_cookies:
        print("[warn] No cookies captured", file=sys.stderr)
        return auth_headers

    cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in all_cookies if c.get("name"))
    if cookie_str:
        auth_headers["cookie"] = cookie_str
    print(f"[*] {len(all_cookies)} cookie(s) captured", file=sys.stderr)

    # Detect base path prefix from observed API calls (e.g. /app/api/... → prefix /app)
    if observed_api_paths:
        prefixes: set = set()
        for p in observed_api_paths[:20]:
            m = _re.match(r"^((?:/[^/]+)?)/api/", p)
            if m:
                prefixes.add(m.group(1))
        if len(prefixes) == 1:
            prefix = prefixes.pop()
            if prefix:
                auth_headers["x-dast-base-path"] = prefix
                print(f"[*] Detected API base path: {prefix}", file=sys.stderr)

    return auth_headers


async def _headless_login(auth_url: str, username: str, password: str) -> Dict[str, str]:
    """Headless login directly to auth_url (no proxy). Returns auth headers."""
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout

    print(f"[*] Headless login to {auth_url}", file=sys.stderr)
    auth_headers: Dict[str, str] = {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--ignore-certificate-errors"],
        )
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        def _on_request(req) -> None:
            for k, v in (req.headers or {}).items():
                if k.lower() in ("authorization", "x-auth-token", "x-api-key"):
                    auth_headers[k.lower()] = v

        page.on("request", _on_request)

        try:
            await page.goto(auth_url, timeout=20000, wait_until="domcontentloaded")

            user_sel = "input[type=email],input[type=text],input[name*=user],input[name*=email],input[id*=user],input[id*=email]"
            pass_sel = "input[type=password]"
            submit_sel = "button[type=submit],input[type=submit]"

            user_field = page.locator(user_sel).first
            await user_field.wait_for(state="visible", timeout=8000)
            await user_field.fill(username)

            pass_field = page.locator(pass_sel).first
            await pass_field.wait_for(state="visible", timeout=5000)
            await pass_field.fill(password)

            btn = page.locator(submit_sel).first
            await btn.click()
            await page.wait_for_load_state("networkidle", timeout=15000)

            cookies = await context.cookies()
            if cookies:
                auth_headers["cookie"] = "; ".join(
                    f"{c['name']}={c['value']}" for c in cookies if c.get("name")
                )
                print(f"[*] Login successful — captured {len(cookies)} cookie(s)", file=sys.stderr)
            else:
                print("[warn] Login completed but no cookies found", file=sys.stderr)

        except PWTimeout:
            print("[warn] Login timed out — check --auth-url and selectors", file=sys.stderr)
        except Exception as e:
            print(f"[warn] Headless login failed: {e}", file=sys.stderr)
        finally:
            await browser.close()

    return auth_headers


def _borrow_real_body(method: str, url: str, host: str, browse_entries: List) -> tuple[Optional[bytes], str]:
    """Find a matching real request body from browse entries (if a session file is passed)."""
    path = urlparse(url).path
    segs = [s for s in path.split("/") if s]
    prefix = "/" + "/".join(segs[:-1]) if len(segs) > 1 else path
    for entry in reversed(browse_entries):
        if getattr(entry, "source", "") in ("agent", "imported"):
            continue
        if entry.host != host:
            continue
        if entry.method != method:
            continue
        if not entry.request_body:
            continue
        ep = urlparse(entry.url).path
        if ep == path or ep.startswith(prefix):
            bs = entry.request_body[:200].decode("utf-8", errors="replace").strip()
            if bs.startswith("{") or bs.startswith("[") or "=" in bs[:80]:
                return entry.request_body, entry.request_headers.get("content-type", "")
    return None, ""


def _build_entry(nf, resolved_url: str, auth_headers: Dict[str, str], browse_entries: List,
                 use_code_fix: bool = False):
    from dast.proxy.session_store import ProxyEntry
    from dast.importers.dast_importer import build_request_body, build_request_headers

    parsed = urlparse(resolved_url)
    host = parsed.netloc
    path = parsed.path or "/"

    headers = build_request_headers(nf)
    headers.update(auth_headers)

    req_body = build_request_body(nf)

    body_str = (req_body or b"").decode("utf-8", errors="replace").strip()
    body_looks_fake = (
        not body_str
        or (not body_str.startswith("{")
            and not body_str.startswith("[")
            and "=" not in body_str[:100])
    )
    if body_looks_fake and nf.method in ("POST", "PUT", "PATCH"):
        borrowed, ct = _borrow_real_body(nf.method, resolved_url, host, browse_entries)
        if borrowed:
            req_body = borrowed
            if ct and not headers.get("content-type"):
                headers["content-type"] = ct
            body_looks_fake = False

    # If source code is indexed, always ask LLM to generate the correct body based on the
    # actual controller/DTO — the importer's guessed body may have wrong field names or types
    if use_code_fix and nf.method in ("POST", "PUT", "PATCH"):
        fixed = _fix_body_from_code(nf, resolved_url)
        if fixed:
            req_body = fixed.encode("utf-8")
            if not headers.get("content-type"):
                headers["content-type"] = "application/json"
            print(f"[*] Body corrected via code hint: {path}", file=sys.stderr)

    return ProxyEntry(
        id=f"validate-{hash(resolved_url) & 0xFFFFFF:06x}",
        method=nf.method,
        url=resolved_url,
        host=host,
        path=path,
        request_headers=headers,
        request_body=req_body,
        source="imported",
        import_hints=[{
            "parameter": nf.parameter,
            "payload": nf.payload,
            "attack_type": nf.attack_type,
        }] if (nf.parameter or nf.payload) else [],
    )


def _parse_with_retry(raw_text: str):
    """
    Parse findings with LLM. If JSON is malformed (LLM failed to escape special
    chars in payload strings), retry with a prompt that asks for simpler output.
    """
    from dast.importers.dast_importer import parse_findings, _preprocess, _PARSE_SYSTEM, _MAX_CONTENT_CHARS
    from dast.ai import bedrock_client
    from dast.importers.dast_importer import NormalisedFinding, _normalise_severity
    import re, json as _json

    # First attempt — normal path
    findings = parse_findings(raw_text)
    if findings:
        return findings

    # Retry: ask the LLM for minimal fields only (no payloads that break JSON)
    print("[*] First parse failed — retrying with simplified prompt", file=sys.stderr)
    _SIMPLE_SYSTEM = """\
You are a security findings parser. Extract each finding and return ONLY a JSON array.
Each item must have exactly these fields (strings only, no nested objects):
  title, severity, attack_type, path, method, content_type, request_body, parameter, host_hint

Rules:
- severity: critical|high|medium|low|info
- attack_type: xss|sqli|nosql|ssrf|lfi|ssti|idor|auth_bypass|cmdi|xxe|csrf|other
- method: GET|POST|PUT|PATCH|DELETE
- path: URL path like /api/users/{id}
- request_body: simple JSON string with placeholder values, or empty for GET
- NO payloads, NO evidence text, NO special characters that could break JSON

Respond ONLY with a JSON array: [{"title":"...","severity":"...","attack_type":"...","path":"...","method":"...","content_type":"...","request_body":"...","parameter":"...","host_hint":"..."},...]
No markdown fence, no explanation.
"""
    processed = _preprocess(raw_text)
    try:
        loop = asyncio.get_event_loop()
        raw = bedrock_client.invoke(
            system=_SIMPLE_SYSTEM,
            user=f"Report:\n{processed[:_MAX_CONTENT_CHARS]}",
            max_tokens=4096,
        )
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rstrip()
            if raw.endswith("```"):
                raw = raw[:-3]
        raw = raw.strip()
        data = _json.loads(raw)
        if isinstance(data, dict):
            data = data.get("findings", [])
        out = []
        for f in data:
            if not isinstance(f, dict):
                continue
            out.append(NormalisedFinding(
                title=str(f.get("title", "Imported Finding")),
                severity=_normalise_severity(f.get("severity", "medium")),
                cwe=str(f.get("cwe", "")),
                attack_type=str(f.get("attack_type", "other")),
                url=str(f.get("url", "")),
                path=str(f.get("path", "")),
                method=str(f.get("method", "GET")).upper(),
                content_type=str(f.get("content_type", "")),
                request_body=str(f.get("request_body", "")),
                parameter=str(f.get("parameter", "")),
                payload="",
                evidence="",
                host_hint=str(f.get("host_hint", "")),
            ))
        print(f"[*] Retry parse: {len(out)} finding(s)", file=sys.stderr)
        return out
    except Exception as e:
        print(f"[error] Retry parse also failed: {e}", file=sys.stderr)
        return []


async def _index_sources(sources: List[str], gitlab_token: str = "") -> None:
    """
    Index source code paths/URLs so lookup_code_for_path() can inject relevant
    snippets into the Coordinator's planner prompt for each endpoint.
    Phase 1 only (pattern scan, no LLM) — fast and non-blocking.
    """
    if not sources:
        return
    from dast.code_analysis import run_analysis, create_analysis_id

    print(f"\n[*] Indexing {len(sources)} source(s)...", file=sys.stderr)
    for src in sources:
        analysis_id = create_analysis_id()
        try:
            result = await run_analysis(
                analysis_id=analysis_id,
                sources=[src],
                gitlab_token=gitlab_token,
            )
            print(f"[*] Indexed: {src} ({result.files_scanned} files, "
                  f"{len(result.pattern_matches)} pattern matches)", file=sys.stderr)
        except Exception as exc:
            print(f"[warn] Failed to index {src}: {exc}", file=sys.stderr)


def _fix_body_from_code(nf, resolved_url: str) -> str:
    """
    When source code is indexed, use lookup_code_for_path to find the controller
    and ask the LLM to generate the correct request body based on the actual DTO.
    Only called when the importer-generated body looks wrong (400 responses likely).
    """
    from dast.code_analysis import lookup_code_for_path
    from dast.ai import bedrock_client
    import json as _json

    path = urlparse(resolved_url).path
    code_hint = lookup_code_for_path(path)
    if not code_hint:
        return ""

    system = (
        "You are a security testing assistant. Given source code for an API endpoint, "
        "generate a minimal valid JSON request body that will return HTTP 200. "
        "Use realistic placeholder values (deployment=1, page=0, pageSize=10, filter='{}', etc.). "
        "Respond ONLY with valid JSON. No markdown, no explanation."
    )
    user = (
        f"Endpoint: {nf.method} {path}\n"
        f"Current body (may be wrong): {nf.request_body or '(empty)'}\n\n"
        f"{code_hint}"
    )
    try:
        result = bedrock_client.invoke_json(
            system=system, user=user,
            model_id=bedrock_client.get_fast_model(),
            max_tokens=512,
        )
        if isinstance(result, dict) and result:
            return _json.dumps(result)
    except Exception as exc:
        print(f"[warn] Body fix LLM failed for {path}: {exc}", file=sys.stderr)
    return ""


_ATTACKER_SIM_SYSTEM = """\
You are a penetration tester validating a DAST finding against a live target.
You only report vulnerabilities you can actually exploit.

Work ONLY with the code and endpoint provided. Do NOT invent code, security controls,
or entry points that are not shown.

Your job: generate 3-6 concrete HTTP request payloads to test the reported vulnerability.

General rules:
- Read the source code context carefully — use the exact field names, types, and routes shown
- Infer the backend stack from cookie names, imports, controller naming, and field casing
- For NoSQL injection: try operator injection in filter/query string fields, enum boundary abuse,
  wildcard/empty values, and nested operator objects
- For IDOR: try substituting other users' IDs, incrementing IDs, using 0/null/-1
- For auth bypass: try removing auth headers, using expired tokens, parameter pollution
- For privilege escalation: try setting role/admin/deployment fields to higher-privilege values
- Do NOT use payloads that destroy data (DROP, DELETE, TRUNCATE, rm -rf)
- Safe proof-of-concept only

Important: MongoDB operators ($where, $ne, $or, $gt, etc.) may be filtered by WAFs.
When testing NoSQL injection, also try:
- Sending numeric/enum boundary values that expand scope (e.g. deployment=0 for ALL)
- Sending empty or wildcard filter strings: "{}", "", "1==1"
- Sending malformed JSON to trigger different error paths
- Changing pageSize to a very large number to confirm data exposure

Response format — return ONLY valid JSON, no markdown fence:
{
  "payloads": [
    {
      "description": "what this tests",
      "method": "POST",
      "path": "/api/endpoint",
      "headers": {"Content-Type": "application/json"},
      "body": "...",
      "success_indicator": "HTTP 200 with data / response size increases / different error"
    }
  ]
}
"""


def _generate_targeted_payloads(nf, resolved_url: str, auth_headers: dict) -> list:
    """
    Use the attacker simulation prompt (adapted from orchestrator-ai) to generate
    targeted payloads for this specific finding + endpoint + source code context.
    Returns a list of payload dicts ready to execute.
    """
    from dast.code_analysis import lookup_code_for_path
    from dast.ai import bedrock_client
    import json as _json

    parsed = urlparse(resolved_url)
    path = parsed.path
    code_hint = lookup_code_for_path(path) or ""

    user = (
        f"Finding: {nf.title}\n"
        f"Attack type: {nf.attack_type}\n"
        f"Endpoint: {nf.method} {resolved_url}\n"
        f"Parameter: {nf.parameter or '(unknown)'}\n"
        f"Reported payload: {nf.payload or '(none)'}\n"
        f"Evidence: {nf.evidence or '(none)'}\n"
        f"\nSource code context:\n{code_hint[:4000]}" if code_hint else
        f"Finding: {nf.title}\n"
        f"Attack type: {nf.attack_type}\n"
        f"Endpoint: {nf.method} {resolved_url}\n"
        f"Parameter: {nf.parameter or '(unknown)'}\n"
        f"Reported payload: {nf.payload or '(none)'}\n"
    )

    try:
        result = bedrock_client.invoke_json(
            system=_ATTACKER_SIM_SYSTEM,
            user=user,
            model_id=bedrock_client.get_validation_model(),
            max_tokens=2048,
        )
        payloads = result.get("payloads", []) if isinstance(result, dict) else []
        print(f"[*] Attacker sim generated {len(payloads)} payload(s) for {path}", file=sys.stderr)
        return payloads
    except Exception as exc:
        print(f"[warn] Attacker sim failed for {path}: {exc}", file=sys.stderr)
        return []


async def _execute_sim_payloads(payloads: list, auth_headers: dict,
                                base_url: str, timeout: float) -> list:
    """Execute payloads generated by attacker simulation, return results."""
    import httpx as _httpx
    import json as _json

    results = []
    parsed_base = urlparse(base_url)
    host = f"{parsed_base.scheme}://{parsed_base.netloc}"

    async with _httpx.AsyncClient(verify=False, timeout=timeout,
                                   follow_redirects=False) as client:
        for p in payloads:
            method = p.get("method", "GET").upper()
            path = p.get("path", "/")
            url = host + path
            headers = dict(p.get("headers") or {})
            headers.update(auth_headers)
            body_raw = p.get("body", "")
            if isinstance(body_raw, dict):
                body = _json.dumps(body_raw)
            else:
                body = str(body_raw) if body_raw else None

            try:
                resp = await client.request(
                    method=method, url=url, headers=headers,
                    content=body.encode() if body else None,
                )
                results.append({
                    "description": p.get("description", ""),
                    "url": url,
                    "status": resp.status_code,
                    "response_size": len(resp.content),
                    "body_preview": resp.text[:300],
                    "success_indicator": p.get("success_indicator", ""),
                })
                print(f"    [{resp.status_code}] {method} {path} — {len(resp.content)}b",
                      file=sys.stderr)
            except Exception as exc:
                results.append({
                    "description": p.get("description", ""),
                    "url": url,
                    "error": str(exc),
                })
    return results


async def _run_finding(nf, resolved_url, auth_headers, browse_entries, confidence, timeout,
                       use_code_fix: bool = False) -> dict:
    from dast.proxy.runner import _entry_to_check_target
    from dast.scanners.active_checks import run_active_checks

    entry = _build_entry(nf, resolved_url, auth_headers, browse_entries, use_code_fix=use_code_fix)
    target = _entry_to_check_target(entry, store=None)
    if target is None:
        return {"url": resolved_url, "attack_type": nf.attack_type, "title": nf.title,
                "error": "skipped (dangerous path or no params)"}

    t0 = time.monotonic()
    try:
        findings = await run_active_checks(
            target,
            proxy_url=None,
            confidence_threshold=confidence,
            timeout=timeout,
        )
    except Exception as exc:
        return {"url": resolved_url, "attack_type": nf.attack_type, "title": nf.title,
                "error": str(exc), "elapsed": round(time.monotonic() - t0, 1)}

    coordinator_findings = [
        {
            "title": getattr(f, "title", ""),
            "severity": getattr(f, "severity", ""),
            "cwe": getattr(f, "cwe", ""),
            "confidence": getattr(f, "confidence", 0.0),
            "evidence": (getattr(f, "evidence", "") or "")[:400],
            "payload": getattr(f, "payload", ""),
        }
        for f in (findings or [])
    ]

    # Stage 2: attacker simulation — run when source code is indexed, regardless of
    # coordinator result (catches cases where coordinator's generic payloads miss)
    sim_results = []
    if use_code_fix:
        print(f"[*] Running attacker simulation for {urlparse(resolved_url).path}",
              file=sys.stderr)
        payloads = _generate_targeted_payloads(nf, resolved_url, auth_headers)
        if payloads:
            sim_results = await _execute_sim_payloads(
                payloads, auth_headers, resolved_url, timeout
            )

    confirmed = bool(coordinator_findings) or any(
        r.get("status") == 200 and not r.get("error") for r in sim_results
        if r.get("response_size", 0) > 100
    )

    return {
        "url": resolved_url,
        "attack_type": nf.attack_type,
        "title": nf.title,
        "elapsed": round(time.monotonic() - t0, 1),
        "confirmed": confirmed,
        "findings": coordinator_findings,
        "sim_results": sim_results,
    }


async def main(args: argparse.Namespace) -> int:
    from dast.importers.dast_importer import parse_findings, resolve_url

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"[error] Report not found: {report_path}", file=sys.stderr)
        return 1

    # Resolve auth headers — priority: --cookie/--header > --browse > --auth-url
    auth_headers: Dict[str, str] = {}

    if args.cookie:
        auth_headers["cookie"] = args.cookie
    for h in args.header:
        if ":" in h:
            name, _, value = h.partition(":")
            auth_headers[name.strip().lower()] = value.strip()

    if not auth_headers and args.auth_url and args.username:
        auth_headers = await _headless_login(args.auth_url, args.username, args.password)
    elif args.browse:
        browser_result = await _capture_cookies_via_browser(args.target, timeout_seconds=args.login_timeout)
        # Merge — cookie/header args take precedence, but base path always comes from browser
        base_path = browser_result.pop("x-dast-base-path", "")
        if base_path and not args.target.rstrip("/").endswith(base_path):
            args.target = args.target.rstrip("/") + base_path
            print(f"[*] Target adjusted to: {args.target}", file=sys.stderr)
        if not auth_headers:
            auth_headers = browser_result
        else:
            auth_headers.update({k: v for k, v in browser_result.items() if k not in auth_headers})

    if not auth_headers:
        print("[warn] No auth configured — requests will be unauthenticated", file=sys.stderr)

    # Index source code (if provided) — populates lookup_code_for_path() for all agents
    if args.source:
        await _index_sources(args.source, gitlab_token=args.gitlab_token)

    # Parse report
    print(f"\n[*] Parsing: {report_path.name}", file=sys.stderr)
    raw_text = report_path.read_text(encoding="utf-8")
    findings = _parse_with_retry(raw_text)
    print(f"[*] {len(findings)} finding(s) normalised", file=sys.stderr)

    if args.only:
        findings = [f for f in findings if f.attack_type in set(args.only)]
        print(f"[*] Filtered to {len(findings)} finding(s): {args.only}", file=sys.stderr)

    if not findings:
        print("[warn] Nothing to validate.", file=sys.stderr)
        return 0

    # Resolve URLs
    resolved = [(nf, resolve_url(nf, args.target)) for nf in findings]
    resolved = [(nf, url) for nf, url in resolved if url]
    skipped = len(findings) - len(resolved)
    if skipped:
        print(f"[warn] {skipped} finding(s) skipped — could not resolve URL", file=sys.stderr)

    print(f"[*] Running against {len(resolved)} endpoint(s) on {args.target}", file=sys.stderr)
    print(f"[*] Confidence threshold: {args.confidence}\n", file=sys.stderr)

    results = []
    for i, (nf, url) in enumerate(resolved, 1):
        print(f"  [{i:2d}/{len(resolved)}] {nf.attack_type.upper():10s} {url}", file=sys.stderr)
        result = await _run_finding(nf, url, auth_headers, [], args.confidence, args.timeout,
                                    use_code_fix=bool(args.source))
        if result.get("error"):
            label = f"ERROR: {result['error']}"
        elif result.get("confirmed"):
            label = f"CONFIRMED ({len(result['findings'])} finding(s))"
        else:
            label = "not confirmed"
        print(f"             -> {label} ({result.get('elapsed', '?')}s)", file=sys.stderr)
        results.append(result)

    confirmed = [r for r in results if r.get("confirmed")]
    print(f"\n[*] Done — {len(confirmed)}/{len(results)} confirmed", file=sys.stderr)

    output = json.dumps({
        "summary": {
            "total": len(results),
            "confirmed": len(confirmed),
            "target": args.target,
            "report": str(report_path),
        },
        "results": results,
    }, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"[*] Results -> {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0 if not confirmed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(_build_parser().parse_args())))

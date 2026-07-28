"""
AI-powered findings importer for Frieren DAST-AI.

Accepts any format (JSON, Markdown, plain text, SAST reports, scanner exports, etc.).
The AI normalises the input, infers missing URLs/paths and request bodies from context,
then each finding is stored in the session and queued for a full active DAST scan.
Probe requests from the agents appear in HTTP history tagged source="imported".

Pipeline:
  raw text/bytes
      |
      v
  [pre-process]  — strip metadata, keep only confirmed/relevant findings
      |
      v
  [LLM parse]  — understands arbitrary schemas, infers URLs and request bodies
      |
      v
  list of NormalisedFinding (title, severity, url, method, params, body, ...)
      |
      v
  ProxyEntry stored with source="imported", findings attached (stub from report)
      |
      v
  Queued for active DAST scan → agents run → probe requests appear in HTTP history
  Confirmed exploits → new findings added to the entry by the agents
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from dast.ai import bedrock_client
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_PARSE_SYSTEM = """\
You are a security findings parser for a DAST tool.
You will receive pre-processed text from an external security report (JSON, Markdown,
plain text, scanner export, OWASP ZAP JSON, custom SAST output, pentest report, etc.).

Your job: extract every distinct security finding and normalise it, including inferring
the HTTP endpoint and a representative request body so the DAST tool can replay and
actively test each vulnerability.

For each finding, produce:
{
  "title":        "<vulnerability name>",
  "severity":     "<critical|high|medium|low|info>",
  "cwe":          "<CWE-NNN or empty string>",
  "attack_type":  "<xss|sqli|nosql|ssrf|lfi|ssti|idor|auth_bypass|open_redirect|secret|cmdi|xxe|prompt_injection|csrf|other>",
  "url":          "<full URL if present in the report, else empty string>",
  "path":         "<URL path inferred from file path / route / operation name if full URL not available>",
  "method":       "<HTTP method — POST for mutations/API writes, GET for reads; default POST if unknown>",
  "content_type": "<application/json | application/x-www-form-urlencoded | empty>",
  "request_body": "<JSON string of a representative request body with benign sample values, or empty if GET>",
  "parameter":    "<name of the vulnerable parameter>",
  "payload":      "<proof-of-concept payload if present in the report, else empty>",
  "evidence":     "<concise description of the vulnerability — one or two sentences max>",
  "host_hint":    "<hostname or domain extracted from the report>"
}

Path / URL inference rules:
- If GraphQL schemas are provided at the top of the user message, use them as the source of truth
  for building request_body. Match the finding's mutation/query name against the schema and use
  the exact field names, argument names, and input type structure from the schema.
  Example: schema says "createCourse($input: CreateCourseInput { title: String, locale: String })"
  → request_body: {"query":"mutation CreateCourse($input: CreateCourseInput!) { createCourse(input: $input) { course { id } } }","variables":{"input":{"title":"test","locale":"en"}}}
- For GraphQL findings without a schema, infer the path from the endpoint listed in the schema
  section header (e.g. "/modstore/graphql") if the mutation/query name matches. Otherwise use "/graphql".
- Rails REST controllers: app/controllers/users_controller.rb action=update → path="/users/:id", method=PATCH
- Vue/Nuxt frontend-only findings (postMessage, v-html, CSP): these are client-side; path="/" method=GET
- If the report already contains a full example HTTP request with payload, extract the URL, body and payload from it exactly.
- If no payload is given but the attack type is clear, generate a suitable proof-of-concept payload yourself
  (e.g. for XSS: <script>alert(1)</script>, for SQLi: ' OR 1=1--, for NoSQLi: {"$where":"1==1"}, for SSTI: {{7*7}}, etc.).
- Use attack_type "nosql" for MongoDB / CouchDB / Redis / DynamoDB injection (operators like $where, $ne, $regex in query params or body).
  Use "sqli" only for SQL databases (MySQL, PostgreSQL, MSSQL, SQLite, Oracle).
- If path is truly unknown, set path="" — do not guess the host, only the path.

Severity mapping:
- CVSS 9-10 or "Critical" → critical; 7-9 or "High" → high; 4-7 or "Medium" → medium; 0-4 or "Low" → low

Deduplication: if the same title + parameter + path appears more than once, emit it only once.
Skip non-vulnerability items (recommendations, statistics, scanner config, triage rejections).

Respond with ONLY valid JSON: {"findings": [...]}
No markdown fence, no explanation outside the JSON.
"""

_MAX_CONTENT_CHARS = 40_000  # ~10k tokens — enough for large reports
_MAX_SCHEMA_CHARS  = 6_000   # total schema block cap — schemas can be huge


@dataclass
class NormalisedFinding:
    title: str
    severity: str
    cwe: str
    attack_type: str
    url: str
    path: str
    method: str
    content_type: str
    request_body: str
    parameter: str
    payload: str
    evidence: str
    host_hint: str


def parse_findings(
    raw_text: str,
    graphql_schemas: Optional[Dict[str, dict]] = None,
) -> List[NormalisedFinding]:
    """
    Use the LLM to parse arbitrary security report text and return normalised findings.
    URL resolution against live hosts happens in the caller.

    graphql_schemas: dict of {endpoint_url: compact_schema} from the introspection
    plugin. When provided, the LLM uses the real schema to build correct
    query/mutation bodies instead of guessing.
    """
    processed = _preprocess(raw_text)

    schema_block = ""
    if graphql_schemas:
        schema_block = _format_schemas_for_prompt(graphql_schemas)

    if schema_block:
        prompt = (
            f"GraphQL schemas discovered in this session:\n{schema_block}\n\n"
            f"Report content:\n{processed[:_MAX_CONTENT_CHARS]}"
        )
    else:
        prompt = f"Report content:\n{processed[:_MAX_CONTENT_CHARS]}"

    logger.debug(
        "import parse",
        chars_in=len(raw_text),
        chars_after_preprocess=len(processed),
        schema_endpoints=len(graphql_schemas) if graphql_schemas else 0,
    )

    try:
        result = bedrock_client.invoke_json(
            system=_PARSE_SYSTEM,
            user=prompt,
            model_id=bedrock_client.get_active_model(),
            max_tokens=8192,
        )
    except Exception as exc:
        logger.error("Findings import parse failed", error=str(exc))
        return []

    raw_findings = result.get("findings") or []
    out = []
    for f in raw_findings:
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
            payload=str(f.get("payload", "")),
            evidence=str(f.get("evidence", "")),
            host_hint=str(f.get("host_hint", "")),
        ))

    logger.info("import parsed", raw_findings=len(raw_findings), normalised=len(out))
    return out


# ── GraphQL schema formatting ──────────────────────────────────────────────

def _format_schemas_for_prompt(schemas: Dict[str, dict]) -> str:
    """
    Convert the compact schema map (from graphql_introspection plugin) into
    a concise text block the LLM can use to build correct query/mutation bodies.

    Each endpoint gets its own section. Input types are inlined under the
    mutations/queries that reference them to avoid the LLM needing to cross-reference.
    Total output is capped at _MAX_SCHEMA_CHARS.
    """
    lines: List[str] = []

    for endpoint, schema in schemas.items():
        if not schema.get("introspected"):
            continue  # catalogued but not yet introspected — nothing to format
        mutations: dict = schema.get("mutations") or {}
        queries: dict = schema.get("queries") or {}
        input_types: dict = schema.get("input_types") or {}

        lines.append(f"### {endpoint}")

        if mutations:
            lines.append("Mutations:")
            for name, info in mutations.items():
                args = info.get("args") or []
                arg_strs = []
                for a in args:
                    atype = a["type"]
                    # Inline input type fields when available
                    if atype in input_types:
                        fields = input_types[atype].get("fields") or []
                        field_str = ", ".join(f"{f['name']}: {f['type']}" for f in fields[:12])
                        arg_strs.append(f"${a['name']}: {atype} {{ {field_str} }}")
                    else:
                        arg_strs.append(f"${a['name']}: {atype}")
                lines.append(f"  {name}({', '.join(arg_strs)})")

        if queries:
            lines.append("Queries:")
            for name, info in queries.items():
                args = info.get("args") or []
                arg_strs = [f"${a['name']}: {a['type']}" for a in args]
                lines.append(f"  {name}({', '.join(arg_strs)})")

        lines.append("")

    result = "\n".join(lines)
    if len(result) > _MAX_SCHEMA_CHARS:
        result = result[:_MAX_SCHEMA_CHARS] + "\n... (truncated)"
    return result


# ── pre-processing ─────────────────────────────────────────────────────────

def _preprocess(text: str) -> str:
    """
    Reduce report size before sending to the LLM.

    Strategies (applied in order):
    1. If it looks like our orchestrator-ai JSON format, extract only confirmed findings.
    2. If it looks like our orchestrator-ai Markdown format, extract the confirmed
       vulnerabilities section and strip repetitive attack-path prose.
    3. Otherwise return the text as-is (trimmed to _MAX_CONTENT_CHARS).
    """
    stripped = text.strip()

    # ── Strategy 1: orchestrator-ai JSON ──────────────────────────────────
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
            return _preprocess_orchestrator_json(data)
        except json.JSONDecodeError:
            pass

    # ── Strategy 2: orchestrator-ai / generic Markdown ────────────────────
    if stripped.startswith("#") or "## " in stripped[:200]:
        return _preprocess_markdown(stripped)

    return stripped


def _preprocess_orchestrator_json(data: dict | list) -> str:
    """
    Extract only the confirmed findings from orchestrator-ai JSON format.
    Drops triage_only / rejected entries to stay within context limits.
    """
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("findings", [])
        # Include metadata hints (service URLs, project name) as a brief header
        project = data.get("project", "")
        service_urls = (data.get("service_urls") or
                        (data.get("context", {}) or {}).get("service_urls") or [])
    else:
        return json.dumps(data)

    # Keep confirmed findings; fall back to all if none confirmed
    confirmed = [f for f in findings
                 if isinstance(f, dict)
                 and f.get("status") in ("confirmed", "stage2_confirmed", "claude_code_confirmed")]
    if not confirmed:
        # Include all non-rejected findings
        confirmed = [f for f in findings
                     if isinstance(f, dict)
                     and "reject" not in str(f.get("status", "")).lower()
                     and "false" not in str(f.get("status", "")).lower()]
    if not confirmed:
        confirmed = [f for f in findings if isinstance(f, dict)]

    # Slim each finding: keep title, severity, description, file, cwe, attack paths
    slim = []
    for f in confirmed:
        entry: dict = {
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "cwe": f.get("cwe", ""),
            "description": (f.get("description") or "")[:800],
            "file": f.get("file", ""),
            "line": f.get("line"),
        }
        # Include claude_code analysis for richer context
        cc = f.get("claude_code")
        if isinstance(cc, dict):
            entry["how_to_exploit"] = str(cc.get("how_to_exploit") or "")[:600]
            entry["attack_paths"] = cc.get("attack_paths", [])[:3]
        elif isinstance(cc, str):
            entry["claude_code"] = cc[:800]
        slim.append(entry)

    # Build a plain-text context header so the LLM has project/URL hints
    # without corrupting the JSON structure
    context_lines = []
    if isinstance(data, dict):
        if project:
            context_lines.append(f"Project: {project}")
        if service_urls:
            context_lines.append(f"Service URLs: {', '.join(str(u) for u in service_urls)}")

    findings_json = json.dumps({"findings": slim}, indent=2, ensure_ascii=False)
    if context_lines:
        return "# Context\n" + "\n".join(context_lines) + "\n\n# Findings\n" + findings_json
    return findings_json


def _preprocess_markdown(text: str) -> str:
    """
    For orchestrator-ai Markdown reports: extract the confirmed vulnerabilities
    section and slim down verbose attack-path blocks.
    """
    # Extract service URLs from the document (used for host_hint)
    urls_match = re.search(r'### Service URLs\s*\n(.*?)(?=\n###|\n##|\Z)', text, re.DOTALL)
    urls_block = urls_match.group(0) if urls_match else ""

    # Find the confirmed vulnerabilities section.
    # Try specific patterns first (most precise → least precise) to avoid
    # matching executive-summary "Findings by Severity" tables.
    vuln_start = None
    for pattern in (
        r'##\s+.*Confirmed Vulnerabilities',
        r'##\s+.*Vulnerabilities\b',
        r'###\s+(HIGH|MEDIUM|LOW|CRITICAL|INFO)\s+Severity',
        r'####\s+1\.',                         # numbered finding heading
        r'##\s+.*Findings\b(?!\s+by)',         # "Findings" but not "Findings by"
    ):
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            vuln_start = m
            break

    if vuln_start:
        vuln_text = text[vuln_start.start():]
    else:
        vuln_text = text

    # Drop trailing sections that describe findings the upstream pipeline already
    # ruled out or that are not vulnerabilities at all — importing them means we
    # replay findings that were explicitly rejected and re-reject them, wasting a
    # full active scan and cluttering the dashboard with pre-cleared false positives.
    # Cut vuln_text at the first such section header (whichever appears earliest).
    _STOP_SECTION_PATTERNS = (
        r'##\s+.*Rejected by Red Team',        # Stage 3 (Opus) analyzed & cleared
        r'##\s+.*Rejected by Triage',          # likely false positive, not analyzed
        r'##\s+.*Merge Requests Analyzed',     # report metadata, not findings
        r'##\s+.*Scan Cost',                   # report metadata, not findings
    )
    earliest_stop = None
    for pattern in _STOP_SECTION_PATTERNS:
        m = re.search(pattern, vuln_text, re.IGNORECASE)
        if m and (earliest_stop is None or m.start() < earliest_stop):
            earliest_stop = m.start()
    if earliest_stop is not None:
        vuln_text = vuln_text[:earliest_stop]

    # For each finding block, keep: header, Location, Source, Severity, Description,
    # How to Exploit, and the first attack path payload. Drop long repetitive sections.
    sections = re.split(r'\n(?=####\s)', vuln_text)
    slim_sections = []
    for section in sections:
        slim_sections.append(_slim_finding_section(section))

    result = urls_block + "\n\n" + "\n\n---\n\n".join(slim_sections)
    return result


def _slim_finding_section(section: str) -> str:
    """
    Reduce a single finding section by removing repetitive content:
    - Keep: header, Location, Source, Severity, Description, How to Exploit,
      first attack path (with payload), Attack Chains summary
    - Remove: full triage analysis prose, all attack paths after the first,
      long data flow chains
    """
    # Always keep the first 600 chars (header + basic metadata)
    keep_parts = [section[:600]]

    # Extract and keep "How to Exploit" block (numbered steps)
    how_match = re.search(r'\*\*How to Exploit:\*\*\s*\n(.*?)(?=\n\*\*|\n---|\Z)', section, re.DOTALL)
    if how_match:
        keep_parts.append("**How to Exploit:**\n" + how_match.group(1)[:500])

    # Extract first attack path with its payload
    path_match = re.search(
        r'\*\*1\..*?(?=\*\*2\.|\*\*Attack Chains|\Z)',
        section, re.DOTALL
    )
    if path_match:
        keep_parts.append(path_match.group(0)[:800])

    return "\n".join(keep_parts)


# ── URL resolution ─────────────────────────────────────────────────────────

def resolve_url(nf: NormalisedFinding, base_url: str) -> str:
    """Return the best URL to use for this finding."""
    from urllib.parse import urlparse as _urlparse, urlunparse as _urlunparse

    if nf.url and nf.url.startswith("http"):
        # Strip PoC payloads embedded in path segments by the report author
        # e.g. /api/items/000000')]}},$where:'1==1'}//details → /api/items
        parsed = _urlparse(nf.url)
        clean_path = _strip_payload_from_path(parsed.path)
        # If base_url is provided and the URL's host differs, rewrite to base_url host
        if base_url:
            base_parsed = _urlparse(base_url)
            if base_parsed.netloc and base_parsed.netloc != parsed.netloc:
                return base_url.rstrip("/") + clean_path
        if clean_path != parsed.path:
            return _urlunparse(parsed._replace(path=clean_path, query="", fragment=""))
        return _urlunparse(parsed._replace(query="", fragment=""))

    base = base_url.rstrip("/") if base_url else ""
    if not base:
        if nf.host_hint and not ("|" in nf.host_hint):
            base = f"https://{nf.host_hint.lstrip('/')}"
        else:
            return ""

    path = nf.path or ""
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    path = _strip_payload_from_path(path)
    return base + path


def _strip_payload_from_path(path: str) -> str:
    """
    Remove PoC injection payloads embedded in URL path segments.
    Splits on the first segment that looks like an attack payload and keeps only the prefix.
    """
    segments = path.split("/")
    clean: list = []
    _PAYLOAD_MARKERS = ("$where", "$ne", "$or", "$and", "$regex", "$gt", "$lt",
                        "')]}", "))}", "<script", "alert(", "' or ", "\" or ",
                        "1=1", "union select", "../", "%00", "{{", "}}")
    for seg in segments:
        seg_lower = seg.lower()
        if any(marker in seg_lower for marker in _PAYLOAD_MARKERS):
            break
        clean.append(seg)
    result = "/".join(clean)
    if not result.startswith("/"):
        result = "/" + result.lstrip("/")
    return result or "/"


# ── finding dict builders ──────────────────────────────────────────────────

def build_stub_finding(nf: NormalisedFinding) -> dict:
    """
    Build the initial 'imported' finding dict that appears on the entry
    before active scanning has run. Agents will add their own findings later.
    """
    return {
        "title": nf.title,
        "severity": nf.severity,
        "cwe": nf.cwe,
        "attack_type": nf.attack_type,
        "parameter": nf.parameter,
        "payload": nf.payload,
        "evidence": f"[Imported from external report] {nf.evidence}",
        "validated_by": ["imported"],
        "confirmed": False,
        "confidence": 0.0,
        "reasoning": "Imported from external report — active DAST scan queued for validation",
        "raw_request": "",
        "raw_response": "",
        "import_status": "queued",
    }


def build_request_body(nf: NormalisedFinding) -> Optional[bytes]:
    """Build the raw request body bytes for a proxy entry from the inferred body."""
    body = nf.request_body.strip()
    if not body:
        return None
    try:
        if "json" in nf.content_type or body.startswith("{") or body.startswith("["):
            json.loads(body)  # validate — raises if invalid
        return body.encode("utf-8")
    except Exception:
        return body.encode("utf-8")


def build_request_headers(nf: NormalisedFinding) -> Dict[str, str]:
    """Build minimal request headers for the proxy entry."""
    headers: Dict[str, str] = {}
    ct = nf.content_type
    if not ct:
        body = nf.request_body.strip()
        if body.startswith("{") or body.startswith("["):
            ct = "application/json"
        elif body and "=" in body:
            ct = "application/x-www-form-urlencoded"
    if ct:
        headers["content-type"] = ct
    return headers


# ── helpers ────────────────────────────────────────────────────────────────

def _normalise_severity(raw: str) -> str:
    s = raw.lower().strip()
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    if s in ("informational", "information", "note"):
        return "info"
    return "medium"

"""
Code analysis orchestrator — two-phase design.

Phase 1 — load_and_scan (fast, no LLM, non-blocking):
  Loads source files and runs the deterministic pattern scanner.
  Completes in seconds. Called by POST /api/code/analyze.

Phase 2 — enrich_with_ai (LLM, explicit trigger only):
  Endpoint extraction (Haiku) + hypothesis generation (Opus).
  Called only by POST /api/code/enrich/{id} when the user clicks "AI Enrich".
  Runs in a separate thread pool so it never competes with scan traffic.

Code Index:
  After Phase 1, files are indexed for fast path-based lookup.
  The scanner uses lookup_code_for_path() to inject relevant source snippets
  into the Coordinator's planner prompt before scanning an endpoint.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List

from dast.utils.logger import get_logger
from dast.code_analysis.source_loader import load_source
from dast.code_analysis.pattern_scanner import PatternMatch, scan_patterns

logger = get_logger(__name__)

# Dedicated thread pool for AI enrichment — isolated from scan workers.
# 5 workers: endpoint extraction chunks run in parallel without blocking scan workers.
_AI_POOL = ThreadPoolExecutor(max_workers=5, thread_name_prefix="code-ai")

# ── Result data models ─────────────────────────────────────────────────────

@dataclass
class DiscoveredEndpoint:
    """An HTTP endpoint discovered in the source code."""

    method: str         # GET / POST / PUT / PATCH / DELETE
    path: str           # /api/users/:id
    controller: str     # UsersController#show  or  filename:function
    params: List[str]   # known parameter names
    notes: str          # AI notes about this endpoint


@dataclass
class VulnHypothesis:
    """A vulnerability hypothesis produced by AI analysis of the source."""

    endpoint_path: str
    vuln_type: str          # ssrf / sqli / xss / idor / auth_bypass / etc.
    severity: str           # critical / high / medium / low
    reasoning: str          # why this endpoint looks vulnerable
    suggested_payload: str  # a concrete test payload
    # Populated after validate_hypothesis queues the entry
    scan_entry_id: str = ""   # proxy entry ID that was queued
    scan_status: str = ""     # "queued" | "scanning" | "confirmed" | "safe" | "error" | "pending"


@dataclass
class CodeAnalysisResult:
    """Full result of one code analysis job."""

    analysis_id: str
    sources: List[str]       # one or more local paths / GitLab URLs
    status: str              # scanning / scanned / enriching / enriched / error
    files_scanned: int
    # The live target URL associated with this codebase, e.g. https://staging.example.com
    # Set by the user at analysis time so validate_hypothesis knows where to probe
    # regardless of what's in proxy history.
    target_url: str = ""
    # Additional target URLs — when multiple repos map to multiple services, each
    # hypothesis is tried against all URLs; the first that produces a real entry wins.
    extra_target_urls: List[str] = field(default_factory=list)
    # raw file dicts kept in memory for search and context injection
    _files: List[dict] = field(default_factory=list, repr=False)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    pattern_matches: List[PatternMatch] = field(default_factory=list)
    hypotheses: List[VulnHypothesis] = field(default_factory=list)
    error: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def source(self) -> str:
        """Single-string representation of all sources (for display)."""
        return ", ".join(self.sources) if self.sources else ""

    def to_dict(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "sources": self.sources,
            "source": self.source,
            "status": self.status,
            "files_scanned": self.files_scanned,
            "target_url": self.target_url,
            "extra_target_urls": self.extra_target_urls,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "endpoints": [
                {
                    "method": ep.method,
                    "path": ep.path,
                    "controller": ep.controller,
                    "params": ep.params,
                    "notes": ep.notes,
                }
                for ep in self.endpoints
            ],
            "pattern_matches": [
                {
                    "file_path": pm.file_path,
                    "line_number": pm.line_number,
                    "line_content": pm.line_content,
                    "pattern_id": pm.pattern_id,
                    "title": pm.title,
                    "severity": pm.severity,
                    "cwe": pm.cwe,
                    "language": pm.language,
                }
                for pm in self.pattern_matches
            ],
            "hypotheses": [
                {
                    "endpoint_path": h.endpoint_path,
                    "vuln_type": h.vuln_type,
                    "severity": h.severity,
                    "reasoning": h.reasoning,
                    "suggested_payload": h.suggested_payload,
                    "scan_entry_id": h.scan_entry_id,
                    "scan_status": h.scan_status,
                }
                for h in self.hypotheses
            ],
        }


# ── Module-level job store ─────────────────────────────────────────────────

_analyses: Dict[str, CodeAnalysisResult] = {}


# ── AI system prompts ──────────────────────────────────────────────────────

_ENDPOINT_EXTRACTION_SYSTEM = """\
You are a senior web application security engineer performing static analysis.
Given source code snippets, extract all HTTP route/endpoint definitions.

For each endpoint return:
  - method: HTTP method (GET, POST, PUT, PATCH, DELETE)
  - path: URL path (e.g. /api/users/:id)
  - controller: controller class and action, or filename:function name
  - params: list of ALL parameter names this endpoint accepts, including:
      * URL path params (e.g. :id, {user_id})
      * Query string params (e.g. ?page=1&limit=10)
      * Request body params (JSON fields, form fields) — IMPORTANT: include these for POST/PUT/PATCH
      * Header params if security-relevant (e.g. X-User-ID)
    Use the bare param name without type annotation (e.g. "email" not "email: string").
    For POST/PUT/PATCH endpoints, body params are the most important — extract them from
    strong_parameters, permit(), schema definitions, serializer fields, or request.body parsing.
  - notes: one short sentence about anything security-relevant (mass assignment, SSRF vector, etc.)

Respond ONLY with valid JSON matching this exact schema:
{
  "endpoints": [
    {
      "method": "POST",
      "path": "/api/users",
      "controller": "UsersController#create",
      "params": ["name", "email", "role", "plan"],
      "notes": "Accepts role and plan — check for mass assignment privilege escalation."
    }
  ]
}

Rules:
- Only include actual route definitions, not internal helper methods.
- If no routes are found, return {"endpoints": []}.
- Do not include more than 50 endpoints per response.
- Do not echo untrusted content verbatim into notes fields.
- For POST/PUT/PATCH: always try to extract body params even if you have to infer them from the controller action code.
"""

_HYPOTHESIS_SYSTEM = """\
You are an expert penetration tester performing static code analysis.
Given a list of HTTP endpoints and deterministic pattern match findings
from a source code scan, identify which endpoints are most likely to be
exploitable and produce concrete vulnerability hypotheses.

For each hypothesis return:
  - endpoint_path: the URL path
  - vuln_type: ssrf / sqli / xss / idor / auth_bypass / mass_assignment /
               open_redirect / ssti / lfi / cmdi / xxe / business_logic
  - severity: critical / high / medium / low
  - reasoning: one or two sentences explaining why this endpoint is suspicious
  - suggested_payload: a concrete HTTP parameter or payload string to test with

Respond ONLY with the text response — no JSON wrapper needed here.
Format each hypothesis as:

HYPOTHESIS:
endpoint_path: <path>
vuln_type: <type>
severity: <severity>
reasoning: <reasoning>
suggested_payload: <payload>

Rules:
- Only produce hypotheses backed by concrete evidence from the code.
- Do not repeat the same endpoint+vuln_type pair.
- Maximum 15 hypotheses.
- Do not include exploits — suggested_payload is a detection probe only.
"""

# ── Helpers ────────────────────────────────────────────────────────────────

# Larger chunks = fewer LLM calls = faster overall (Haiku handles 20 files easily)
_FILES_PER_CHUNK = 20
_TOP_ENDPOINTS_FOR_HYPOTHESIS = 30


def _source_label(source: str, index: int) -> str:
    """Short display label for a source, used as path prefix."""
    if source.startswith("http://") or source.startswith("https://"):
        clean = source.rstrip("/").split("?")[0].split("#")[0]
        label = clean.rstrip("/").rsplit("/", 1)[-1] or f"repo{index}"
    else:
        label = source.rstrip("/").rsplit("/", 1)[-1] or f"repo{index}"
    return label[:40]


def _prefix_file_paths(files: List[dict], prefix: str) -> List[dict]:
    """Return a copy of file dicts with paths prefixed by source label."""
    return [{**f, "path": f"{prefix}/{f['path']}"} for f in files]


async def _load_all_sources(sources: List[str], gitlab_token: str) -> List[dict]:
    """Load all sources in parallel, prefixing paths when more than one source."""
    multi = len(sources) > 1
    tasks = [load_source(s, gitlab_token=gitlab_token) for s in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_files: List[dict] = []
    for idx, (source, result) in enumerate(zip(sources, results)):
        if isinstance(result, Exception):
            logger.error("Failed to load source", source=source, error=str(result))
            continue
        files: List[dict] = result
        if multi:
            files = _prefix_file_paths(files, _source_label(source, idx))
        all_files.extend(files)

    return all_files


def _build_file_chunk_text(files: List[dict]) -> str:
    """Format a list of source file dicts as a readable code block for the LLM."""
    parts: List[str] = []
    for file_dict in files:
        path = file_dict.get("path", "")
        content = file_dict.get("content", "")
        truncated = content[:3000]
        if len(content) > 3000:
            truncated += "\n... [truncated]"
        parts.append(f"--- File: {path} ---\n{truncated}")
    return "\n\n".join(parts)


def _group_files_by_language(files: List[dict]) -> Dict[str, List[dict]]:
    """Group source file dicts by language."""
    groups: Dict[str, List[dict]] = {}
    for f in files:
        lang = f.get("language", "unknown")
        groups.setdefault(lang, []).append(f)
    return groups


def _parse_endpoint_response(raw: dict) -> List[DiscoveredEndpoint]:
    """Parse the JSON response from the endpoint extraction LLM call."""
    endpoints: List[DiscoveredEndpoint] = []
    for item in raw.get("endpoints", []):
        try:
            endpoints.append(DiscoveredEndpoint(
                method=str(item.get("method", "GET")).upper()[:10],
                path=str(item.get("path", ""))[:200],
                controller=str(item.get("controller", ""))[:200],
                params=[str(p)[:100] for p in item.get("params", []) if p][:20],
                notes=str(item.get("notes", ""))[:300],
            ))
        except Exception as exc:
            logger.debug("Failed to parse endpoint item", error=str(exc))
    return endpoints


def _parse_hypothesis_response(raw_text: str) -> List[VulnHypothesis]:
    """Parse the free-text hypothesis response from the Opus LLM call."""
    hypotheses: List[VulnHypothesis] = []
    blocks = raw_text.split("HYPOTHESIS:")
    for block in blocks[1:]:
        lines = block.strip().splitlines()
        fields: Dict[str, str] = {}
        for line in lines:
            if ":" in line:
                key, _, value = line.partition(":")
                fields[key.strip().lower().replace(" ", "_")] = value.strip()
        try:
            raw_path = fields.get("endpoint_path", "")
            # LLM sometimes prefixes the path with the HTTP method, e.g. "GET /foo/bar"
            # Strip it so we get a clean path like "/foo/bar"
            raw_path = re.sub(
                r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+', "", raw_path.strip(), flags=re.IGNORECASE
            )
            if raw_path and not raw_path.startswith("/"):
                raw_path = "/" + raw_path
            hypothesis = VulnHypothesis(
                endpoint_path=raw_path[:200],
                vuln_type=fields.get("vuln_type", "")[:50],
                severity=fields.get("severity", "medium")[:20],
                reasoning=fields.get("reasoning", "")[:500],
                suggested_payload=fields.get("suggested_payload", "")[:300],
            )
            if hypothesis.endpoint_path and hypothesis.vuln_type:
                hypotheses.append(hypothesis)
        except Exception as exc:
            logger.debug("Failed to parse hypothesis block", error=str(exc))
    return hypotheses


# ── AI extraction coroutines ───────────────────────────────────────────────

async def _extract_endpoints_for_chunk(
    files: List[dict],
    loop: asyncio.AbstractEventLoop,
) -> List[DiscoveredEndpoint]:
    """Call Haiku to extract endpoints from a single file chunk."""
    from dast.ai import bedrock_client

    chunk_text = _build_file_chunk_text(files)
    user_prompt = f"Extract all HTTP route definitions from the following source code:\n\n{chunk_text}"

    try:
        raw = await loop.run_in_executor(
            _AI_POOL,
            lambda: bedrock_client.invoke_json(
                system=_ENDPOINT_EXTRACTION_SYSTEM,
                user=user_prompt,
                model_id=bedrock_client.get_fast_model(),
                max_tokens=2000,
            ),
        )
        return _parse_endpoint_response(raw)
    except Exception as exc:
        logger.warning(
            "Endpoint extraction LLM call failed",
            files=[f.get("path") for f in files],
            error=str(exc),
        )
        return []


async def _extract_all_endpoints(
    files: List[dict],
    loop: asyncio.AbstractEventLoop,
) -> List[DiscoveredEndpoint]:
    """Extract endpoints from all files by chunking per language."""
    language_groups = _group_files_by_language(files)
    tasks = []
    for _lang, lang_files in language_groups.items():
        for i in range(0, len(lang_files), _FILES_PER_CHUNK):
            tasks.append(_extract_endpoints_for_chunk(lang_files[i:i + _FILES_PER_CHUNK], loop))

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_endpoints: List[DiscoveredEndpoint] = []
    for result in results:
        if isinstance(result, list):
            all_endpoints.extend(result)

    seen: set = set()
    unique: List[DiscoveredEndpoint] = []
    for ep in all_endpoints:
        key = (ep.method, ep.path)
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    logger.info("Endpoint extraction complete", endpoints=len(unique))
    return unique


async def _generate_hypotheses(
    endpoints: List[DiscoveredEndpoint],
    pattern_matches: List[PatternMatch],
    loop: asyncio.AbstractEventLoop,
) -> List[VulnHypothesis]:
    """Call Opus to generate vulnerability hypotheses."""
    from dast.ai import bedrock_client

    if not endpoints and not pattern_matches:
        return []

    top_endpoints = endpoints[:_TOP_ENDPOINTS_FOR_HYPOTHESIS]
    endpoint_lines = [
        f"{ep.method} {ep.path}  controller={ep.controller}  params=[{', '.join(ep.params) or 'none'}]"
        + (f"  notes: {ep.notes}" if ep.notes else "")
        for ep in top_endpoints
    ]
    match_lines = [
        f"[{pm.severity.upper()}] {pm.title} ({pm.cwe}) in {pm.file_path}:{pm.line_number}"
        f" — {pm.line_content}"
        for pm in pattern_matches[:30]
    ]

    user_prompt = (
        "Endpoints discovered in the codebase:\n"
        + "\n".join(endpoint_lines or ["(none)"])
        + "\n\nDeterministic pattern matches found:\n"
        + "\n".join(match_lines or ["(none)"])
        + "\n\nIdentify the most likely exploitable vulnerabilities."
    )

    try:
        raw_text = await loop.run_in_executor(
            _AI_POOL,
            lambda: bedrock_client.invoke(
                system=_HYPOTHESIS_SYSTEM,
                user=user_prompt,
                model_id=bedrock_client.get_validation_model(),
                max_tokens=2000,
            ),
        )
        hypotheses = _parse_hypothesis_response(raw_text)
        logger.info("Hypothesis generation complete", hypotheses=len(hypotheses))
        return hypotheses
    except Exception as exc:
        logger.warning("Hypothesis generation LLM call failed", error=str(exc))
        return []


# ── Phase 1: load + pattern scan (fast, no LLM) ───────────────────────────

async def run_analysis(
    analysis_id: str,
    sources: List[str],
    gitlab_token: str = "",
    target_url: str = "",
) -> CodeAnalysisResult:
    """
    Phase 1: load source files and run deterministic pattern scanner.
    No LLM calls. Completes quickly and does not compete with scan traffic.
    """
    result = CodeAnalysisResult(
        analysis_id=analysis_id,
        sources=sources,
        status="scanning",
        files_scanned=0,
        target_url=target_url,
        started_at=time.time(),
    )
    _analyses[analysis_id] = result

    loop = asyncio.get_running_loop()

    try:
        logger.info("Code analysis Phase 1 started", analysis_id=analysis_id, sources=sources)

        files = await _load_all_sources(sources, gitlab_token)
        result.files_scanned = len(files)
        result._files = files
        logger.info("Sources loaded", analysis_id=analysis_id, files=len(files))

        if not files:
            logger.warning("No supported source files found", analysis_id=analysis_id)

        pattern_matches = await loop.run_in_executor(None, scan_patterns, files)
        result.pattern_matches = pattern_matches
        logger.info("Pattern scan complete", analysis_id=analysis_id, matches=len(pattern_matches))

        result.status = "scanned"
        result.finished_at = time.time()
        logger.info(
            "Code analysis Phase 1 complete",
            analysis_id=analysis_id,
            files=result.files_scanned,
            matches=len(pattern_matches),
            duration_seconds=round(result.finished_at - result.started_at, 2),
        )

    except Exception as exc:
        logger.error("Code analysis Phase 1 failed", analysis_id=analysis_id, error=str(exc))
        result.status = "error"
        result.error = str(exc)
        result.finished_at = time.time()

    _analyses[analysis_id] = result
    return result


# ── Phase 2: AI enrichment (LLM, explicit trigger) ────────────────────────

async def enrich_with_ai(analysis_id: str) -> CodeAnalysisResult:
    """
    Phase 2: AI endpoint extraction + vulnerability hypothesis generation.
    Uses the dedicated _AI_POOL so it never competes with scan workers.
    Only runs if Phase 1 has completed (status == 'scanned').
    """
    result = _analyses.get(analysis_id)
    if not result:
        raise ValueError(f"Analysis {analysis_id} not found")
    if result.status not in ("scanned", "enriched"):
        raise ValueError(f"Analysis is in status '{result.status}' — run Phase 1 first")

    result.status = "enriching"
    _analyses[analysis_id] = result

    loop = asyncio.get_running_loop()

    try:
        from dast.proxy.plugin_manager import log_event
        n_files = len(result._files)
        n_chunks = max(1, (n_files + _FILES_PER_CHUNK - 1) // _FILES_PER_CHUNK)
        logger.info("Code analysis Phase 2 started", analysis_id=analysis_id,
                    files=n_files, chunks=n_chunks)
        log_event("code", "info",
                  f"AI Enrich started — {n_files} files in {n_chunks} chunk(s) "
                  f"({_FILES_PER_CHUNK} files/chunk, 2 parallel workers). "
                  f"Phase 1: endpoint extraction via Haiku. Phase 2: hypothesis generation via Opus.",
                  source="agent")

        endpoints = await _extract_all_endpoints(result._files, loop)
        result.endpoints = endpoints
        log_event("code", "info",
                  f"AI Enrich phase 1 complete — {len(endpoints)} endpoints extracted. "
                  f"Starting hypothesis generation…",
                  source="agent")

        hypotheses = await _generate_hypotheses(endpoints, result.pattern_matches, loop)
        result.hypotheses = hypotheses

        result.status = "enriched"
        result.finished_at = time.time()
        elapsed = round(result.finished_at - result.started_at, 1)
        logger.info(
            "Code analysis Phase 2 complete",
            analysis_id=analysis_id,
            endpoints=len(endpoints),
            hypotheses=len(hypotheses),
        )
        log_event("code", "info",
                  f"AI Enrich complete — {len(endpoints)} endpoints, "
                  f"{len(hypotheses)} hypotheses in {elapsed}s",
                  source="agent")

    except Exception as exc:
        logger.error("Code analysis Phase 2 failed", analysis_id=analysis_id, error=str(exc))
        log_event("code", "error", f"AI Enrich failed: {exc}", source="agent")
        result.status = "error"
        result.error = str(exc)

    _analyses[analysis_id] = result
    return result


# ── Code context lookup for scan integration ──────────────────────────────

def lookup_code_for_path(url_path: str, max_snippets: int = 3) -> str:
    """
    Find source code snippets relevant to a URL path from all loaded analyses.

    Returns a formatted string suitable for injection into the Coordinator's
    planner prompt. Returns empty string if no relevant code is found.

    Matching strategy (in order of priority):
    1. Files whose path contains the last segment of the URL path
    2. Files containing the URL path string as a literal
    """
    if not _analyses or not url_path:
        return ""

    # Normalize URL path segments for matching
    segments = [s for s in url_path.strip("/").split("/") if s]
    if not segments:
        return ""

    # Build candidate keywords from path segments (strip REST verbs and pure IDs)
    _REST_VERBS = {"search", "list", "get", "create", "update", "delete",
                   "save", "count", "history", "details", "approve", "deny"}
    _candidate_segments: List[str] = []
    for seg in reversed(segments):
        seg_lower = seg.lower().replace("-", "")
        # Skip pure numeric/UUID IDs
        if re.match(r'^[0-9a-f\-]{4,}$', seg):
            continue
        # Skip template placeholders like {id}
        if seg.startswith("{") and seg.endswith("}"):
            continue
        # Skip common REST verb suffixes — prefer the resource noun
        if seg_lower in _REST_VERBS and _candidate_segments:
            continue
        _candidate_segments.append(seg_lower)
        if len(_candidate_segments) >= 3:
            break

    if not _candidate_segments:
        return ""

    # For /api/ paths, prefer server-side controller files over client TS/JS
    _is_api_path = url_path.startswith("/api/")

    # Collect all matches then sort: controllers first for API paths
    matched_files: List[tuple] = []  # (priority, file_dict)
    seen_paths: set = set()

    for result in _analyses.values():
        if result.status not in ("scanned", "enriched") or not result._files:
            continue

        for file_dict in result._files:
            file_path = file_dict.get("path", "").lower()
            content = file_dict.get("content", "")

            if file_path in seen_paths:
                continue

            # Match if any candidate segment appears in the file path (strips hyphens for comparison)
            file_path_nohyphen = file_path.replace("-", "")
            path_match = any(seg in file_path_nohyphen for seg in _candidate_segments)

            # Match by content containing the URL path literally or partial path
            content_match = (
                url_path in content
                or (len(segments) >= 2 and f"/{segments[-2]}/{segments[-1]}" in content)
            )

            if path_match or content_match:
                seen_paths.add(file_path)
                # Priority: lower = shown first
                # 0 = controller with exact resource name match
                # 1 = controller (any)
                # 2 = service/interface
                # 3 = model/dto
                # 4 = other
                file_basename = file_path.split("/")[-1].replace("-", "").replace("controller.cs", "")
                exact_controller = (
                    _is_api_path
                    and "controller" in file_path
                    and any(seg == file_basename for seg in _candidate_segments)
                )
                if exact_controller:
                    priority = 0
                elif _is_api_path and "controller" in file_path:
                    priority = 1
                elif "service" in file_path or "interface" in file_path:
                    priority = 2
                elif "dto" in file_path or "model" in file_path:
                    priority = 3
                else:
                    priority = 4
                matched_files.append((priority, file_dict))

    matched_files.sort(key=lambda x: x[0])
    snippets: List[str] = []
    for _, file_dict in matched_files[:max_snippets]:
        content = file_dict.get("content", "")
        snippet = content[:1500]
        if len(content) > 1500:
            snippet += "\n... [truncated]"
        snippets.append(f"--- {file_dict['path']} ---\n{snippet}")

    if not snippets:
        return ""

    return "Relevant source code for this endpoint:\n\n" + "\n\n".join(snippets)


# ── Utilities ──────────────────────────────────────────────────────────────

def create_analysis_id() -> str:
    """Generate a unique analysis job identifier."""
    return str(uuid.uuid4())

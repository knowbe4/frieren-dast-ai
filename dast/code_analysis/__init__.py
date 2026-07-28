"""
Code analysis package for Frieren DAST-AI.

Provides static source code analysis combining:
  - Deterministic regex pattern scanning (no LLM, fast)
  - AI-assisted HTTP endpoint extraction (Haiku)
  - AI-assisted vulnerability hypothesis generation (Opus)

Supports both local filesystem paths and GitLab repository URLs as sources.

Usage:
    from dast.code_analysis import run_analysis, CodeAnalysisResult, _analyses
    import uuid

    analysis_id = str(uuid.uuid4())
    result = await run_analysis(analysis_id, "/path/to/project")
    # or
    result = await run_analysis(analysis_id, "https://gitlab.com/group/project",
                                gitlab_token="glpat-...")

    # Poll status from a background task:
    status = _analyses[analysis_id].status  # "running" | "completed" | "error"
"""

from dast.code_analysis.analyzer import (
    CodeAnalysisResult,
    DiscoveredEndpoint,
    VulnHypothesis,
    _analyses,
    run_analysis,
    enrich_with_ai,
    create_analysis_id,
    lookup_code_for_path,
)

__all__ = [
    "run_analysis",
    "enrich_with_ai",
    "create_analysis_id",
    "lookup_code_for_path",
    "CodeAnalysisResult",
    "DiscoveredEndpoint",
    "VulnHypothesis",
    "_analyses",
]

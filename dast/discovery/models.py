"""
Data models for the discovery package.
All fields are optional — modules populate what they can, agents skip what's absent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_INJECTION_RE = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)"
    r"|system\s*:\s*you\s+are"
    r"|<\s*/?system\s*>"
    r"|\[INST\]|\[/INST\]"
    r"|###\s*instruction"
    r"|---\s*new\s+prompt"
    r"|forget\s+(everything|all)\s+(above|previous)"
    r"|you\s+are\s+now\s+(a\s+)?(different|new)\s+(ai|assistant|model))",
    re.IGNORECASE,
)


def _safe(value: str) -> str:
    """Strip prompt-injection patterns from untrusted header/body values."""
    return _INJECTION_RE.sub("[redacted]", value[:200])


@dataclass
class TechStack:
    """Technology fingerprint derived from headers and response bodies."""
    framework: Optional[str] = None        # e.g. "Django", "Rails", "Spring", "Express"
    language: Optional[str] = None         # e.g. "Python", "Ruby", "Java", "JavaScript"
    server: Optional[str] = None           # e.g. "nginx/1.18", "Apache/2.4"
    database_hints: List[str] = field(default_factory=list)   # e.g. ["PostgreSQL", "Redis"]
    orm_hints: List[str] = field(default_factory=list)        # e.g. ["ActiveRecord", "SQLAlchemy"]
    cdn: Optional[str] = None
    waf_hints: List[str] = field(default_factory=list)        # e.g. ["Cloudflare", "ModSecurity"]
    template_engine: Optional[str] = None  # e.g. "Jinja2", "Twig", "Thymeleaf", "Handlebars"
    cms: Optional[str] = None              # e.g. "WordPress", "Drupal", "Shopify"
    extra: Dict[str, str] = field(default_factory=dict)       # any other k/v signals


@dataclass
class ApiEndpoint:
    """
    An API endpoint inferred from JS analysis or OpenAPI schema.
    Not necessarily an endpoint the proxy has seen — may be undiscovered.
    """
    method: str                            # GET / POST / PUT / DELETE / PATCH
    path: str                              # e.g. /api/users/{id}
    params: List[Dict[str, str]] = field(default_factory=list)
    # [{name, location (query|body|path), type (string|int|...), description}]
    source: str = "js"                     # "js" | "openapi" | "traffic"
    description: Optional[str] = None


@dataclass
class CallEdge:
    """
    An observed call relationship: response from source_url fed a param into target_url.
    Captured purely from traffic — no source code access required.
    """
    source_url: str             # URL whose response contained the value
    source_field: str           # JSON key / query param name in the source response
    target_url: str             # URL that received the value
    target_param: str           # param name in the target request
    sample_value: str           # the actual value observed (truncated)
    confidence: float = 0.5     # 0.0–1.0; higher when field names match exactly


@dataclass
class DiscoveryContext:
    """
    Aggregated discovery context for a single host.
    Attached to CheckTarget.discovery_context by the DiscoveryEngine.
    Agents read this; they never modify it.
    """
    host: str
    tech_stack: Optional[TechStack] = None
    api_endpoints: List[ApiEndpoint] = field(default_factory=list)
    call_edges: List[CallEdge] = field(default_factory=list)
    openapi_schema: Optional[dict] = None   # raw parsed OpenAPI dict if found

    def to_agent_summary(self) -> str:
        """
        Compact text summary injected into agent prompts.
        All values from external sources pass through _safe() to prevent prompt injection.
        """
        lines = []
        if self.tech_stack:
            ts = self.tech_stack
            parts = []
            if ts.framework:
                parts.append(_safe(ts.framework))
            if ts.language:
                parts.append(_safe(ts.language))
            if ts.server:
                parts.append(_safe(ts.server))
            if ts.database_hints:
                parts.append("DB:" + ",".join(_safe(h) for h in ts.database_hints))
            if ts.orm_hints:
                parts.append("ORM:" + ",".join(_safe(h) for h in ts.orm_hints))
            if ts.template_engine:
                parts.append("Template:" + _safe(ts.template_engine))
            if ts.cms:
                parts.append("CMS:" + _safe(ts.cms))
            if ts.waf_hints:
                parts.append("WAF:" + ",".join(_safe(h) for h in ts.waf_hints))
            if parts:
                lines.append("Tech: " + " | ".join(parts))

        if self.call_edges:
            lines.append(f"Observed call chains ({len(self.call_edges)}):")
            for e in self.call_edges[:5]:  # top 5 to keep prompt concise
                lines.append(
                    f"  {_safe(e.source_url)}[{_safe(e.source_field)}]"
                    f" → {_safe(e.target_url)}[{_safe(e.target_param)}]"
                    f" (confidence={e.confidence:.2f})"
                )

        if self.api_endpoints:
            lines.append(f"Known API endpoints ({len(self.api_endpoints)}):")
            for ep in self.api_endpoints[:10]:
                param_names = [_safe(p["name"]) for p in ep.params]
                lines.append(
                    f"  {_safe(ep.method)} {_safe(ep.path)}"
                    + (f" params={param_names}" if param_names else "")
                    + f" [{_safe(ep.source)}]"
                )

        return "\n".join(lines) if lines else ""

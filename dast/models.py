"""
Core data models for Frieren DAST-AI.

All data flowing through the pipeline is typed here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(str, Enum):
    PENDING = "pending"
    CRAWLING = "crawling"
    ATTACKING = "attacking"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class AttackVerdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    PROTECTED = "PROTECTED"
    NEEDS_RETRY = "NEEDS_RETRY"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class HttpResponse:
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class Interaction:
    """A single intercepted browser request+response pair."""
    request: HttpRequest
    response: HttpResponse
    page_url: str = ""
    triggered_by: str = ""  # "navigation" | "fetch" | "xhr" | "form_submit"


@dataclass
class EndpointParameter:
    name: str
    location: str       # "query" | "body" | "header" | "path" | "cookie"
    value: str = ""
    inferred_type: str = "string"  # "string" | "integer" | "boolean" | "object"


@dataclass
class Endpoint:
    """A discovered API endpoint or page."""
    url: str
    method: str
    parameters: List[EndpointParameter] = field(default_factory=list)
    auth_required: bool = False
    content_type: str = ""
    sample_request: Optional[HttpRequest] = None
    sample_response: Optional[HttpResponse] = None
    # Source: how this endpoint was discovered
    discovered_via: str = "crawl"  # "crawl" | "js_analysis" | "network_intercept" | "ai_inference"


@dataclass
class AttackPayload:
    """A single attack payload with metadata."""
    value: str
    attack_type: str           # e.g. "xss", "sqli", "idor", "ssrf"
    injection_point: str       # parameter name / header name
    injection_location: str    # "query" | "body" | "header" | "path"
    rationale: str = ""        # why this payload was chosen


@dataclass
class AttackAttempt:
    """One iteration of an attack against an endpoint."""
    endpoint: Endpoint
    payload: AttackPayload
    request: Optional[HttpRequest] = None
    response: Optional[HttpResponse] = None
    iteration: int = 1
    evidence: str = ""         # raw evidence from response
    verdict: AttackVerdict = AttackVerdict.INCONCLUSIVE
    ai_reasoning: str = ""


@dataclass
class Finding:
    """A confirmed or candidate security vulnerability."""
    title: str
    severity: Severity
    attack_type: str
    endpoint: Endpoint
    evidence: str
    ai_reasoning: str
    confirmed_attempts: List[AttackAttempt] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""
    confidence: float = 0.0


@dataclass
class ScanConfig:
    target_url: str
    auth_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    max_depth: int = 5
    max_pages: int = 200
    parallel_workers: int = 4
    request_delay_ms: int = 100
    browser_headless: bool = True
    max_attack_iterations: int = 3
    confidence_threshold: float = 0.7
    enabled_attack_types: List[str] = field(default_factory=lambda: [
        "xss", "sqli", "idor", "ssrf", "open_redirect",
        "auth_bypass", "mass_assignment", "graphql_injection"
    ])
    ai_model_id: str = ""
    output_dir: str = "./scan-results"


@dataclass
class ScanResult:
    config: ScanConfig
    status: ScanStatus
    endpoints_discovered: List[Endpoint] = field(default_factory=list)
    attack_attempts: List[AttackAttempt] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    scan_duration_s: float = 0.0
    pages_crawled: int = 0
    requests_made: int = 0
    errors: List[str] = field(default_factory=list)

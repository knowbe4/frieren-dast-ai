"""
Discovery package — enriches CheckTarget with dynamic context gathered
from traffic already flowing through the proxy.

Modules:
  fingerprinter   — tech stack detection from headers/bodies (zero extra requests)
  js_analyzer     — endpoint + param extraction from captured JS bundles
  traffic_graph   — call chain inference from observed request sequences
  openapi_probe   — OpenAPI/Swagger schema discovery (5 GETs per new host, cached)

All modules feed into DiscoveryContext which is attached to CheckTarget.
Agents treat it as read-only advisory context — never as proof of vulnerability.
"""

from dast.discovery.models import DiscoveryContext, ApiEndpoint, CallEdge, TechStack

__all__ = ["DiscoveryContext", "ApiEndpoint", "CallEdge", "TechStack"]

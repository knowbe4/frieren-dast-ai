"""
OpenAPI/Swagger discovery — sends up to 5 GET requests per new host (once, cached).

Tries common documentation paths. On success, parses the schema and extracts
all endpoints + parameters into ApiEndpoint objects.

Supported formats:
- OpenAPI 3.x (openapi: "3.x.x")
- Swagger 2.x (swagger: "2.0")
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Set

import httpx

from dast.discovery.models import ApiEndpoint
from dast.utils.logger import get_logger

logger = get_logger(__name__)

_PROBE_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/openapi.json",
    "/v2/api-docs",
    "/swagger/v1/swagger.json",
    "/docs/openapi.json",
    "/.well-known/openapi.json",
]

_TIMEOUT = httpx.Timeout(8.0)


class OpenApiProbe:
    """
    Discovers OpenAPI/Swagger schemas for new hosts.
    Thread-safe — checked_hosts is a set protected by asyncio lock.
    """

    def __init__(self) -> None:
        self._checked_hosts: Set[str] = set()
        self._lock = asyncio.Lock()
        # host → parsed schema (None = checked but not found)
        self._schemas: Dict[str, Optional[dict]] = {}

    async def probe_host(self, host: str, scheme: str = "https") -> Optional[dict]:
        """
        Probe a host for OpenAPI schema. Returns cached result on repeat calls.
        scheme: "https" or "http"
        """
        async with self._lock:
            if host in self._checked_hosts:
                return self._schemas.get(host)
            self._checked_hosts.add(host)

        base_url = f"{scheme}://{host}"
        schema = await self._try_paths(base_url)

        # If https failed, try http
        if schema is None and scheme == "https":
            schema = await self._try_paths(f"http://{host}")

        async with self._lock:
            self._schemas[host] = schema

        if schema:
            logger.info("OpenAPI schema discovered", host=host)
        else:
            logger.debug("No OpenAPI schema found", host=host)

        return schema

    async def _try_paths(self, base_url: str) -> Optional[dict]:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=_TIMEOUT,
        ) as client:
            for path in _PROBE_PATHS:
                try:
                    resp = await client.get(base_url + path)
                    if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                        data = resp.json()
                        if _is_openapi(data):
                            return data
                except Exception:
                    continue
        return None

    def already_checked(self, host: str) -> bool:
        return host in self._checked_hosts


def _is_openapi(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    return "openapi" in data or "swagger" in data


# ── schema parsers ─────────────────────────────────────────────────────────

def endpoints_from_schema(schema: dict) -> List[ApiEndpoint]:
    """Parse OpenAPI 2.x or 3.x schema into ApiEndpoint list."""
    if not isinstance(schema, dict):
        return []
    if "openapi" in schema:
        return _parse_openapi3(schema)
    if "swagger" in schema:
        return _parse_swagger2(schema)
    return []


def _parse_openapi3(schema: dict) -> List[ApiEndpoint]:
    endpoints = []
    paths = schema.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() in ("get", "post", "put", "delete", "patch", "head", "options"):
                params = _extract_params_openapi3(op)
                endpoints.append(ApiEndpoint(
                    method=method.upper(),
                    path=path,
                    params=params,
                    source="openapi",
                    description=op.get("summary") or op.get("description"),
                ))
    return endpoints


def _parse_swagger2(schema: dict) -> List[ApiEndpoint]:
    endpoints = []
    paths = schema.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() in ("get", "post", "put", "delete", "patch", "head"):
                params = _extract_params_swagger2(op)
                endpoints.append(ApiEndpoint(
                    method=method.upper(),
                    path=path,
                    params=params,
                    source="openapi",
                    description=op.get("summary") or op.get("description"),
                ))
    return endpoints


def _extract_params_openapi3(op: dict) -> List[dict]:
    params = []
    for p in op.get("parameters") or []:
        if not isinstance(p, dict):
            continue
        schema = p.get("schema") or {}
        params.append({
            "name": p.get("name", ""),
            "location": p.get("in", "query"),
            "type": schema.get("type", "string"),
            "description": p.get("description", ""),
        })
    # Request body
    body = op.get("requestBody") or {}
    content = body.get("content") or {}
    for ct, media in content.items():
        if not isinstance(media, dict):
            continue
        body_schema = media.get("schema") or {}
        for prop_name, prop in (body_schema.get("properties") or {}).items():
            params.append({
                "name": prop_name,
                "location": "body",
                "type": prop.get("type", "string") if isinstance(prop, dict) else "string",
                "description": prop.get("description", "") if isinstance(prop, dict) else "",
            })
    return params


def _extract_params_swagger2(op: dict) -> List[dict]:
    params = []
    for p in op.get("parameters") or []:
        if not isinstance(p, dict):
            continue
        location = p.get("in", "query")
        if location == "body":
            body_schema = p.get("schema") or {}
            for prop_name, prop in (body_schema.get("properties") or {}).items():
                params.append({
                    "name": prop_name,
                    "location": "body",
                    "type": prop.get("type", "string") if isinstance(prop, dict) else "string",
                    "description": "",
                })
        else:
            params.append({
                "name": p.get("name", ""),
                "location": location,
                "type": p.get("type", "string"),
                "description": p.get("description", ""),
            })
    return params

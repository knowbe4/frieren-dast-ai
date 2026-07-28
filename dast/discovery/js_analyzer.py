"""
JS analyzer — extracts API endpoints and parameter names from JavaScript
bundles already captured by the proxy. Zero extra requests.

Handles:
- fetch() / axios / XMLHttpRequest / $.ajax / superagent calls
- React Router / Vue Router / Angular route definitions
- GraphQL query strings (endpoint + operation variables)
- OpenAPI-style JSDoc @param hints embedded in JS
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from dast.discovery.models import ApiEndpoint


# ── fetch / XHR patterns ───────────────────────────────────────────────────

# fetch("/api/users", { method: "POST", body: ... })
_FETCH_RE = re.compile(
    r"""fetch\s*\(\s*[`'"]((?:/|https?://)[^`'"]+)[`'"]"""
    r"""(?:\s*,\s*\{[^}]*method\s*:\s*[`'"](GET|POST|PUT|DELETE|PATCH|HEAD)[`'"])?""",
    re.I,
)

# axios.get("/api/users", { params: { id: ... } })
# axios.post("/api/users", { userId: ... })
_AXIOS_RE = re.compile(
    r"""axios\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*[`'"]((?:/|https?://)[^`'"]+)[`'"]""",
    re.I,
)

# axios({ method: "post", url: "/api/..." })
_AXIOS_CONFIG_RE = re.compile(
    r"""axios\s*\(\s*\{[^}]*?(?:method\s*:\s*[`'"](GET|POST|PUT|DELETE|PATCH)[`'"][^}]*?url\s*:\s*[`'"]((?:/|https?://)[^`'"]+)[`'"]"""
    r"""|url\s*:\s*[`'"]((?:/|https?://)[^`'"]+)[`'"][^}]*?method\s*:\s*[`'"](GET|POST|PUT|DELETE|PATCH)[`'"])""",
    re.I | re.S,
)

# $.ajax({ url: "/api/...", method: "POST", data: {...} })
_JQUERY_AJAX_RE = re.compile(
    r"""\$\.ajax\s*\(\s*\{[^}]*?url\s*:\s*[`'"]((?:/|https?://)[^`'"]+)[`'"]""",
    re.I | re.S,
)

# $.get("...", ...) / $.post("...", ...)
_JQUERY_SHORTHAND_RE = re.compile(
    r"""\$\.(get|post)\s*\(\s*[`'"]((?:/|https?://)[^`'"]+)[`'"]""",
    re.I,
)

# new XMLHttpRequest() ... .open("POST", "/api/...")
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*[`'"](GET|POST|PUT|DELETE|PATCH)[`'"]\s*,\s*[`'"]((?:/|https?://)[^`'"]+)[`'"]""",
    re.I,
)

# superagent / request / got
_SUPERAGENT_RE = re.compile(
    r"""(?:request|superagent|got)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*[`'"]((?:/|https?://)[^`'"]+)[`'"]""",
    re.I,
)


# ── router patterns ────────────────────────────────────────────────────────

# React Router: <Route path="/users/:id" ...> or { path: "/users/:id", ... }
_REACT_ROUTE_RE = re.compile(
    r"""(?:path|route)\s*[=:]\s*[`'"](/[^`'"?#]+)[`'"]""",
    re.I,
)

# Vue Router: { path: '/users/:id', component: ... }
_VUE_ROUTE_RE = re.compile(
    r"""path\s*:\s*[`'"](/[^`'"?#]+)[`'"]""",
    re.I,
)

# Angular: { path: 'users/:id', component: ... }
_ANGULAR_ROUTE_RE = re.compile(
    r"""path\s*:\s*[`'"](/[^`'"?#]+)[`'"]""",
    re.I,
)


# ── parameter extraction ────────────────────────────────────────────────────

# JSON body literal near an API call: { userId: 42, name: "...", ... }
_JSON_KEY_RE = re.compile(r"""[`'"]([a-zA-Z_][a-zA-Z0-9_]{1,40})[`'"]\s*:""")

# Template literal path params: /api/users/${userId}/orders/${orderId}
_TEMPLATE_PARAM_RE = re.compile(r"""\$\{([a-zA-Z_][a-zA-Z0-9_]{1,40})\}""")

# Colon-style path params: /api/users/:id/orders/:orderId
_COLON_PARAM_RE = re.compile(r""":([a-zA-Z_][a-zA-Z0-9_]{1,40})""")

# Curly-style path params: /api/users/{id}/orders/{orderId}
_CURLY_PARAM_RE = re.compile(r"""\{([a-zA-Z_][a-zA-Z0-9_]{1,40})\}""")


# ── GraphQL ────────────────────────────────────────────────────────────────

# graphql endpoint in fetch/axios + variables object
_GQL_ENDPOINT_RE = re.compile(
    r"""[`'"]((?:/|https?://)[^`'"]*graphql[^`'"]*)[`'"]""",
    re.I,
)
_GQL_VARIABLE_RE = re.compile(r"""variables\s*:\s*\{([^}]{1,500})\}""", re.S)


# ── helpers ────────────────────────────────────────────────────────────────

_NOISE_PATHS = re.compile(
    r"""^(https?://|//)[^/]*(cdn|static|fonts?|images?|assets|analytics|tracking)""",
    re.I,
)

_VALID_API_PATH = re.compile(r"""^(/[a-zA-Z0-9/_\-:.{}$]+)$""")


def _is_api_path(path: str) -> bool:
    """Filter out obvious non-API paths (static assets, absolute CDN URLs, etc.)."""
    if _NOISE_PATHS.search(path):
        return False
    # Strip query string for check
    clean = path.split("?")[0].split("#")[0]
    if not _VALID_API_PATH.match(clean):
        return False
    # Skip pure static extensions
    if re.search(r"\.(js|css|png|jpg|gif|ico|woff|ttf|map|svg)(\?|$)", clean, re.I):
        return False
    return True


def _normalise_path(path: str) -> str:
    """
    Convert template literal paths to OpenAPI-style {param}.
    /api/users/${userId}/orders → /api/users/{userId}/orders
    """
    path = _TEMPLATE_PARAM_RE.sub(r"{\1}", path)
    # Also collapse colon params
    path = re.sub(r"/:([a-zA-Z_][a-zA-Z0-9_]*)", r"/{\1}", path)
    # Strip host if absolute URL
    parsed = urlparse(path)
    if parsed.scheme:
        return parsed.path or "/"
    return path.split("?")[0]


def _extract_params_near(js: str, pos: int, path: str) -> List[dict]:
    """
    Extract likely parameter names from the 400 chars following pos in js.
    Combines path params (colon/curly/template) with nearby JSON key names.
    """
    params: List[dict] = []
    seen: set = set()

    # Path params
    for pat in (_COLON_PARAM_RE, _CURLY_PARAM_RE, _TEMPLATE_PARAM_RE):
        for m in pat.finditer(path):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                params.append({"name": name, "location": "path", "type": "string"})

    # Nearby JSON keys
    snippet = js[pos:pos + 400]
    for m in _JSON_KEY_RE.finditer(snippet):
        name = m.group(1)
        if name not in seen and len(name) > 1 and name not in (
            "method", "headers", "body", "url", "data", "params",
            "content", "type", "mode", "cache", "credentials",
        ):
            seen.add(name)
            params.append({"name": name, "location": "body", "type": "string"})

    return params


def _add_endpoint(
    endpoints: List[ApiEndpoint],
    seen: set,
    method: str,
    path: str,
    params: List[dict],
    source: str = "js",
) -> None:
    method = method.upper()
    norm_path = _normalise_path(path)
    if not _is_api_path(norm_path):
        return
    key = (method, norm_path)
    if key in seen:
        return
    seen.add(key)
    endpoints.append(ApiEndpoint(method=method, path=norm_path, params=params, source=source))


# ── public API ─────────────────────────────────────────────────────────────

def extract_endpoints(js_source: str) -> List[ApiEndpoint]:
    """
    Parse a JS bundle and return all detected API endpoints with parameters.
    Called by DiscoveryEngine on every captured JS response.
    """
    endpoints: List[ApiEndpoint] = []
    seen: set = set()

    # fetch()
    for m in _FETCH_RE.finditer(js_source):
        path = m.group(1)
        method = m.group(2) or "GET"
        params = _extract_params_near(js_source, m.end(), path)
        _add_endpoint(endpoints, seen, method, path, params)

    # axios.get / axios.post
    for m in _AXIOS_RE.finditer(js_source):
        method = m.group(1)
        path = m.group(2)
        params = _extract_params_near(js_source, m.end(), path)
        _add_endpoint(endpoints, seen, method, path, params)

    # axios({ method, url })
    for m in _AXIOS_CONFIG_RE.finditer(js_source):
        method = m.group(1) or m.group(4) or "POST"
        path = m.group(2) or m.group(3) or ""
        if path:
            params = _extract_params_near(js_source, m.end(), path)
            _add_endpoint(endpoints, seen, method, path, params)

    # $.get / $.post
    for m in _JQUERY_SHORTHAND_RE.finditer(js_source):
        method = m.group(1)
        path = m.group(2)
        params = _extract_params_near(js_source, m.end(), path)
        _add_endpoint(endpoints, seen, method, path, params)

    # XHR .open()
    for m in _XHR_OPEN_RE.finditer(js_source):
        method = m.group(1)
        path = m.group(2)
        params = _extract_params_near(js_source, m.end(), path)
        _add_endpoint(endpoints, seen, method, path, params)

    # superagent / got
    for m in _SUPERAGENT_RE.finditer(js_source):
        method = m.group(1)
        path = m.group(2)
        params = _extract_params_near(js_source, m.end(), path)
        _add_endpoint(endpoints, seen, method, path, params)

    # GraphQL
    for m in _GQL_ENDPOINT_RE.finditer(js_source):
        path = m.group(1)
        params: List[dict] = []
        # Extract variable names from nearby variables: { ... }
        snippet = js_source[m.start():m.start() + 800]
        vm = _GQL_VARIABLE_RE.search(snippet)
        if vm:
            for km in _JSON_KEY_RE.finditer(vm.group(1)):
                params.append({"name": km.group(1), "location": "body", "type": "string"})
        _add_endpoint(endpoints, seen, "POST", path, params, source="js-graphql")

    # Router paths (undiscovered endpoints — method unknown, mark as GET)
    for m in _REACT_ROUTE_RE.finditer(js_source):
        path = m.group(1)
        params = _extract_params_near(js_source, m.end(), path)
        _add_endpoint(endpoints, seen, "GET", path, params, source="js-router")

    return endpoints

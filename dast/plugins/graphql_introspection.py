"""
GraphQL Introspection plugin.

On every proxied request, detects new GraphQL endpoints (POST requests whose
path ends with /graphql or whose body contains a GraphQL query/mutation) and
catalogues them in SessionStore.graphql_schemas keyed by endpoint URL — no
outbound request is made automatically. Introspection (which sends a real
request to the target, and needs the right auth headers for the endpoint's
owning session) is always a manual, user-triggered action from the GraphQL
tab's Schema Explorer (POST /api/graphql/introspect) or from rescanning
already-captured history (POST /api/graphql/rescan-history).

The findings importer reads introspected schemas when constructing query/mutation
bodies for imported reports, so the generated bodies match the actual API schema.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Optional

import httpx

from dast.proxy.plugin_base import ProxyPlugin
from dast.proxy.plugin_manager import log_event
from dast.utils.logger import get_logger

if TYPE_CHECKING:
    from dast.proxy.session_store import ProxyEntry, SessionStore

logger = get_logger(__name__)

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    mutationType { name }
    queryType { name }
    types {
      name
      kind
      fields(includeDeprecated: false) {
        name
        type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
        args {
          name
          type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
          defaultValue
        }
      }
      inputFields {
        name
        type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
        defaultValue
      }
      possibleTypes { name }
      enumValues { name }
    }
  }
}
""".strip()


def _is_graphql_endpoint(entry: "ProxyEntry") -> bool:
    if entry.method != "POST":
        return False
    path = entry.path.lower()
    if path.endswith("/graphql") or path.endswith("/graphql/"):
        return True
    # Body-based detection: JSON with a "query" key containing GraphQL syntax
    if entry.request_body:
        try:
            body = entry.request_body[:2000].decode("utf-8", errors="replace")
            if '"query"' in body:
                data = json.loads(body)
                if isinstance(data, dict) and isinstance(data.get("query"), str):
                    q = data["query"].strip()
                    if q.startswith(("query ", "mutation ", "subscription ", "{")):
                        return True
        except Exception:
            pass
    return False


def _endpoint_url(entry: "ProxyEntry") -> str:
    from urllib.parse import urlparse, urlunparse
    p = urlparse(entry.url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def _unwrap_type(t: Optional[dict], depth: int = 0) -> str:
    if not t or depth > 5:
        return "Unknown"
    if t.get("name"):
        return t["name"]
    return _unwrap_type(t.get("ofType"), depth + 1)


def _wrapper_kind(t: Optional[dict], depth: int = 0) -> Optional[str]:
    """
    Collapse a GraphQL type's NON_NULL/LIST wrapper chain into one compact label.

    The query builder only needs two facts to generate a valid argument: "must this
    always be supplied" (NON_NULL anywhere in the chain) and "is it a list at the
    outermost non-null layer" — real-world nesting never goes deeper than
    NON_NULL(LIST(NON_NULL(x))), so a flat label is enough; we don't need to carry
    the raw nested-dict wrapper structure into the compact schema.
    """
    if not t or depth > 5:
        return None
    kind = t.get("kind")
    if kind == "NON_NULL":
        inner = _wrapper_kind(t.get("ofType"), depth + 1)
        if inner == "LIST":
            return "NON_NULL_LIST"
        if inner == "LIST_OF_NON_NULL":
            return "NON_NULL_LIST_OF_NON_NULL"
        return "NON_NULL"
    if kind == "LIST":
        inner_type = t.get("ofType") or {}
        if inner_type.get("kind") == "NON_NULL":
            return "LIST_OF_NON_NULL"
        return "LIST"
    return None


def _compact_schema(raw: dict) -> dict:
    """
    Reduce introspection response to what the importer and query builder need:
    - mutations: {name: {args: [{name, type, wrapper}], return_type}}
    - queries:   {name: {args: [{name, type, wrapper}], return_type}}
    - input_types:  {name: {fields: [{name, type, wrapper}]}}
    - object_types: {name: {kind, fields: [{name, type, wrapper, arg_count}]}}
    - union_types:  {name: {possible_types: [str]}}
    - enum_types:   {name: {values: [str]}}
    """
    schema = (raw.get("data") or {}).get("__schema") or {}
    all_types: list = schema.get("types") or []

    mutation_root = (schema.get("mutationType") or {}).get("name", "Mutation")
    query_root = (schema.get("queryType") or {}).get("name", "Query")

    mutations: dict = {}
    queries: dict = {}
    input_types: dict = {}
    object_types: dict = {}
    union_types: dict = {}
    enum_types: dict = {}

    def _args(field: dict) -> list:
        return [
            {
                "name": a["name"],
                "type": _unwrap_type(a.get("type")),
                "wrapper": _wrapper_kind(a.get("type")),
            }
            for a in (field.get("args") or [])
        ]

    for t in all_types:
        name = t.get("name", "")
        kind = t.get("kind", "")

        # Collect mutation and query fields
        if name == mutation_root and kind == "OBJECT":
            for field in (t.get("fields") or []):
                mutations[field["name"]] = {
                    "args": _args(field),
                    "return_type": _unwrap_type(field.get("type")),
                }
        elif name == query_root and kind == "OBJECT":
            for field in (t.get("fields") or []):
                queries[field["name"]] = {
                    "args": _args(field),
                    "return_type": _unwrap_type(field.get("type")),
                }
        elif kind == "INPUT_OBJECT":
            input_types[name] = {
                "fields": [
                    {
                        "name": f["name"],
                        "type": _unwrap_type(f.get("type")),
                        "wrapper": _wrapper_kind(f.get("type")),
                    }
                    for f in (t.get("inputFields") or [])
                ]
            }
        elif kind in ("OBJECT", "INTERFACE") and name not in (mutation_root, query_root):
            object_types[name] = {
                "kind": kind,
                "fields": [
                    {
                        "name": f["name"],
                        "type": _unwrap_type(f.get("type")),
                        "wrapper": _wrapper_kind(f.get("type")),
                        "arg_count": len(f.get("args") or []),
                    }
                    for f in (t.get("fields") or [])
                ],
            }
        elif kind == "UNION":
            union_types[name] = {
                "possible_types": [
                    p["name"] for p in (t.get("possibleTypes") or []) if p.get("name")
                ]
            }
        elif kind == "ENUM":
            enum_types[name] = {
                "values": [
                    v["name"] for v in (t.get("enumValues") or []) if v.get("name")
                ]
            }

    return {
        "introspected": True,
        "mutations": mutations,
        "queries": queries,
        "input_types": input_types,
        "object_types": object_types,
        "union_types": union_types,
        "enum_types": enum_types,
        "ts": time.time(),
    }


async def _introspect(
    endpoint: str,
    headers: dict,
    store: "SessionStore",
    plugin_name: str = "GraphQL Introspection",
) -> Optional[str]:
    """
    Run introspection against `endpoint` using `headers` for auth, and store
    the compact schema on `store.graphql_schemas[endpoint]` on success.

    `headers` should carry whatever auth the caller has available (cookies,
    bearer tokens, etc.) — content-type/accept are set here regardless of
    what's passed in.

    Returns None on success, or a human-readable error string on failure —
    every failure is ALSO logged (warn/error, source="plugin") to the global
    system log for the Logs tab, but the caller should surface the returned
    string directly rather than sending the user to go check Logs, since the
    default Logs filter hides "warn"-level events.
    """
    headers = dict(headers)
    headers["content-type"] = "application/json"
    headers["accept"] = "application/json"

    body = json.dumps({"query": _INTROSPECTION_QUERY})

    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(15.0),
            follow_redirects=False,
        ) as client:
            resp = await client.post(endpoint, content=body, headers=headers)

        if resp.status_code != 200:
            error = f"Introspection failed: HTTP {resp.status_code}"
            logger.debug("GraphQL introspection returned non-200", endpoint=endpoint, status=resp.status_code)
            log_event(plugin_name, "warn", error, url=endpoint)
            return error

        data = resp.json()
        if "errors" in data and not data.get("data"):
            server_message = ""
            errors_list = data.get("errors") or []
            if errors_list and isinstance(errors_list[0], dict):
                server_message = str(errors_list[0].get("message", ""))[:200]
            error = "Introspection disabled on this endpoint" + (f" — {server_message}" if server_message else "")
            logger.debug("GraphQL introspection disabled or errored", endpoint=endpoint, errors=errors_list[:1])
            log_event(plugin_name, "warn", error, url=endpoint)
            return error

        schema = _compact_schema(data)
        mutation_count = len(schema.get("mutations") or {})
        query_count = len(schema.get("queries") or {})

        store.graphql_schemas[endpoint] = schema
        logger.info(
            "GraphQL schema stored",
            endpoint=endpoint,
            mutations=mutation_count,
            queries=query_count,
        )
        log_event(
            plugin_name, "info",
            f"Schema loaded: {mutation_count} mutations, {query_count} queries",
            url=endpoint,
        )
        return None

    except Exception as exc:
        error = f"Introspection error: {exc}"
        logger.debug("GraphQL introspection error", endpoint=endpoint, error=str(exc))
        log_event(plugin_name, "error", error, url=endpoint)
        return error


def catalogue_endpoint(endpoint: str, store: "SessionStore") -> bool:
    """
    Record `endpoint` as a known GraphQL endpoint if not already known — never
    overwrites an already-introspected schema. Returns True if this call added
    a new entry, False if the endpoint was already known (in any state).
    """
    if endpoint in store.graphql_schemas:
        return False
    store.graphql_schemas[endpoint] = {"introspected": False}
    return True


class GraphQLIntrospectionPlugin(ProxyPlugin):
    name = "GraphQL Introspection"
    description = (
        "Catalogues GraphQL endpoints seen in proxied traffic. Introspection itself "
        "is always a manual action from the GraphQL tab — this plugin never sends "
        "an outbound request on its own."
    )
    version = "0.2.0"
    author = "dast-ai"
    enabled = True
    active = False

    async def on_entry(self, entry: "ProxyEntry", store: "SessionStore") -> None:
        if entry.source in ("agent",):
            return
        if not _is_graphql_endpoint(entry):
            return

        endpoint = _endpoint_url(entry)
        if catalogue_endpoint(endpoint, store):
            logger.debug("GraphQL endpoint catalogued", endpoint=endpoint)
            log_event(
                self.name, "info",
                "New GraphQL endpoint discovered — run introspection from the GraphQL tab to load its schema",
                url=endpoint,
            )

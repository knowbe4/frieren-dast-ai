"""
Schema-driven GraphQL query/mutation builder.

Given the extended compact schema produced by
dast.plugins.graphql_introspection._compact_schema(), generates a complete,
runnable GraphQL operation (query text + variables dict) for any discovered
query or mutation field — argument values are filled in with type-aware
heuristics, and the return-field selection set is generated recursively from
the schema's object/union types.

All functions here are pure (no I/O, no session-store access) — the schema
dict is the only input, making this trivially unit-testable.

Adapted from a schema-driven query-builder algorithm to the compact schema
shape already stored by this project's introspection plugin instead of
re-walking a raw introspection response.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from dast.utils.logger import get_logger

logger = get_logger(__name__)

# Recursion caps — mirror the ported algorithm's limits to avoid infinite
# loops on recursive input/object types and to keep generated queries small.
MAX_INPUT_DEPTH = 3
MAX_SELECTION_DEPTH = 2
MAX_FIELDS_PER_LEVEL = 15

# Argument-name hints for context-aware Int values.
_LIMIT_NAME_RE = re.compile(r"(first|limit|count|size)", re.IGNORECASE)
_OFFSET_NAME_RE = re.compile(r"(skip|offset)", re.IGNORECASE)

# Custom-scalar name-pattern heuristics — matched against the bare type name.
_DATE_TYPE_RE = re.compile(r"date|time", re.IGNORECASE)
_UUID_TYPE_RE = re.compile(r"uuid|guid", re.IGNORECASE)
_URL_TYPE_RE = re.compile(r"url|uri", re.IGNORECASE)
_EMAIL_TYPE_RE = re.compile(r"email", re.IGNORECASE)

_SAMPLE_UUID = "00000000-0000-0000-0000-000000000000"
_SAMPLE_URL = "https://example.com"
_SAMPLE_EMAIL = "test@example.com"
_SAMPLE_DATE = "2024-01-01T00:00:00Z"

_BUILTIN_SCALARS = frozenset({"String", "Int", "Float", "Boolean", "ID"})


_OPERATION_BUCKET = {"query": "queries", "mutation": "mutations"}


def _lookup_field(schema: dict, operation_kind: str, field_name: str) -> dict:
    bucket = schema.get(_OPERATION_BUCKET.get(operation_kind, ""), {})
    field = bucket.get(field_name)
    if field is None:
        raise ValueError(f"{operation_kind} field '{field_name}' not found in schema")
    return field


def _is_list_wrapper(wrapper: Optional[str]) -> bool:
    return wrapper in ("LIST", "NON_NULL_LIST", "LIST_OF_NON_NULL", "NON_NULL_LIST_OF_NON_NULL")


def _is_required_wrapper(wrapper: Optional[str]) -> bool:
    return wrapper in ("NON_NULL", "NON_NULL_LIST", "NON_NULL_LIST_OF_NON_NULL")


def _gql_type_string(bare_type: str, wrapper: Optional[str]) -> str:
    """Render a GraphQL type reference string for a $var declaration, e.g. '[ID!]!'."""
    if wrapper == "NON_NULL":
        return f"{bare_type}!"
    if wrapper == "LIST":
        return f"[{bare_type}]"
    if wrapper == "NON_NULL_LIST":
        return f"[{bare_type}]!"
    if wrapper == "LIST_OF_NON_NULL":
        return f"[{bare_type}!]"
    if wrapper == "NON_NULL_LIST_OF_NON_NULL":
        return f"[{bare_type}!]!"
    return bare_type


def _scalar_value(bare_type: str, arg_name: str) -> Any:
    """Heuristic value for a builtin or custom scalar type."""
    if bare_type == "Int":
        if _LIMIT_NAME_RE.search(arg_name):
            return 10
        if _OFFSET_NAME_RE.search(arg_name):
            return 0
        return 1
    if bare_type == "Float":
        return 1.0
    if bare_type == "Boolean":
        return True
    if bare_type == "ID":
        return "1"
    if bare_type == "String":
        if _DATE_TYPE_RE.search(arg_name):
            return _SAMPLE_DATE
        return "sample"
    # Custom scalar — guess from the scalar's own type name first, then arg name.
    if _DATE_TYPE_RE.search(bare_type):
        return _SAMPLE_DATE
    if _UUID_TYPE_RE.search(bare_type):
        return _SAMPLE_UUID
    if _URL_TYPE_RE.search(bare_type):
        return _SAMPLE_URL
    if _EMAIL_TYPE_RE.search(bare_type):
        return _SAMPLE_EMAIL
    if _DATE_TYPE_RE.search(arg_name):
        return _SAMPLE_DATE
    if _UUID_TYPE_RE.search(arg_name):
        return _SAMPLE_UUID
    if _EMAIL_TYPE_RE.search(arg_name):
        return _SAMPLE_EMAIL
    return "sample"


def build_argument_value(
    schema: dict,
    arg_type: str,
    wrapper: Optional[str],
    *,
    arg_name: str = "",
    _depth: int = 0,
    _seen_input_types: Optional[Set[str]] = None,
) -> Any:
    """
    Generate a heuristic literal value for one argument, given its bare type
    name and wrapper encoding. Returns a plain Python value suitable for
    json.dumps() into a GraphQL `variables` object.

    Resolution order: ENUM -> first enum value; INPUT_OBJECT -> recurse into a
    dict literal (capped at MAX_INPUT_DEPTH, with cycle detection against
    _seen_input_types); otherwise scalar heuristics (builtin or custom).
    A LIST wrapper wraps the single generated value in a one-element list.
    """
    if _seen_input_types is None:
        _seen_input_types = set()

    if arg_type in schema.get("enum_types", {}):
        values = schema["enum_types"][arg_type].get("values") or []
        value: Any = values[0] if values else "UNKNOWN"
    elif arg_type in schema.get("input_types", {}):
        value = _build_input_object(schema, arg_type, _depth=_depth, _seen_input_types=_seen_input_types)
    else:
        value = _scalar_value(arg_type, arg_name)

    if _is_list_wrapper(wrapper):
        return [value]
    return value


def _build_input_object(
    schema: dict,
    input_type_name: str,
    *,
    _depth: int,
    _seen_input_types: Set[str],
) -> Dict[str, Any]:
    if _depth >= MAX_INPUT_DEPTH or input_type_name in _seen_input_types:
        return {}

    seen = _seen_input_types | {input_type_name}
    fields = schema.get("input_types", {}).get(input_type_name, {}).get("fields") or []
    result: Dict[str, Any] = {}
    for f in fields:
        field_type = f.get("type", "")
        # Cycle guard: a field whose own type is the enclosing input type would
        # recurse forever — skip it (matches the ported algorithm's behaviour).
        if field_type == input_type_name:
            continue
        result[f["name"]] = build_argument_value(
            schema, field_type, f.get("wrapper"),
            arg_name=f["name"], _depth=_depth + 1, _seen_input_types=seen,
        )
    return result


def build_selection_set(schema: dict, return_type: str, *, _depth: int = 0) -> str:
    """
    Recursively build a `{ field1 field2 { nested } }` selection-set string for
    the given return type name, using schema['object_types']/['union_types'].
    Falls back to `__typename` when the type is unknown, has no fields, or
    recursion is capped.
    """
    if return_type in schema.get("union_types", {}):
        possible = schema["union_types"][return_type].get("possible_types") or []
        if not possible:
            return "{ __typename }"
        first = possible[0]
        inner = build_selection_set(schema, first, _depth=_depth)
        return f"{{ ... on {first} {inner} }}"

    obj = schema.get("object_types", {}).get(return_type)
    if not obj or _depth >= MAX_SELECTION_DEPTH:
        return "{ __typename }"

    fields = obj.get("fields") or []
    parts: List[str] = []
    for f in fields[:MAX_FIELDS_PER_LEVEL]:
        if f.get("arg_count", 0) > 0:
            continue  # would require args we can't supply in a selection set
        field_type = f.get("type", "")
        is_container = (
            field_type in schema.get("object_types", {})
            or field_type in schema.get("union_types", {})
        )
        if is_container:
            nested = build_selection_set(schema, field_type, _depth=_depth + 1)
            parts.append(f"{f['name']} {nested}")
        else:
            parts.append(f["name"])

    if not parts:
        return "{ __typename }"
    return "{ " + " ".join(parts) + " }"


def build_operation(schema: dict, operation_kind: str, field_name: str) -> Dict[str, Any]:
    """
    Build a complete GraphQL operation for the given query/mutation field.

    Returns {"query": str, "variables": dict, "operation_name": str}.
    Raises ValueError if field_name is not found under schema[f"{operation_kind}s"].
    """
    if operation_kind not in ("query", "mutation"):
        raise ValueError(f"operation_kind must be 'query' or 'mutation', got {operation_kind!r}")

    field = _lookup_field(schema, operation_kind, field_name)
    args = field.get("args") or []

    var_decls: List[str] = []
    call_args: List[str] = []
    variables: Dict[str, Any] = {}
    seen_input_types: Set[str] = set()

    for i, arg in enumerate(args):
        var_name = f"var{i}"
        gql_type = _gql_type_string(arg["type"], arg.get("wrapper"))
        var_decls.append(f"${var_name}: {gql_type}")
        call_args.append(f"{arg['name']}: ${var_name}")
        variables[var_name] = build_argument_value(
            schema, arg["type"], arg.get("wrapper"),
            arg_name=arg["name"], _seen_input_types=seen_input_types,
        )

    return_type = field.get("return_type", "")
    selection = build_selection_set(schema, return_type) if return_type else "{ __typename }"

    op_name = field_name[0].upper() + field_name[1:] if field_name else "Op"
    decls = "(" + ", ".join(var_decls) + ")" if var_decls else ""
    call = "(" + ", ".join(call_args) + ")" if call_args else ""

    query = f"{operation_kind} {op_name}{decls} {{ {field_name}{call} {selection} }}"

    logger.debug(
        "GraphQL operation built",
        operation_kind=operation_kind, field_name=field_name, var_count=len(variables),
    )

    return {"query": query, "variables": variables, "operation_name": op_name}

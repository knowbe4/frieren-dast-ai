"""
Unit tests for dast.plugins.graphql_introspection's schema compaction.

Covers _wrapper_kind (NON_NULL/LIST collapsing) and _compact_schema's extended
output (return_type, wrapper, object_types, union_types, enum_types) added to
support the GraphQL query builder (dast/graphql/query_builder.py).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dast.plugins.graphql_introspection import (
    GraphQLIntrospectionPlugin,
    _compact_schema,
    _is_graphql_endpoint,
    _unwrap_type,
    _wrapper_kind,
    catalogue_endpoint,
)


def _scalar(name: str) -> dict:
    return {"name": name, "kind": "SCALAR"}


def _non_null(inner: dict) -> dict:
    return {"kind": "NON_NULL", "ofType": inner}


def _list(inner: dict) -> dict:
    return {"kind": "LIST", "ofType": inner}


class TestWrapperKind:
    def test_bare_scalar_has_no_wrapper(self):
        assert _wrapper_kind(_scalar("String")) is None

    def test_non_null_scalar(self):
        assert _wrapper_kind(_non_null(_scalar("String"))) == "NON_NULL"

    def test_list_of_nullable(self):
        assert _wrapper_kind(_list(_scalar("String"))) == "LIST"

    def test_non_null_list_of_nullable(self):
        assert _wrapper_kind(_non_null(_list(_scalar("String")))) == "NON_NULL_LIST"

    def test_list_of_non_null(self):
        assert _wrapper_kind(_list(_non_null(_scalar("String")))) == "LIST_OF_NON_NULL"

    def test_non_null_list_of_non_null(self):
        t = _non_null(_list(_non_null(_scalar("String"))))
        assert _wrapper_kind(t) == "NON_NULL_LIST_OF_NON_NULL"

    def test_none_input(self):
        assert _wrapper_kind(None) is None


class TestUnwrapType:
    def test_unwraps_through_all_wrappers(self):
        t = _non_null(_list(_non_null(_scalar("String"))))
        assert _unwrap_type(t) == "String"

    def test_none_input_returns_unknown(self):
        assert _unwrap_type(None) == "Unknown"


def _raw_schema(types: list, mutation_root: str = "Mutation", query_root: str = "Query") -> dict:
    return {
        "data": {
            "__schema": {
                "mutationType": {"name": mutation_root},
                "queryType": {"name": query_root},
                "types": types,
            }
        }
    }


class TestCompactSchema:
    def test_query_field_captures_return_type_and_arg_wrapper(self):
        raw = _raw_schema([
            {
                "name": "Query", "kind": "OBJECT",
                "fields": [{
                    "name": "user",
                    "type": {"name": "User", "kind": "OBJECT"},
                    "args": [{"name": "id", "type": _non_null(_scalar("ID"))}],
                }],
            },
        ])
        result = _compact_schema(raw)
        assert result["queries"]["user"]["return_type"] == "User"
        assert result["queries"]["user"]["args"] == [
            {"name": "id", "type": "ID", "wrapper": "NON_NULL"}
        ]

    def test_mutation_field_captures_input_object_arg(self):
        raw = _raw_schema([
            {
                "name": "Mutation", "kind": "OBJECT",
                "fields": [{
                    "name": "createUser",
                    "type": {"name": "User", "kind": "OBJECT"},
                    "args": [{"name": "input", "type": _non_null(
                        {"name": "CreateUserInput", "kind": "INPUT_OBJECT"}
                    )}],
                }],
            },
        ])
        result = _compact_schema(raw)
        assert result["mutations"]["createUser"]["args"][0]["type"] == "CreateUserInput"
        assert result["mutations"]["createUser"]["args"][0]["wrapper"] == "NON_NULL"

    def test_input_object_fields_captured(self):
        raw = _raw_schema([
            {
                "name": "CreateUserInput", "kind": "INPUT_OBJECT",
                "inputFields": [
                    {"name": "email", "type": _non_null(_scalar("String"))},
                    {"name": "role", "type": {"name": "Role", "kind": "ENUM"}},
                ],
            },
        ])
        result = _compact_schema(raw)
        assert result["input_types"]["CreateUserInput"]["fields"] == [
            {"name": "email", "type": "String", "wrapper": "NON_NULL"},
            {"name": "role", "type": "Role", "wrapper": None},
        ]

    def test_object_type_excludes_root_types_and_includes_others(self):
        raw = _raw_schema([
            {"name": "Query", "kind": "OBJECT", "fields": []},
            {"name": "Mutation", "kind": "OBJECT", "fields": []},
            {
                "name": "User", "kind": "OBJECT",
                "fields": [
                    {"name": "id", "type": _non_null(_scalar("ID")), "args": []},
                    {"name": "posts", "type": _list({"name": "Post", "kind": "OBJECT"}),
                     "args": [{"name": "limit", "type": _scalar("Int")}]},
                ],
            },
        ])
        result = _compact_schema(raw)
        assert "Query" not in result["object_types"]
        assert "Mutation" not in result["object_types"]
        user = result["object_types"]["User"]
        assert user["kind"] == "OBJECT"
        assert user["fields"][0] == {"name": "id", "type": "ID", "wrapper": "NON_NULL", "arg_count": 0}
        assert user["fields"][1] == {"name": "posts", "type": "Post", "wrapper": "LIST", "arg_count": 1}

    def test_interface_type_captured_as_object_type(self):
        raw = _raw_schema([
            {"name": "Node", "kind": "INTERFACE", "fields": [
                {"name": "id", "type": _non_null(_scalar("ID")), "args": []},
            ]},
        ])
        result = _compact_schema(raw)
        assert result["object_types"]["Node"]["kind"] == "INTERFACE"

    def test_union_type_captures_possible_types(self):
        raw = _raw_schema([
            {
                "name": "SearchResult", "kind": "UNION",
                "possibleTypes": [{"name": "User"}, {"name": "Post"}],
            },
        ])
        result = _compact_schema(raw)
        assert result["union_types"]["SearchResult"]["possible_types"] == ["User", "Post"]

    def test_enum_type_captures_values(self):
        raw = _raw_schema([
            {
                "name": "Role", "kind": "ENUM",
                "enumValues": [{"name": "ADMIN"}, {"name": "USER"}],
            },
        ])
        result = _compact_schema(raw)
        assert result["enum_types"]["Role"]["values"] == ["ADMIN", "USER"]

    def test_empty_schema_produces_empty_maps(self):
        result = _compact_schema({"data": {"__schema": {"types": []}}})
        assert result["mutations"] == {}
        assert result["queries"] == {}
        assert result["input_types"] == {}
        assert result["object_types"] == {}
        assert result["union_types"] == {}
        assert result["enum_types"] == {}
        assert "ts" in result

    def test_non_standard_root_type_names_are_respected(self):
        raw = _raw_schema(
            [
                {
                    "name": "RootQueryType", "kind": "OBJECT",
                    "fields": [{"name": "ping", "type": _scalar("String"), "args": []}],
                },
            ],
            query_root="RootQueryType",
        )
        result = _compact_schema(raw)
        assert "ping" in result["queries"]
        # RootQueryType itself must not leak into object_types (it's the query root)
        assert "RootQueryType" not in result["object_types"]


class TestIsGraphqlEndpoint:
    class _FakeEntry:
        def __init__(self, method: str, path: str, body: bytes | None):
            self.method = method
            self.path = path
            self.request_body = body

    def test_path_suffix_graphql_detected(self):
        entry = self._FakeEntry("POST", "/api/graphql", None)
        assert _is_graphql_endpoint(entry) is True

    def test_body_query_field_detected(self):
        entry = self._FakeEntry("POST", "/api/anything", b'{"query": "query { me }"}')
        assert _is_graphql_endpoint(entry) is True

    def test_get_request_not_detected(self):
        entry = self._FakeEntry("GET", "/graphql", None)
        assert _is_graphql_endpoint(entry) is False

    def test_unrelated_json_body_not_detected(self):
        entry = self._FakeEntry("POST", "/api/users", b'{"name": "bob"}')
        assert _is_graphql_endpoint(entry) is False


class TestCatalogueEndpoint:
    def _store(self):
        from dast.proxy.session_store import SessionStore
        return SessionStore()

    def test_new_endpoint_is_catalogued_uninstrospected(self):
        store = self._store()
        added = catalogue_endpoint("https://example.com/graphql", store)
        assert added is True
        assert store.graphql_schemas["https://example.com/graphql"] == {"introspected": False}

    def test_already_known_endpoint_is_not_reset(self):
        store = self._store()
        store.graphql_schemas["https://example.com/graphql"] = {"introspected": True, "queries": {"x": {}}}
        added = catalogue_endpoint("https://example.com/graphql", store)
        assert added is False
        # Must not clobber an already-introspected schema with the sentinel.
        assert store.graphql_schemas["https://example.com/graphql"]["introspected"] is True
        assert "queries" in store.graphql_schemas["https://example.com/graphql"]


class TestOnEntryNeverAutoIntrospects:
    class _FakeEntry:
        def __init__(self, method="POST", path="/graphql", body=None, source="proxy", url="https://example.com/graphql"):
            self.method = method
            self.path = path
            self.request_body = body
            self.source = source
            self.url = url
            self.request_headers = {}

    def _store(self):
        from dast.proxy.session_store import SessionStore
        return SessionStore()

    @pytest.mark.asyncio
    async def test_on_entry_catalogues_without_calling_introspect(self):
        store = self._store()
        plugin = GraphQLIntrospectionPlugin()
        with patch("dast.plugins.graphql_introspection._introspect", AsyncMock()) as mock_introspect:
            await plugin.on_entry(self._FakeEntry(), store)
        mock_introspect.assert_not_called()
        assert store.graphql_schemas["https://example.com/graphql"] == {"introspected": False}

    @pytest.mark.asyncio
    async def test_on_entry_ignores_agent_traffic(self):
        store = self._store()
        plugin = GraphQLIntrospectionPlugin()
        await plugin.on_entry(self._FakeEntry(source="agent"), store)
        assert store.graphql_schemas == {}

    @pytest.mark.asyncio
    async def test_on_entry_ignores_non_graphql_traffic(self):
        store = self._store()
        plugin = GraphQLIntrospectionPlugin()
        await plugin.on_entry(self._FakeEntry(path="/api/users"), store)
        assert store.graphql_schemas == {}

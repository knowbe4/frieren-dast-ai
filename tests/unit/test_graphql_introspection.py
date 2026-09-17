"""
Unit tests for dast.plugins.graphql_introspection's schema compaction.

Covers _wrapper_kind (NON_NULL/LIST collapsing) and _compact_schema's extended
output (return_type, wrapper, object_types, union_types, enum_types) added to
support the GraphQL query builder (dast/graphql/query_builder.py).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

import json

from dast.plugins.graphql_introspection import (
    GraphQLIntrospectionPlugin,
    _compact_schema,
    _is_graphql_endpoint,
    _request_is_introspection,
    _unwrap_type,
    _wrapper_kind,
    catalogue_endpoint,
    store_captured_introspection,
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


_INTROSPECTION_REQUEST_BODY = b'{"query": "query IntrospectionQuery { __schema { queryType { name } } }"}'


def _introspection_response_body() -> bytes:
    """A minimal but valid introspection response with one query and one mutation."""
    raw = {
        "data": {
            "__schema": {
                "mutationType": {"name": "Mutation"},
                "queryType": {"name": "Query"},
                "types": [
                    {
                        "name": "Query", "kind": "OBJECT",
                        "fields": [{
                            "name": "me",
                            "type": {"name": "User", "kind": "OBJECT"},
                            "args": [],
                        }],
                    },
                    {
                        "name": "Mutation", "kind": "OBJECT",
                        "fields": [{
                            "name": "login",
                            "type": {"name": "String", "kind": "SCALAR"},
                            "args": [{"name": "password", "type": _non_null(_scalar("String"))}],
                        }],
                    },
                ],
            }
        }
    }
    return json.dumps(raw).encode("utf-8")


class _CaptureEntry:
    def __init__(
        self,
        request_body: bytes | None = _INTROSPECTION_REQUEST_BODY,
        response_status: int | None = 200,
        response_body: bytes | None = None,
        source: str = "browse",
        method: str = "POST",
        path: str = "/graphql",
        url: str = "https://example.com/graphql",
    ):
        self.request_body = request_body
        self.response_status = response_status
        self.response_body = _introspection_response_body() if response_body is None else response_body
        self.source = source
        self.method = method
        self.path = path
        self.url = url
        self.request_headers = {}


class TestRequestIsIntrospection:
    def test_detects_schema_query(self):
        assert _request_is_introspection(_CaptureEntry()) is True

    def test_plain_query_is_not_introspection(self):
        assert _request_is_introspection(_CaptureEntry(request_body=b'{"query": "{ me }"}')) is False

    def test_empty_body_is_not_introspection(self):
        assert _request_is_introspection(_CaptureEntry(request_body=None)) is False


class TestStoreCapturedIntrospection:
    def _store(self):
        from dast.proxy.session_store import SessionStore
        return SessionStore()

    def test_captured_introspection_is_stored_with_schema(self):
        store = self._store()
        stored = store_captured_introspection(
            _CaptureEntry(), "https://example.com/graphql", store
        )
        assert stored is True
        schema = store.graphql_schemas["https://example.com/graphql"]
        assert schema["introspected"] is True
        assert "me" in schema["queries"]
        assert "login" in schema["mutations"]

    def test_overwrites_uninstrospected_sentinel(self):
        store = self._store()
        store.graphql_schemas["https://example.com/graphql"] = {"introspected": False}
        stored = store_captured_introspection(
            _CaptureEntry(), "https://example.com/graphql", store
        )
        assert stored is True
        assert store.graphql_schemas["https://example.com/graphql"]["introspected"] is True

    def test_does_not_clobber_existing_introspected_schema(self):
        store = self._store()
        store.graphql_schemas["https://example.com/graphql"] = {
            "introspected": True, "queries": {"manual": {}}
        }
        stored = store_captured_introspection(
            _CaptureEntry(), "https://example.com/graphql", store
        )
        assert stored is False
        assert store.graphql_schemas["https://example.com/graphql"]["queries"] == {"manual": {}}

    def test_non_200_response_is_not_stored(self):
        store = self._store()
        stored = store_captured_introspection(
            _CaptureEntry(response_status=403), "https://example.com/graphql", store
        )
        assert stored is False
        assert store.graphql_schemas == {}

    def test_non_introspection_request_is_not_stored(self):
        store = self._store()
        stored = store_captured_introspection(
            _CaptureEntry(request_body=b'{"query": "{ me }"}'),
            "https://example.com/graphql", store,
        )
        assert stored is False
        assert store.graphql_schemas == {}

    def test_response_without_schema_data_is_not_stored(self):
        store = self._store()
        stored = store_captured_introspection(
            _CaptureEntry(response_body=b'{"data": {"me": {"id": 1}}}'),
            "https://example.com/graphql", store,
        )
        assert stored is False
        assert store.graphql_schemas == {}

    def test_non_json_response_is_not_stored(self):
        store = self._store()
        stored = store_captured_introspection(
            _CaptureEntry(response_body=b"<html>not json</html>"),
            "https://example.com/graphql", store,
        )
        assert stored is False
        assert store.graphql_schemas == {}


class TestOnEntryHarvestsCapturedIntrospection:
    def _store(self):
        from dast.proxy.session_store import SessionStore
        return SessionStore()

    @pytest.mark.asyncio
    async def test_on_entry_harvests_schema_from_captured_response(self):
        store = self._store()
        plugin = GraphQLIntrospectionPlugin()
        # Never sends an outbound request — the schema comes from the captured response.
        with patch("dast.plugins.graphql_introspection._introspect", AsyncMock()) as mock_introspect:
            await plugin.on_entry(_CaptureEntry(), store)
        mock_introspect.assert_not_called()
        schema = store.graphql_schemas["https://example.com/graphql"]
        assert schema["introspected"] is True
        assert "me" in schema["queries"]
        assert "login" in schema["mutations"]

    @pytest.mark.asyncio
    async def test_on_entry_ignores_agent_captured_introspection(self):
        store = self._store()
        plugin = GraphQLIntrospectionPlugin()
        await plugin.on_entry(_CaptureEntry(source="agent"), store)
        assert store.graphql_schemas == {}

    @pytest.mark.asyncio
    async def test_on_entry_plain_query_only_catalogues(self):
        # A normal (non-introspection) GraphQL request just catalogues the endpoint.
        store = self._store()
        plugin = GraphQLIntrospectionPlugin()
        await plugin.on_entry(
            _CaptureEntry(request_body=b'{"query": "{ me }"}', response_body=b'{"data": {"me": null}}'),
            store,
        )
        assert store.graphql_schemas["https://example.com/graphql"] == {"introspected": False}

"""
Unit tests for dast.graphql.query_builder — the schema-driven GraphQL
query/mutation generator.
"""

from __future__ import annotations

import re

import pytest

from dast.graphql.query_builder import (
    build_argument_value,
    build_operation,
    build_selection_set,
)


def _schema(**overrides) -> dict:
    base = {
        "queries": {},
        "mutations": {},
        "input_types": {},
        "object_types": {},
        "union_types": {},
        "enum_types": {},
    }
    base.update(overrides)
    return base


# ── build_argument_value ──────────────────────────────────────────────────────

class TestBuildArgumentValue:
    def test_scalar_string(self):
        schema = _schema()
        assert build_argument_value(schema, "String", None) == "sample"

    def test_scalar_int_default(self):
        schema = _schema()
        assert build_argument_value(schema, "Int", None, arg_name="count") == 10

    def test_scalar_int_offset_hint(self):
        schema = _schema()
        assert build_argument_value(schema, "Int", None, arg_name="offset") == 0

    def test_scalar_int_plain(self):
        schema = _schema()
        assert build_argument_value(schema, "Int", None, arg_name="age") == 1

    def test_scalar_boolean(self):
        schema = _schema()
        assert build_argument_value(schema, "Boolean", None) is True

    def test_scalar_id(self):
        schema = _schema()
        assert build_argument_value(schema, "ID", None) == "1"

    def test_scalar_float(self):
        schema = _schema()
        assert build_argument_value(schema, "Float", None) == 1.0

    def test_custom_scalar_uuid_by_type_name(self):
        schema = _schema()
        value = build_argument_value(schema, "UUID", None)
        assert re.match(r"^[0-9a-f-]{36}$", value)

    def test_custom_scalar_email_by_type_name(self):
        schema = _schema()
        assert "@" in build_argument_value(schema, "Email", None)

    def test_custom_scalar_url_by_type_name(self):
        schema = _schema()
        assert build_argument_value(schema, "URL", None).startswith("http")

    def test_custom_scalar_date_by_arg_name(self):
        schema = _schema()
        value = build_argument_value(schema, "SomeScalar", None, arg_name="createdDate")
        assert "T" in value  # ISO8601-ish

    def test_enum_returns_first_value(self):
        schema = _schema(enum_types={"Role": {"values": ["ADMIN", "USER"]}})
        assert build_argument_value(schema, "Role", None) == "ADMIN"

    def test_enum_with_no_values_falls_back(self):
        schema = _schema(enum_types={"Empty": {"values": []}})
        assert build_argument_value(schema, "Empty", None) == "UNKNOWN"

    def test_list_wrapper_wraps_value_in_list(self):
        schema = _schema()
        assert build_argument_value(schema, "String", "LIST") == ["sample"]

    def test_non_null_list_wrapper_wraps_value_in_list(self):
        schema = _schema()
        assert build_argument_value(schema, "Int", "NON_NULL_LIST", arg_name="ids") == [1]

    def test_input_object_recurses_into_dict(self):
        schema = _schema(input_types={
            "Input": {"fields": [
                {"name": "email", "type": "String", "wrapper": "NON_NULL"},
                {"name": "age", "type": "Int", "wrapper": None},
            ]}
        })
        result = build_argument_value(schema, "Input", None)
        assert result == {"email": "sample", "age": 1}

    def test_input_object_self_reference_is_skipped_not_infinite(self):
        schema = _schema(input_types={
            "TreeInput": {"fields": [
                {"name": "value", "type": "String", "wrapper": None},
                {"name": "parent", "type": "TreeInput", "wrapper": None},
            ]}
        })
        result = build_argument_value(schema, "TreeInput", None)
        assert result == {"value": "sample"}
        assert "parent" not in result

    def test_input_object_depth_capped(self):
        # A -> B -> C -> D chain; MAX_INPUT_DEPTH=3 should truncate before D.
        schema = _schema(input_types={
            "A": {"fields": [{"name": "b", "type": "B", "wrapper": None}]},
            "B": {"fields": [{"name": "c", "type": "C", "wrapper": None}]},
            "C": {"fields": [{"name": "d", "type": "D", "wrapper": None}]},
            "D": {"fields": [{"name": "leaf", "type": "String", "wrapper": None}]},
        })
        result = build_argument_value(schema, "A", None)
        # Should not raise / hang, and should bottom out to an empty dict at the cap.
        assert isinstance(result, dict)


# ── build_selection_set ────────────────────────────────────────────────────────

class TestBuildSelectionSet:
    def test_unknown_type_falls_back_to_typename(self):
        schema = _schema()
        assert build_selection_set(schema, "Nonexistent") == "{ __typename }"

    def test_object_with_scalar_fields(self):
        schema = _schema(object_types={
            "User": {"kind": "OBJECT", "fields": [
                {"name": "id", "type": "ID", "wrapper": "NON_NULL", "arg_count": 0},
                {"name": "name", "type": "String", "wrapper": None, "arg_count": 0},
            ]}
        })
        result = build_selection_set(schema, "User")
        assert result == "{ id name }"

    def test_fields_requiring_args_are_skipped(self):
        schema = _schema(object_types={
            "User": {"kind": "OBJECT", "fields": [
                {"name": "id", "type": "ID", "wrapper": "NON_NULL", "arg_count": 0},
                {"name": "posts", "type": "Post", "wrapper": "LIST", "arg_count": 1},
            ]}
        })
        result = build_selection_set(schema, "User")
        assert "posts" not in result
        assert result == "{ id }"

    def test_no_fields_falls_back_to_typename(self):
        schema = _schema(object_types={"Empty": {"kind": "OBJECT", "fields": []}})
        assert build_selection_set(schema, "Empty") == "{ __typename }"

    def test_nested_object_recurses(self):
        schema = _schema(object_types={
            "User": {"kind": "OBJECT", "fields": [
                {"name": "profile", "type": "Profile", "wrapper": None, "arg_count": 0},
            ]},
            "Profile": {"kind": "OBJECT", "fields": [
                {"name": "bio", "type": "String", "wrapper": None, "arg_count": 0},
            ]},
        })
        result = build_selection_set(schema, "User")
        assert result == "{ profile { bio } }"

    def test_recursion_depth_capped(self):
        # Self-referential object type — must not recurse forever.
        schema = _schema(object_types={
            "Node": {"kind": "OBJECT", "fields": [
                {"name": "child", "type": "Node", "wrapper": None, "arg_count": 0},
            ]},
        })
        result = build_selection_set(schema, "Node")
        # Depth-capped at MAX_SELECTION_DEPTH=2 — should terminate with __typename somewhere.
        assert "__typename" in result

    def test_field_count_capped(self):
        fields = [
            {"name": f"f{i}", "type": "String", "wrapper": None, "arg_count": 0}
            for i in range(20)
        ]
        schema = _schema(object_types={"Big": {"kind": "OBJECT", "fields": fields}})
        result = build_selection_set(schema, "Big")
        assert result.count("f") <= 16  # 15 fields + within "f" chars tolerance; sanity check below
        field_names_used = [f"f{i}" for i in range(20) if f"f{i}" in result]
        assert len(field_names_used) == 15

    def test_union_type_uses_first_possible_type(self):
        schema = _schema(
            union_types={"SearchResult": {"possible_types": ["User", "Post"]}},
            object_types={
                "User": {"kind": "OBJECT", "fields": [
                    {"name": "id", "type": "ID", "wrapper": None, "arg_count": 0},
                ]},
                "Post": {"kind": "OBJECT", "fields": [
                    {"name": "title", "type": "String", "wrapper": None, "arg_count": 0},
                ]},
            },
        )
        result = build_selection_set(schema, "SearchResult")
        assert result == "{ ... on User { id } }"

    def test_union_with_no_possible_types_falls_back(self):
        schema = _schema(union_types={"Empty": {"possible_types": []}})
        assert build_selection_set(schema, "Empty") == "{ __typename }"

    def test_interface_type_treated_like_object(self):
        schema = _schema(object_types={
            "Node": {"kind": "INTERFACE", "fields": [
                {"name": "id", "type": "ID", "wrapper": None, "arg_count": 0},
            ]}
        })
        assert build_selection_set(schema, "Node") == "{ id }"


# ── build_operation ────────────────────────────────────────────────────────────

class TestBuildOperation:
    def _full_schema(self) -> dict:
        return _schema(
            queries={
                "user": {
                    "args": [{"name": "id", "type": "ID", "wrapper": "NON_NULL"}],
                    "return_type": "User",
                },
            },
            mutations={
                "createUser": {
                    "args": [{"name": "input", "type": "CreateUserInput", "wrapper": "NON_NULL"}],
                    "return_type": "User",
                },
            },
            input_types={
                "CreateUserInput": {"fields": [
                    {"name": "email", "type": "String", "wrapper": "NON_NULL"},
                    {"name": "role", "type": "Role", "wrapper": None},
                ]},
            },
            object_types={
                "User": {"kind": "OBJECT", "fields": [
                    {"name": "id", "type": "ID", "wrapper": "NON_NULL", "arg_count": 0},
                    {"name": "posts", "type": "Post", "wrapper": "LIST", "arg_count": 1},
                ]},
                "Post": {"kind": "OBJECT", "fields": [
                    {"name": "title", "type": "String", "wrapper": None, "arg_count": 0},
                ]},
            },
            enum_types={"Role": {"values": ["ADMIN", "USER"]}},
        )

    def test_query_operation_shape(self):
        result = build_operation(self._full_schema(), "query", "user")
        assert result["operation_name"] == "User"
        assert "query User($var0: ID!)" in result["query"]
        assert "user(id: $var0)" in result["query"]
        assert result["variables"] == {"var0": "1"}

    def test_mutation_operation_shape(self):
        result = build_operation(self._full_schema(), "mutation", "createUser")
        assert "mutation CreateUser($var0: CreateUserInput!)" in result["query"]
        assert result["variables"]["var0"]["email"] == "sample"
        assert result["variables"]["var0"]["role"] == "ADMIN"

    def test_query_braces_are_balanced(self):
        result = build_operation(self._full_schema(), "query", "user")
        assert result["query"].count("{") == result["query"].count("}")

    def test_mutation_braces_are_balanced(self):
        result = build_operation(self._full_schema(), "mutation", "createUser")
        assert result["query"].count("{") == result["query"].count("}")

    def test_var_declarations_match_usage(self):
        result = build_operation(self._full_schema(), "query", "user")
        declared = set(re.findall(r"\$var\d+", result["query"].split(")", 1)[0]))
        used_vars = set(result["variables"].keys())
        assert {d.lstrip("$") for d in declared} == used_vars

    def test_unknown_operation_kind_raises(self):
        with pytest.raises(ValueError):
            build_operation(self._full_schema(), "subscription", "user")

    def test_unknown_field_raises(self):
        with pytest.raises(ValueError):
            build_operation(self._full_schema(), "query", "doesNotExist")

    def test_operation_with_no_args_omits_declaration_parens(self):
        schema = _schema(queries={"ping": {"args": [], "return_type": "String"}})
        result = build_operation(schema, "query", "ping")
        assert "query Ping {" in result["query"]
        assert result["variables"] == {}

"""Unit tests for BusinessLogicAgent helpers."""

from __future__ import annotations

import json

import pytest

from dast.agents.business_logic_agent import (
    _coerce_probe_value,
    _inject_into_body,
    _inject_into_graphql_variables,
)


class TestCoerceProbeValue:
    def test_negative_int(self):
        assert _coerce_probe_value("-1") == -1

    def test_zero(self):
        assert _coerce_probe_value("0") == 0

    def test_float(self):
        assert _coerce_probe_value("-0.01") == pytest.approx(-0.01)

    def test_true(self):
        assert _coerce_probe_value("true") is True

    def test_false(self):
        assert _coerce_probe_value("false") is False

    def test_null(self):
        assert _coerce_probe_value("null") is None

    def test_string_passthrough(self):
        assert _coerce_probe_value("admin") == "admin"

    def test_large_number(self):
        assert _coerce_probe_value("99999999") == 99999999


class TestInjectIntoBody:
    def test_json_existing_field(self):
        body = json.dumps({"amount": 100, "currency": "USD"})
        result = _inject_into_body(body, "amount", "-1", "application/json")
        data = json.loads(result)
        assert data["amount"] == -1
        assert data["currency"] == "USD"

    def test_json_new_field_mass_assignment(self):
        body = json.dumps({"name": "test"})
        result = _inject_into_body(body, "isAdmin", "true", "application/json")
        data = json.loads(result)
        assert data["isAdmin"] is True

    def test_json_numeric_string(self):
        body = json.dumps({"quantity": 5})
        result = _inject_into_body(body, "quantity", "99999999", "application/json")
        data = json.loads(result)
        assert data["quantity"] == 99999999

    def test_form_existing_field(self):
        body = "price=50&item=widget"
        result = _inject_into_body(body, "price", "-1", "application/x-www-form-urlencoded")
        assert "price=-1" in result
        assert "item=widget" in result

    def test_form_new_field(self):
        body = "action=purchase"
        result = _inject_into_body(body, "role", "admin", "application/x-www-form-urlencoded")
        assert "role=admin" in result

    def test_unknown_content_type_with_json_body(self):
        body = json.dumps({"status": "pending"})
        result = _inject_into_body(body, "status", "approved", "")
        data = json.loads(result)
        assert data["status"] == "approved"

    def test_non_json_non_form_returns_none(self):
        result = _inject_into_body("binary_content", "field", "value", "image/png")
        assert result is None

    def test_empty_body_json(self):
        result = _inject_into_body("", "role", "admin", "application/json")
        data = json.loads(result)
        assert data["role"] == "admin"


class TestInjectIntoGraphqlVariables:
    def test_simple_variable(self):
        body = json.dumps({
            "query": "mutation { updateOrder($input: OrderInput!) }",
            "variables": {"orderId": 1, "amount": 100}
        })
        result = _inject_into_graphql_variables(body, "amount", "-50")
        data = json.loads(result)
        assert data["variables"]["amount"] == -50

    def test_dotted_path(self):
        body = json.dumps({
            "query": "mutation { createOrder($input: OrderInput!) }",
            "variables": {"input": {"price": 99, "qty": 1}}
        })
        result = _inject_into_graphql_variables(body, "input.price", "-1")
        data = json.loads(result)
        assert data["variables"]["input"]["price"] == -1

    def test_new_field_mass_assignment(self):
        body = json.dumps({
            "query": "mutation { updateProfile($input: ProfileInput!) }",
            "variables": {"name": "Alice"}
        })
        result = _inject_into_graphql_variables(body, "isAdmin", "true")
        data = json.loads(result)
        assert data["variables"]["isAdmin"] is True

    def test_non_graphql_body_returns_none(self):
        body = json.dumps({"amount": 100})
        result = _inject_into_graphql_variables(body, "amount", "-1")
        assert result is None

    def test_invalid_json_returns_none(self):
        result = _inject_into_graphql_variables("not-json", "field", "value")
        assert result is None


class TestAgentRegistration:
    def test_agent_registered_with_coordinator(self):
        import dast.agents  # noqa: F401 — triggers registration
        from dast.ai.coordinator import Coordinator
        assert "business_logic" in Coordinator.registered_types()

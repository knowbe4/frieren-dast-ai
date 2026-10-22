"""Unit tests for AI payload generation.

Locks in: malformed items from the model are skipped instead of aborting the
whole batch, and a non-list ``payloads`` value yields no payloads.
"""

from __future__ import annotations

from typing import Any

import pytest

from dast.ai import payload_generator
from dast.models import Endpoint, EndpointParameter


def _endpoint() -> Endpoint:
    return Endpoint(
        url="http://app.example.com/item",
        method="GET",
        parameters=[EndpointParameter(name="id", location="query", value="1")],
    )


def _stub_model(monkeypatch: pytest.MonkeyPatch, result: Any) -> None:
    monkeypatch.setattr(payload_generator.bedrock_client, "invoke_json", lambda **_: result)


def test_malformed_items_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_model(monkeypatch, {"payloads": ["stray text", {"value": "'", "attack_type": "sqli"}]})

    payloads = payload_generator.generate_payloads(_endpoint(), ["sqli"])

    assert [p.value for p in payloads] == ["'"]
    assert payloads[0].attack_type == "sqli"


def test_non_list_payloads_yield_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_model(monkeypatch, {"payloads": "not a list"})

    assert payload_generator.generate_payloads(_endpoint(), ["sqli"]) == []

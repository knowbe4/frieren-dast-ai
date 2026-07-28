"""
Unit tests for dast.graphql.variable_fuzzer.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dast.graphql.variable_fuzzer import (
    ExtractedVariable,
    FuzzAttempt,
    build_fuzz_matrix,
    coerce_payload,
    extract_variables,
    run_fuzz_job,
)
from dast.hackerone import payload_safety
from dast.payloads.loader import get_all_payloads


class TestGraphqlPayloadsAreNeverDestructive:
    """
    Safety-policy regression: dast/payloads/graphql.yaml must never contain a
    destructive payload (SQL writes, OS-destructive commands, etc.) — this
    fuzzer sends every payload here for real, against a live target, with no
    per-payload review step (unlike the HackerOne validator's report-driven
    flow). A destructive string ('; DROP TABLE ...) briefly existed in this
    file and must never reappear.
    """

    def test_no_payload_classifies_as_destructive(self):
        payloads = get_all_payloads("graphql")
        assert payloads, "graphql.yaml produced no payloads — check the file loaded correctly"
        for payload in payloads:
            verdict = payload_safety.classify(payload, "sqli")
            assert not verdict.is_destructive, f"destructive payload found in graphql.yaml: {payload!r} ({verdict.reason})"


# ── extract_variables ────────────────────────────────────────────────────────

class TestExtractVariables:
    def test_extracts_string_int_bool_null_list_object(self):
        body = json.dumps({
            "query": "query Q($a: String, $b: Int) { x }",
            "variables": {
                "a": "hello",
                "b": 5,
                "c": True,
                "d": None,
                "e": [1, 2],
                "f": {"nested": 1},
            },
        })
        result = extract_variables(body)
        by_name = {v.name: v for v in result}
        assert by_name["a"].inferred_type == "string"
        assert by_name["b"].inferred_type == "int"
        assert by_name["c"].inferred_type == "bool"
        assert by_name["d"].inferred_type == "null"
        assert by_name["e"].inferred_type == "list"
        assert by_name["f"].inferred_type == "object"

    def test_float_type_inferred(self):
        body = json.dumps({"variables": {"price": 1.5}})
        result = extract_variables(body)
        assert result[0].inferred_type == "float"

    def test_no_variables_key_raises(self):
        body = json.dumps({"query": "query { x }"})
        with pytest.raises(ValueError):
            extract_variables(body)

    def test_empty_variables_object_raises(self):
        body = json.dumps({"query": "query { x }", "variables": {}})
        with pytest.raises(ValueError):
            extract_variables(body)

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError):
            extract_variables("not json")

    def test_non_object_body_raises(self):
        with pytest.raises(ValueError):
            extract_variables("[1, 2, 3]")


# ── coerce_payload ───────────────────────────────────────────────────────────

class TestCoercePayload:
    def test_null_literal_becomes_none(self):
        assert coerce_payload("null", "string") is None

    def test_empty_object_literal_parsed(self):
        assert coerce_payload("{}", "object") == {}

    def test_empty_array_literal_parsed(self):
        assert coerce_payload("[]", "list") == []

    def test_bool_variable_gets_int_confusion(self):
        assert coerce_payload("0", "bool") == 0
        assert coerce_payload("1", "bool") == 1

    def test_bool_variable_non_numeric_payload_stays_string(self):
        assert coerce_payload("' OR 1=1--", "bool") == "' OR 1=1--"

    def test_int_variable_numeric_payload_coerced(self):
        assert coerce_payload("-1", "int") == -1

    def test_int_variable_float_payload_coerced(self):
        assert coerce_payload("1.5", "float") == 1.5

    def test_int_variable_non_numeric_payload_stays_string(self):
        assert coerce_payload("' OR 1=1--", "int") == "' OR 1=1--"

    def test_list_variable_wraps_payload(self):
        assert coerce_payload("x", "list") == ["x"]

    def test_object_variable_json_payload_parsed(self):
        assert coerce_payload('{"$ne": null}', "object") == {"$ne": None}

    def test_object_variable_non_json_payload_stays_string(self):
        assert coerce_payload("not-json", "object") == "not-json"

    def test_string_variable_payload_passthrough(self):
        assert coerce_payload("<script>alert(1)</script>", "string") == "<script>alert(1)</script>"


# ── build_fuzz_matrix ────────────────────────────────────────────────────────

class TestBuildFuzzMatrix:
    def test_cross_product_size(self):
        variables = [
            ExtractedVariable("a", "1", "int"),
            ExtractedVariable("b", "x", "string"),
        ]
        payloads = ["p1", "p2", "p3"]
        attempts = build_fuzz_matrix(variables, payloads)
        assert len(attempts) == 6

    def test_each_variable_paired_with_every_payload(self):
        variables = [ExtractedVariable("a", "1", "int")]
        payloads = ["p1", "p2"]
        attempts = build_fuzz_matrix(variables, payloads)
        assert {a.payload for a in attempts} == {"p1", "p2"}
        assert all(a.variable == "a" for a in attempts)

    def test_coerced_value_set_per_attempt(self):
        variables = [ExtractedVariable("flag", True, "bool")]
        attempts = build_fuzz_matrix(variables, ["1"])
        assert attempts[0].coerced_value == 1


# ── run_fuzz_job ─────────────────────────────────────────────────────────────

def _make_response(status_code=200, body="{}"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = body.encode("utf-8")
    resp.text = body
    return resp


class TestRunFuzzJob:
    def _job(self):
        return {"status": "queued", "progress": None, "results": [], "cancel": False}

    @pytest.mark.asyncio
    async def test_records_one_result_per_attempt(self):
        job = self._job()
        attempts = [
            FuzzAttempt(variable="id", payload="p1", coerced_value="p1"),
            FuzzAttempt(variable="id", payload="p2", coerced_value="p2"),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200, '{"data": {}}'))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
            await run_fuzz_job(
                job, "POST", "https://example.com/graphql", {},
                json.dumps({"query": "query{x}", "variables": {"id": "1"}}),
                attempts, baseline_length=10, baseline_had_errors=False,
            )

        assert job["status"] == "done"
        assert len(job["results"]) == 2
        assert job["progress"]["done"] == 2

    @pytest.mark.asyncio
    async def test_5xx_status_is_a_hit(self):
        job = self._job()
        attempts = [FuzzAttempt(variable="id", payload="p1", coerced_value="p1")]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(500, "internal error"))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
            await run_fuzz_job(
                job, "POST", "https://example.com/graphql", {},
                json.dumps({"query": "query{x}", "variables": {"id": "1"}}),
                attempts, baseline_length=10, baseline_had_errors=False,
            )

        assert job["results"][0]["hit"] is True

    @pytest.mark.asyncio
    async def test_new_errors_not_in_baseline_is_a_hit(self):
        job = self._job()
        attempts = [FuzzAttempt(variable="id", payload="p1", coerced_value="p1")]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200, '{"errors": [{"message": "boom"}]}'))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
            await run_fuzz_job(
                job, "POST", "https://example.com/graphql", {},
                json.dumps({"query": "query{x}", "variables": {"id": "1"}}),
                attempts, baseline_length=10, baseline_had_errors=False,
            )

        assert job["results"][0]["hit"] is True
        assert job["results"][0]["errors_present"] is True

    @pytest.mark.asyncio
    async def test_errors_present_in_baseline_too_is_not_a_hit(self):
        job = self._job()
        attempts = [FuzzAttempt(variable="id", payload="p1", coerced_value="p1")]
        body = '{"errors": [{"message": "boom"}]}'
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200, body))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        # baseline_length matches the response length so only the
        # errors-present rule is under test, not the length-delta rule.
        with patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
            await run_fuzz_job(
                job, "POST", "https://example.com/graphql", {},
                json.dumps({"query": "query{x}", "variables": {"id": "1"}}),
                attempts, baseline_length=len(body), baseline_had_errors=True,
            )

        assert job["results"][0]["hit"] is False

    @pytest.mark.asyncio
    async def test_length_delta_beyond_threshold_is_a_hit(self):
        job = self._job()
        attempts = [FuzzAttempt(variable="id", payload="p1", coerced_value="p1")]
        big_body = "{" + "x" * 500 + "}"
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200, big_body))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
            await run_fuzz_job(
                job, "POST", "https://example.com/graphql", {},
                json.dumps({"query": "query{x}", "variables": {"id": "1"}}),
                attempts, baseline_length=10, baseline_had_errors=False,
            )

        assert job["results"][0]["hit"] is True

    @pytest.mark.asyncio
    async def test_cancel_stops_the_loop_early(self):
        job = self._job()
        job["cancel"] = True
        attempts = [
            FuzzAttempt(variable="id", payload="p1", coerced_value="p1"),
            FuzzAttempt(variable="id", payload="p2", coerced_value="p2"),
        ]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200, "{}"))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
            await run_fuzz_job(
                job, "POST", "https://example.com/graphql", {},
                json.dumps({"query": "query{x}", "variables": {"id": "1"}}),
                attempts, baseline_length=10, baseline_had_errors=False,
            )

        assert job["status"] == "stopped"
        assert len(job["results"]) == 0

    @pytest.mark.asyncio
    async def test_invalid_body_template_sets_error_status(self):
        job = self._job()
        await run_fuzz_job(
            job, "POST", "https://example.com/graphql", {},
            "not json", [], baseline_length=0, baseline_had_errors=False,
        )
        assert job["status"] == "error"

    @pytest.mark.asyncio
    async def test_request_exception_does_not_crash_the_job(self):
        job = self._job()
        attempts = [FuzzAttempt(variable="id", payload="p1", coerced_value="p1")]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=RuntimeError("connection failed"))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
            await run_fuzz_job(
                job, "POST", "https://example.com/graphql", {},
                json.dumps({"query": "query{x}", "variables": {"id": "1"}}),
                attempts, baseline_length=10, baseline_had_errors=False,
            )

        assert job["status"] == "done"
        assert job["results"][0]["status_code"] == 0

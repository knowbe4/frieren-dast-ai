"""
Unit tests for dast.importers.dast_importer — pre-processing, URL resolution,
payload stripping, and finding-dict builders. parse_findings (LLM-backed) is
tested with a mocked bedrock_client, following the fake-client pattern used
elsewhere in the suite.
"""

from __future__ import annotations

import json

import pytest

from dast.ai import bedrock_client
from dast.importers.dast_importer import (
    NormalisedFinding,
    _format_schemas_for_prompt,
    _normalise_severity,
    _preprocess,
    _preprocess_markdown,
    _preprocess_orchestrator_json,
    _strip_payload_from_path,
    build_request_body,
    build_request_headers,
    build_stub_finding,
    parse_findings,
    resolve_url,
)


def _nf(**kw):
    defaults = dict(
        title="Imported XSS",
        severity="high",
        cwe="CWE-79",
        attack_type="xss",
        url="",
        path="",
        method="GET",
        content_type="",
        request_body="",
        parameter="q",
        payload="<script>alert(1)</script>",
        evidence="reflected in response",
        host_hint="",
    )
    defaults.update(kw)
    return NormalisedFinding(**defaults)


# ── _normalise_severity ─────────────────────────────────────────────────────

class TestNormaliseSeverity:
    @pytest.mark.parametrize("raw,expected", [
        ("critical", "critical"), ("HIGH", "high"), ("Medium", "medium"),
        ("low", "low"), ("info", "info"),
        ("informational", "info"), ("Note", "info"),
        ("unknown-garbage", "medium"), ("", "medium"),
    ])
    def test_mapping(self, raw, expected):
        assert _normalise_severity(raw) == expected


# ── _strip_payload_from_path ────────────────────────────────────────────────

class TestStripPayloadFromPath:
    def test_clean_path_unchanged(self):
        assert _strip_payload_from_path("/api/items/123") == "/api/items/123"

    def test_nosql_payload_segment_stripped(self):
        result = _strip_payload_from_path("/api/items/000000')]}},$where:'1==1'}//details")
        assert result == "/api/items"

    def test_sqli_payload_segment_stripped(self):
        result = _strip_payload_from_path("/users/1' or '1'='1/profile")
        assert result == "/users"

    def test_xss_payload_segment_stripped(self):
        result = _strip_payload_from_path("/search/<script>alert(1)</script>")
        assert result == "/search"

    def test_path_traversal_marker_not_stripped_since_it_needs_a_trailing_slash(self):
        # The "../" marker (with trailing slash) can never match inside a single
        # path segment, since the function first splits the path on "/" — so
        # traversal sequences pass through untouched. This documents that gap
        # rather than asserting behavior the function doesn't actually have.
        result = _strip_payload_from_path("/files/../../etc/passwd")
        assert result == "/files/../../etc/passwd"

    def test_empty_path_returns_root(self):
        assert _strip_payload_from_path("") == "/"

    def test_root_path_returns_root(self):
        assert _strip_payload_from_path("/") == "/"


# ── resolve_url ──────────────────────────────────────────────────────────────

class TestResolveUrl:
    def test_full_url_used_as_is_when_no_base(self):
        nf = _nf(url="https://api.example.com/users/1")
        assert resolve_url(nf, base_url="") == "https://api.example.com/users/1"

    def test_full_url_rewritten_to_base_host_when_different(self):
        nf = _nf(url="https://other.example.com/users/1")
        result = resolve_url(nf, base_url="https://api.example.com")
        assert result == "https://api.example.com/users/1"

    def test_full_url_strips_embedded_payload_segment(self):
        nf = _nf(url="https://api.example.com/items/000000')]}},$where:'1==1'}//details")
        result = resolve_url(nf, base_url="")
        assert result == "https://api.example.com/items"

    def test_path_only_combined_with_base_url(self):
        nf = _nf(path="/api/users", url="")
        assert resolve_url(nf, base_url="https://api.example.com") == "https://api.example.com/api/users"

    def test_path_without_leading_slash_normalised(self):
        nf = _nf(path="api/users", url="")
        assert resolve_url(nf, base_url="https://api.example.com") == "https://api.example.com/api/users"

    def test_no_base_url_falls_back_to_host_hint(self):
        nf = _nf(path="/api/users", url="", host_hint="fallback.example.com")
        assert resolve_url(nf, base_url="") == "https://fallback.example.com/api/users"

    def test_no_base_no_host_hint_returns_empty(self):
        nf = _nf(path="/api/users", url="", host_hint="")
        assert resolve_url(nf, base_url="") == ""

    def test_no_path_returns_empty(self):
        nf = _nf(path="", url="")
        assert resolve_url(nf, base_url="https://api.example.com") == ""

    def test_host_hint_with_pipe_is_rejected(self):
        # host_hint containing "|" looks like a list of candidates, not a single host.
        nf = _nf(path="/api/users", url="", host_hint="a.com|b.com")
        assert resolve_url(nf, base_url="") == ""


# ── build_stub_finding / build_request_body / build_request_headers ────────

class TestBuildStubFinding:
    def test_stub_has_expected_shape(self):
        nf = _nf()
        stub = build_stub_finding(nf)
        assert stub["title"] == "Imported XSS"
        assert stub["confirmed"] is False
        assert stub["validated_by"] == ["imported"]
        assert "[Imported from external report]" in stub["evidence"]


class TestBuildRequestBody:
    def test_empty_body_returns_none(self):
        assert build_request_body(_nf(request_body="")) is None

    def test_valid_json_body_encoded(self):
        nf = _nf(request_body='{"user": "test"}', content_type="application/json")
        assert build_request_body(nf) == b'{"user": "test"}'

    def test_invalid_json_still_encoded_as_bytes(self):
        nf = _nf(request_body="{not valid json", content_type="application/json")
        result = build_request_body(nf)
        assert result == b"{not valid json"

    def test_form_body_encoded(self):
        nf = _nf(request_body="user=test&pass=123", content_type="application/x-www-form-urlencoded")
        assert build_request_body(nf) == b"user=test&pass=123"


class TestBuildRequestHeaders:
    def test_explicit_content_type_used(self):
        nf = _nf(content_type="application/json")
        assert build_request_headers(nf) == {"content-type": "application/json"}

    def test_json_body_infers_content_type(self):
        nf = _nf(content_type="", request_body='{"a": 1}')
        assert build_request_headers(nf) == {"content-type": "application/json"}

    def test_form_body_infers_content_type(self):
        nf = _nf(content_type="", request_body="a=1&b=2")
        assert build_request_headers(nf) == {"content-type": "application/x-www-form-urlencoded"}

    def test_no_body_no_content_type(self):
        nf = _nf(content_type="", request_body="")
        assert build_request_headers(nf) == {}


# ── _preprocess / _preprocess_orchestrator_json ─────────────────────────────

class TestPreprocessOrchestratorJson:
    def test_list_input_wrapped_as_findings(self):
        data = [{"title": "SQLi", "status": "confirmed", "severity": "high"}]
        result = _preprocess_orchestrator_json(data)
        parsed = json.loads(result)
        assert parsed["findings"][0]["title"] == "SQLi"

    def test_confirmed_findings_kept_others_dropped(self):
        data = {
            "findings": [
                {"title": "Confirmed one", "status": "confirmed"},
                {"title": "Rejected one", "status": "rejected"},
            ]
        }
        result = _preprocess_orchestrator_json(data)
        parsed = json.loads(result)
        titles = [f["title"] for f in parsed["findings"]]
        assert titles == ["Confirmed one"]

    def test_no_confirmed_falls_back_to_non_rejected(self):
        data = {
            "findings": [
                {"title": "Unclear one", "status": "triage_only"},
                {"title": "False positive", "status": "false_positive"},
            ]
        }
        result = _preprocess_orchestrator_json(data)
        parsed = json.loads(result)
        titles = [f["title"] for f in parsed["findings"]]
        assert titles == ["Unclear one"]

    def test_context_header_included_when_present(self):
        data = {
            "project": "my-project",
            "service_urls": ["https://api.example.com"],
            "findings": [{"title": "X", "status": "confirmed"}],
        }
        result = _preprocess_orchestrator_json(data)
        assert "Project: my-project" in result
        assert "https://api.example.com" in result

    def test_non_dict_non_list_returns_json_dump(self):
        result = _preprocess_orchestrator_json("not a dict")
        assert result == '"not a dict"'


class TestPreprocess:
    def test_json_input_routed_to_orchestrator_preprocessor(self):
        text = json.dumps({"findings": [{"title": "X", "status": "confirmed"}]})
        result = _preprocess(text)
        assert "findings" in result

    def test_invalid_json_falls_through_to_plain_text(self):
        text = "{not valid json at all"
        assert _preprocess(text) == text

    def test_markdown_routed_to_markdown_preprocessor(self):
        text = "# Report\n\n## Confirmed Vulnerabilities\n\n#### 1. XSS in search\nDetails here."
        result = _preprocess(text)
        assert "XSS in search" in result

    def test_plain_text_returned_as_is(self):
        text = "Just a plain description of a bug, no markdown headers."
        assert _preprocess(text) == text


class TestPreprocessMarkdown:
    def test_extracts_confirmed_vulnerabilities_section(self):
        text = (
            "# Report\n\n"
            "## Executive Summary\nSome unrelated summary content.\n\n"
            "## Confirmed Vulnerabilities\n\n"
            "#### 1. SQL Injection\n**Severity:** high\n**Description:** test\n"
        )
        result = _preprocess_markdown(text)
        assert "SQL Injection" in result
        assert "Executive Summary" not in result

    def test_service_urls_section_preserved(self):
        text = (
            "### Service URLs\napi.example.com\n\n"
            "## Findings\n\n#### 1. Something\nDetails.\n"
        )
        result = _preprocess_markdown(text)
        assert "Service URLs" in result

    def test_drops_red_team_rejected_and_metadata_sections(self):
        # Findings the upstream pipeline already ruled out (Rejected by Red Team /
        # Triage) and report metadata (Merge Requests, Scan Cost) must never be
        # imported — re-importing them replays pre-cleared false positives and
        # leaks internal report details (hostnames, source paths) that the operator
        # already decided are not vulnerabilities.
        text = (
            "## Confirmed Vulnerabilities\n\n"
            "#### 1. Real XSS\n**Severity:** high\nA genuine finding.\n\n"
            "## Needs Manual Review (Not Validated)\n\n"
            "#### 1. Maybe an issue\nWorth a human look.\n\n"
            "## Rejected by Red Team (Opus)\n\n"
            "#### 1. Cleared Open Redirect\n"
            "Internal detail: src/utils/resolveApiUrl.ts on gitlab.internal.example.com\n\n"
            "## Merge Requests Analyzed\n\n- !3 secret-branch-name\n\n"
            "## Scan Cost\n\n| Input tokens | 144528 |\n"
        )
        result = _preprocess_markdown(text)
        # Real + needs-review findings survive.
        assert "Real XSS" in result
        assert "Maybe an issue" in result
        # Rejected findings and metadata are gone.
        assert "Cleared Open Redirect" not in result
        assert "resolveApiUrl" not in result
        assert "secret-branch-name" not in result
        assert "144528" not in result


# ── _format_schemas_for_prompt ───────────────────────────────────────────────

class TestFormatSchemasForPrompt:
    def test_mutations_and_queries_formatted(self):
        schemas = {
            "https://api.example.com/graphql": {
                "introspected": True,
                "mutations": {"createUser": {"args": [{"name": "input", "type": "CreateUserInput"}]}},
                "queries": {"getUser": {"args": [{"name": "id", "type": "ID"}]}},
                "input_types": {
                    "CreateUserInput": {"fields": [{"name": "email", "type": "String"}]},
                },
            }
        }
        result = _format_schemas_for_prompt(schemas)
        assert "createUser" in result
        assert "email: String" in result
        assert "getUser" in result

    def test_output_truncated_when_over_cap(self, monkeypatch):
        import dast.importers.dast_importer as mod
        monkeypatch.setattr(mod, "_MAX_SCHEMA_CHARS", 50)
        schemas = {
            "https://api.example.com/graphql": {
                "introspected": True,
                "mutations": {f"mutation{i}": {"args": []} for i in range(20)},
            }
        }
        result = _format_schemas_for_prompt(schemas)
        assert result.endswith("(truncated)")
        assert len(result) <= 50 + len("\n... (truncated)")

    def test_uninstrospected_schema_is_skipped(self):
        schemas = {
            "https://api.example.com/graphql": {"introspected": False},
        }
        result = _format_schemas_for_prompt(schemas)
        assert result == ""


# ── parse_findings (LLM-backed) ─────────────────────────────────────────────

class TestParseFindings:
    def test_llm_findings_normalised(self, monkeypatch):
        monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
            "findings": [{
                "title": "Reflected XSS", "severity": "HIGH", "cwe": "CWE-79",
                "attack_type": "xss", "url": "https://example.com/search",
                "path": "", "method": "get", "content_type": "",
                "request_body": "", "parameter": "q", "payload": "<script>",
                "evidence": "reflected", "host_hint": "example.com",
            }]
        })
        result = parse_findings("some report text")
        assert len(result) == 1
        assert result[0].severity == "high"
        assert result[0].method == "GET"

    def test_llm_failure_returns_empty_list(self, monkeypatch):
        def _raise(*a, **k):
            raise RuntimeError("bedrock down")
        monkeypatch.setattr(bedrock_client, "invoke_json", _raise)
        assert parse_findings("some report text") == []

    def test_non_dict_findings_are_skipped(self, monkeypatch):
        monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {
            "findings": ["not-a-dict", {"title": "Valid one"}]
        })
        result = parse_findings("text")
        assert len(result) == 1
        assert result[0].title == "Valid one"

    def test_missing_findings_key_returns_empty_list(self, monkeypatch):
        monkeypatch.setattr(bedrock_client, "invoke_json", lambda *a, **k: {})
        assert parse_findings("text") == []

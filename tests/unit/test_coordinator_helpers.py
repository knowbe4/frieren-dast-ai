"""
Unit tests for coordinator helper functions — routing, param classification,
and auth-endpoint detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import pytest


@dataclass
class _FakeTarget:
    url: str = "https://example.com/api/users"
    method: str = "GET"
    headers: Dict = field(default_factory=dict)
    body: Optional[str] = None
    params: List = field(default_factory=list)


# ── _is_auth_endpoint ─────────────────────────────────────────────────────

class TestIsAuthEndpoint:
    def test_oidc_callback_is_auth(self):
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://app.example.com/oauth/callback") is True

    def test_saml_endpoint_is_auth(self):
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://app.example.com/saml/acs") is True

    def test_login_endpoint_is_auth(self):
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://app.example.com/auth/token") is True

    def test_regular_api_endpoint_is_not_auth(self):
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://app.example.com/api/users") is False

    def test_user_profile_is_not_auth(self):
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://app.example.com/api/me") is False

    def test_bare_root_on_hrd_host_is_auth(self):
        # Regression: an agent fired open_redirect payloads at the bare '/' of an
        # SSO/HRD host because path-only detection missed it. The hostname alone
        # (the 'hrd' label) must classify it as an auth endpoint.
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://hrd.test.example.com/") is True

    def test_login_subdomain_bare_root_is_auth(self):
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://login.example.com/") is True

    def test_sso_subdomain_is_auth(self):
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://sso.example.com/home") is True

    def test_auth_host_with_open_redirect_param_allowed(self):
        # Even on an auth host, an absolute-URL redirect param is worth testing.
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint(
            "https://login.example.com/?next=https://evil.example"
        ) is False

    def test_regular_host_bare_root_is_not_auth(self):
        from dast.ai.coordinator import _is_auth_endpoint
        assert _is_auth_endpoint("https://app.example.com/") is False


# ── _is_mfa_endpoint ──────────────────────────────────────────────────────

class TestIsMfaEndpoint:
    def test_otp_verify_is_mfa(self):
        from dast.ai.coordinator import _is_mfa_endpoint
        assert _is_mfa_endpoint("https://app.example.com/auth/otp/verify") is True

    def test_mfa_endpoint_is_mfa(self):
        from dast.ai.coordinator import _is_mfa_endpoint
        assert _is_mfa_endpoint("https://app.example.com/mfa/validate") is True

    def test_totp_endpoint_is_mfa(self):
        from dast.ai.coordinator import _is_mfa_endpoint
        assert _is_mfa_endpoint("https://app.example.com/2fa/totp") is True

    def test_regular_login_is_not_mfa(self):
        from dast.ai.coordinator import _is_mfa_endpoint
        assert _is_mfa_endpoint("https://app.example.com/api/login") is False

    def test_user_profile_is_not_mfa(self):
        from dast.ai.coordinator import _is_mfa_endpoint
        assert _is_mfa_endpoint("https://app.example.com/api/users/123") is False


# ── _params_are_all_auth_tokens ──────────────────────────────────────────

class TestParamsAreAllAuthTokens:
    def _target(self, param_names):
        return _FakeTarget(params=[{"name": n, "value": "x"} for n in param_names])

    def test_state_and_code_are_tokens(self):
        from dast.ai.coordinator import _params_are_all_auth_tokens
        assert _params_are_all_auth_tokens(self._target(["state", "code"])) is True

    def test_access_token_is_token(self):
        from dast.ai.coordinator import _params_are_all_auth_tokens
        assert _params_are_all_auth_tokens(self._target(["access_token"])) is True

    def test_id_param_is_not_a_token(self):
        from dast.ai.coordinator import _params_are_all_auth_tokens
        assert _params_are_all_auth_tokens(self._target(["id", "name"])) is False

    def test_mixed_token_and_regular_is_false(self):
        from dast.ai.coordinator import _params_are_all_auth_tokens
        assert _params_are_all_auth_tokens(self._target(["state", "user_id"])) is False

    def test_empty_params_is_false(self):
        from dast.ai.coordinator import _params_are_all_auth_tokens
        assert _params_are_all_auth_tokens(self._target([])) is False


# ── _classify_param ───────────────────────────────────────────────────────

class TestClassifyParam:
    def test_numeric_id(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("id", "42") == "numeric_id"
        assert _classify_param("user_id", "1234") == "numeric_id"

    def test_uuid_value(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("id", "550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_boolean_value(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("active", "true") == "boolean"
        assert _classify_param("enabled", "false") == "boolean"
        assert _classify_param("flag", "1") == "boolean"

    def test_empty_value(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("q", "") == "empty"
        assert _classify_param("q", "   ") == "empty"

    def test_jwt_value_is_token_not_path(self):
        from dast.ai.coordinator import _classify_param
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = _classify_param("token", jwt)
        assert result == "token"

    def test_long_opaque_token_is_token(self):
        from dast.ai.coordinator import _classify_param
        # 40-char alphanumeric string — looks like an API key
        assert _classify_param("key", "abcdefghijklmnopqrstuvwxyz1234567890abcd") == "token"

    def test_path_value(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("file", "/etc/passwd") == "path"
        assert _classify_param("path", "../config.yaml") == "path"

    def test_json_body(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("data", '{"key": "value"}') == "json"
        assert _classify_param("items", '[1, 2, 3]') == "json"

    def test_search_param_name(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("search", "hello world") == "search"
        assert _classify_param("q", "something") == "search"
        assert _classify_param("keyword", "test") == "search"

    def test_token_param_name(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("csrf_token", "abc123") == "token"
        assert _classify_param("nonce", "def456") == "token"

    def test_path_param_name(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("include", "header") == "path"
        assert _classify_param("template", "default") == "path"

    def test_generic_string_fallback(self):
        from dast.ai.coordinator import _classify_param
        assert _classify_param("color", "blue") == "string"
        assert _classify_param("message", "hello") == "string"


# ── payload_filter helpers ────────────────────────────────────────────────

class TestPayloadFilter:
    def _target(self, url="https://example.com/", headers=None, dc=None, hint=""):
        t = _FakeTarget(url=url, headers=headers or {})
        t.discovery_context = dc
        t.app_profile_hint = hint
        return t

    def test_ssti_disabled_without_template_signal(self):
        from dast.agents.payload_filter import _ssti_groups
        # No HTML content-type, no template keywords, no tech-stack hint
        target = self._target()
        target.body = None
        result = _ssti_groups(target, "api json endpoint")
        assert result == [], "SSTI should be disabled without template-rendering evidence"

    def test_ssti_enabled_with_jinja2_signal(self):
        from dast.agents.payload_filter import _ssti_groups
        target = self._target(hint="jinja2 python flask application")
        result = _ssti_groups(target, "jinja2 python flask application")
        assert result, "SSTI should be enabled when Jinja2 is detected"

    def test_jwt_disabled_without_bearer(self):
        from dast.agents.payload_filter import _jwt_groups
        target = self._target(headers={"content-type": "application/json"})
        result = _jwt_groups(target, "")
        assert result == [], "JWT probes should not fire without a Bearer token in headers"

    def test_jwt_enabled_with_bearer_header(self):
        from dast.agents.payload_filter import _jwt_groups
        target = self._target(headers={"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"})
        result = _jwt_groups(target, "bearer token detected")
        assert result, "JWT probes should fire when Authorization: Bearer is present"

    def test_lfi_adds_windows_on_iis_signal(self):
        from dast.agents.payload_filter import _lfi_groups
        target = self._target()
        result = _lfi_groups(target, "iis windows asp.net microsoft")
        assert "windows" in result, "Windows LFI payloads should be added for IIS targets"

    def test_lfi_adds_php_wrappers_on_php_signal(self):
        from dast.agents.payload_filter import _lfi_groups
        target = self._target()
        result = _lfi_groups(target, "php laravel application php-fpm")
        assert "wrappers" in result, "PHP wrapper payloads should be added for PHP targets"

    def test_sqli_adds_stacked_for_postgres(self):
        from dast.agents.payload_filter import _sqli_groups
        target = self._target()
        result = _sqli_groups(target, "postgresql postgres npgsql")
        assert "stacked" in result, "Stacked queries should be enabled for PostgreSQL"

    def test_sqli_no_stacked_for_mysql(self):
        from dast.agents.payload_filter import _sqli_groups
        target = self._target()
        result = _sqli_groups(target, "mysql innodb")
        assert "stacked" not in result, "Stacked queries should NOT be enabled for MySQL"

    def test_get_filtered_payloads_unknown_type_returns_empty(self):
        from dast.agents.payload_filter import get_filtered_payloads
        target = self._target()
        result = get_filtered_payloads("nonexistent_attack_type_xyz", target)
        assert result == [], "Unknown attack type must return empty list, not raise"

    def test_get_filtered_payloads_xss_returns_list(self):
        from dast.agents.payload_filter import get_filtered_payloads
        target = self._target(hint="react spa application html rendering")
        result = get_filtered_payloads("xss", target)
        assert isinstance(result, list)
        assert len(result) > 0


# ── csrf_agent helpers ────────────────────────────────────────────────────

class TestCsrfAgentHelpers:
    def test_responses_similar_both_2xx_same_size(self):
        from dast.agents.csrf_agent import _responses_similar
        assert _responses_similar(200, 1000, 200, 1000) is True

    def test_responses_similar_within_30_percent(self):
        from dast.agents.csrf_agent import _responses_similar
        assert _responses_similar(200, 1000, 200, 900) is True
        assert _responses_similar(200, 1000, 201, 1050) is True

    def test_responses_different_probe_is_4xx(self):
        from dast.agents.csrf_agent import _responses_similar
        assert _responses_similar(200, 1000, 403, 100) is False

    def test_responses_different_baseline_not_2xx(self):
        from dast.agents.csrf_agent import _responses_similar
        assert _responses_similar(401, 100, 200, 100) is False

    def test_responses_different_size(self):
        from dast.agents.csrf_agent import _responses_similar
        assert _responses_similar(200, 1000, 200, 100) is False

    def test_baseline_zero_len_probe_also_zero(self):
        from dast.agents.csrf_agent import _responses_similar
        assert _responses_similar(200, 0, 200, 0) is True

    def test_baseline_zero_len_probe_nonzero(self):
        from dast.agents.csrf_agent import _responses_similar
        assert _responses_similar(200, 0, 200, 500) is False

    def test_remove_param_from_json_body(self):
        from dast.agents.csrf_agent import _remove_param_from_body
        result = _remove_param_from_body('{"_token": "abc", "name": "alice"}', "_token")
        import json
        parsed = json.loads(result)
        assert "_token" not in parsed
        assert parsed["name"] == "alice"

    def test_remove_param_from_form_body(self):
        from dast.agents.csrf_agent import _remove_param_from_body
        result = _remove_param_from_body("_token=abc&name=alice", "_token")
        assert "_token" not in result
        assert "name=alice" in result

    def test_remove_param_not_present_still_has_other_params(self):
        from dast.agents.csrf_agent import _remove_param_from_body
        import json
        # When param exists, it is removed cleanly
        result = _remove_param_from_body('{"_token": "abc", "name": "alice"}', "_token")
        assert json.loads(result).get("name") == "alice"
        assert "_token" not in json.loads(result)

    def test_replace_param_in_json_body(self):
        from dast.agents.csrf_agent import _replace_param_in_body
        result = _replace_param_in_body('{"_token": "real", "name": "alice"}', "_token", "tampered")
        import json
        assert json.loads(result)["_token"] == "tampered"

    def test_replace_param_in_form_body(self):
        from dast.agents.csrf_agent import _replace_param_in_body
        result = _replace_param_in_body("_token=real&name=alice", "_token", "tampered")
        assert "_token=tampered" in result
        assert "name=alice" in result

    def test_find_csrf_params_detects_token(self):
        from dast.agents.csrf_agent import _find_csrf_params
        target = _FakeTarget(params=[
            {"name": "_token", "value": "abc"},
            {"name": "user_id", "value": "1"},
        ])
        assert "_token" in _find_csrf_params(target)
        assert "user_id" not in _find_csrf_params(target)

    def test_find_csrf_params_authenticity_token(self):
        from dast.agents.csrf_agent import _find_csrf_params
        target = _FakeTarget(params=[{"name": "authenticity_token", "value": "xyz"}])
        assert "authenticity_token" in _find_csrf_params(target)


# ── cross_session_idor helpers ────────────────────────────────────────────

class TestCrossSessionIdorHelpers:
    def test_build_session_headers_strips_auth(self):
        from dast.agents.cross_session_idor_agent import _build_session_headers
        from unittest.mock import MagicMock

        session = MagicMock()
        session.auth_headers = {"Authorization": "Bearer session-b-token"}
        session.cookies = {"session_id": {"value": "sess-b-value"}}

        original = {
            "Authorization": "Bearer session-a-token",
            "Content-Type": "application/json",
            "X-Api-Key": "session-a-key",
        }
        result = _build_session_headers(original, session)

        assert result.get("Authorization") == "Bearer session-b-token"
        assert "X-Api-Key" not in result
        assert result.get("Content-Type") == "application/json"
        assert "session_id=sess-b-value" in result.get("cookie", "")

    def test_build_session_headers_no_cookies(self):
        from dast.agents.cross_session_idor_agent import _build_session_headers
        from unittest.mock import MagicMock

        session = MagicMock()
        session.auth_headers = {"Authorization": "Bearer b"}
        session.cookies = {}
        result = _build_session_headers({"Authorization": "Bearer a"}, session)
        assert "cookie" not in result

    def test_responses_similar_within_range(self):
        from dast.agents.cross_session_idor_agent import _responses_similar
        assert _responses_similar(200, 1000, 200, 1100) is True
        assert _responses_similar(200, 1000, 200, 750) is True

    def test_responses_similar_zero_baseline(self):
        from dast.agents.cross_session_idor_agent import _responses_similar
        assert _responses_similar(200, 0, 200, 100) is False

    def test_responses_similar_probe_4xx(self):
        from dast.agents.cross_session_idor_agent import _responses_similar
        assert _responses_similar(200, 1000, 403, 1000) is False


# ── business_logic JWT helpers ────────────────────────────────────────────

class TestBusinessLogicJwtHelpers:
    _SAMPLE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    def test_is_jwt_real_token(self):
        from dast.agents.business_logic_agent import _is_jwt
        assert _is_jwt(self._SAMPLE_JWT) is True

    def test_is_jwt_plain_string(self):
        from dast.agents.business_logic_agent import _is_jwt
        assert _is_jwt("hello") is False
        assert _is_jwt("abc.def") is False

    def test_is_jwt_numeric(self):
        from dast.agents.business_logic_agent import _is_jwt
        assert _is_jwt("12345") is False

    def test_decode_jwt_claims(self):
        from dast.agents.business_logic_agent import _decode_jwt_claims
        claims = _decode_jwt_claims(self._SAMPLE_JWT)
        assert claims is not None
        assert claims.get("sub") == "user123"
        assert claims.get("role") == "user"

    def test_decode_jwt_claims_malformed(self):
        from dast.agents.business_logic_agent import _decode_jwt_claims
        assert _decode_jwt_claims("not.a.jwt") is None
        assert _decode_jwt_claims("only-one-part") is None

    def test_decode_jwt_header(self):
        from dast.agents.business_logic_agent import _decode_jwt_header
        header = _decode_jwt_header(self._SAMPLE_JWT)
        assert header is not None
        assert header.get("alg") == "HS256"
        assert header.get("typ") == "JWT"

    def test_build_jwt_alg_none_preserves_claims(self):
        from dast.agents.business_logic_agent import _build_jwt_alg_none, _decode_jwt_claims
        variants = list(_build_jwt_alg_none(self._SAMPLE_JWT))
        assert len(variants) == 3  # none, None, NONE
        for v in variants:
            claims = _decode_jwt_claims(v)
            assert claims is not None
            assert claims.get("sub") == "user123"

    def test_build_jwt_alg_none_injects_extra_claims(self):
        from dast.agents.business_logic_agent import _build_jwt_alg_none, _decode_jwt_claims
        variants = list(_build_jwt_alg_none(self._SAMPLE_JWT, {"role": "admin"}))
        for v in variants:
            claims = _decode_jwt_claims(v)
            assert claims is not None
            assert claims.get("role") == "admin"

    def test_build_jwt_alg_none_signature_is_empty(self):
        from dast.agents.business_logic_agent import _build_jwt_alg_none
        for v in _build_jwt_alg_none(self._SAMPLE_JWT):
            assert v.endswith("."), f"alg:none token must have empty signature, got: {v}"

    def test_cwe_for_known_type(self):
        from dast.agents.business_logic_agent import _cwe_for_type
        assert _cwe_for_type("mass_assignment") == "CWE-915"
        assert _cwe_for_type("workflow_bypass") == "CWE-841"
        assert _cwe_for_type("privilege_escalation") == "CWE-269"

    def test_cwe_for_unknown_type_fallback(self):
        from dast.agents.business_logic_agent import _cwe_for_type
        result = _cwe_for_type("some_unknown_type")
        assert result.startswith("CWE-")


# ── llm_injection_agent helpers ───────────────────────────────────────────

class TestLlmInjectionHelpers:
    def test_is_ai_param_prompt(self):
        from dast.agents.llm_injection_agent import _is_ai_param
        assert _is_ai_param("prompt") is True
        assert _is_ai_param("system_prompt") is True

    def test_is_ai_param_nested_uses_leaf(self):
        from dast.agents.llm_injection_agent import _is_ai_param
        # "input.prompt" → checks "prompt" (the leaf), not "input"
        assert _is_ai_param("input.prompt") is True

    def test_is_ai_param_message_is_ai_signal(self):
        from dast.agents.llm_injection_agent import _is_ai_param
        # "message" is an LLM input signal
        assert _is_ai_param("message") is True

    def test_is_ai_param_regular_param(self):
        from dast.agents.llm_injection_agent import _is_ai_param
        assert _is_ai_param("user_id") is False
        assert _is_ai_param("page") is False

    def test_is_ai_url_chat_completions(self):
        from dast.agents.llm_injection_agent import _is_ai_url
        assert _is_ai_url("https://api.example.com/v1/chat/completions") is True

    def test_is_ai_url_regular_endpoint(self):
        from dast.agents.llm_injection_agent import _is_ai_url
        assert _is_ai_url("https://app.example.com/api/users") is False

    def test_is_ai_response_with_choices(self):
        from dast.agents.llm_injection_agent import _is_ai_response
        body = '{"choices": [{"message": {"content": "hello"}}], "model": "gpt-4"}'
        assert _is_ai_response(body) is True

    def test_is_ai_response_regular_json(self):
        from dast.agents.llm_injection_agent import _is_ai_response
        assert _is_ai_response('{"users": [{"id": 1}]}') is False

    def test_find_in_output_fields_marker_in_non_input_field(self):
        from dast.agents.llm_injection_agent import _find_in_output_fields
        # "translation" and "summary" are NOT in _INPUT_FIELD_NAMES — these are output fields
        data = {
            "input": {"prompt": "ignored MARKER"},
            "result": {"translation": "the MARKER was executed"},
        }
        assert _find_in_output_fields(data, "MARKER", "prompt") is True

    def test_find_in_output_fields_marker_only_in_input(self):
        from dast.agents.llm_injection_agent import _find_in_output_fields
        data = {
            "data": {
                "generateText": {
                    "prompt": "echo: MARKER",  # input field echoed back
                    "url": "https://example.com/img.png",
                }
            }
        }
        # "prompt" is an input field — marker in it should NOT confirm injection
        assert _find_in_output_fields(data, "MARKER", "prompt") is False

    def test_find_in_output_fields_in_non_input_list_item(self):
        from dast.agents.llm_injection_agent import _find_in_output_fields
        # "response_body" is not in _INPUT_FIELD_NAMES
        data = {"results": [{"response_body": "result: MARKER"}]}
        assert _find_in_output_fields(data, "MARKER", "prompt") is True

    def test_find_in_output_fields_content_is_treated_as_input(self):
        from dast.agents.llm_injection_agent import _find_in_output_fields
        # "content" IS in _INPUT_FIELD_NAMES — should not confirm
        data = {"choices": [{"content": "MARKER echoed"}]}
        assert _find_in_output_fields(data, "MARKER", "content") is False

    def test_find_in_output_fields_not_present(self):
        from dast.agents.llm_injection_agent import _find_in_output_fields
        data = {"output": {"text": "normal response"}}
        assert _find_in_output_fields(data, "MARKER", "prompt") is False


# ── blazor helpers ────────────────────────────────────────────────────────

class TestBlazorHelpers:
    def test_base_url_strips_path(self):
        from dast.agents.blazor_agent import _base_url
        assert _base_url("https://app.example.com/some/path?q=1") == "https://app.example.com"

    def test_base_url_preserves_port(self):
        from dast.agents.blazor_agent import _base_url
        assert _base_url("https://app.example.com:8443/path") == "https://app.example.com:8443"

    def test_make_url_combines(self):
        from dast.agents.blazor_agent import _make_url
        result = _make_url("https://app.example.com", "/_framework/blazor.boot.json")
        assert result == "https://app.example.com/_framework/blazor.boot.json"

    def test_make_url_strips_existing_query(self):
        from dast.agents.blazor_agent import _make_url
        result = _make_url("https://app.example.com?old=1", "/_framework/dotnet.wasm")
        assert "?" not in result
        assert result.endswith("/_framework/dotnet.wasm")

    def test_signalr_handshake_ends_with_separator(self):
        from dast.agents.blazor_agent import _build_signalr_handshake
        msg = _build_signalr_handshake()
        assert msg.endswith(b"\x1e"), "SignalR handshake must end with record separator 0x1e"

    def test_signalr_handshake_is_valid_json(self):
        from dast.agents.blazor_agent import _build_signalr_handshake
        import json
        msg = _build_signalr_handshake().rstrip(b"\x1e")
        parsed = json.loads(msg)
        assert parsed.get("protocol") == "json"
        assert parsed.get("version") == 1

    def test_signalr_message_ends_with_separator(self):
        from dast.agents.blazor_agent import _build_signalr_message
        msg = _build_signalr_message("SomeHub", ["arg1"])
        assert msg.endswith(b"\x1e")

    def test_signalr_message_is_valid_json(self):
        from dast.agents.blazor_agent import _build_signalr_message
        import json
        msg = _build_signalr_message("SomeHub", ["arg1"]).rstrip(b"\x1e")
        parsed = json.loads(msg)
        assert parsed["type"] == 1
        assert parsed["target"] == "SomeHub"
        assert parsed["arguments"] == ["arg1"]

"""
Unit tests for the GraphQL routes: schema lookup, manual introspection,
query building, and the variable-fuzzing job (run/poll/stop).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


def _make_response(status_code=200, body="{}"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = body.encode("utf-8")
    resp.text = body
    resp.json = MagicMock(return_value=__import__("json").loads(body)) if body.strip().startswith("{") else MagicMock(side_effect=Exception())
    return resp


@pytest.fixture
def app_and_store():
    from dast.proxy.dashboard_server import build_app
    from dast.proxy.session_store import SessionStore

    store = SessionStore()
    app = build_app(store=store, scan_queue=asyncio.Queue())
    return app, store


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


_SCHEMA = {
    "introspected": True,
    "queries": {
        "user": {"args": [{"name": "id", "type": "ID", "wrapper": "NON_NULL"}], "return_type": "User"},
    },
    "mutations": {},
    "input_types": {},
    "object_types": {
        "User": {"kind": "OBJECT", "fields": [
            {"name": "id", "type": "ID", "wrapper": "NON_NULL", "arg_count": 0},
        ]},
    },
    "union_types": {},
    "enum_types": {},
}


class TestGraphqlSchemaEndpoints:
    @pytest.mark.asyncio
    async def test_endpoints_lists_stored_schemas(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = _SCHEMA
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/endpoints")
            assert resp.json()["endpoints"] == [
                {"endpoint": "https://example.com/graphql", "introspected": True}
            ]

    @pytest.mark.asyncio
    async def test_endpoints_lists_uninstrospected_catalogued_endpoint(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = {"introspected": False}
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/endpoints")
            assert resp.json()["endpoints"] == [
                {"endpoint": "https://example.com/graphql", "introspected": False}
            ]

    @pytest.mark.asyncio
    async def test_schema_missing_endpoint_param_400(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/schema")
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_schema_unknown_endpoint_returns_available_list(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = _SCHEMA
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/schema?endpoint=https://other.com/graphql")
            data = resp.json()
            assert data["schema"] is None
            assert "https://example.com/graphql" in data["available"]

    @pytest.mark.asyncio
    async def test_schema_found_by_exact_match(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = _SCHEMA
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/schema?endpoint=https://example.com/graphql")
            assert resp.json()["schema"] == _SCHEMA

    @pytest.mark.asyncio
    async def test_schema_not_yet_introspected_returns_none(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = {"introspected": False}
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/schema?endpoint=https://example.com/graphql")
            data = resp.json()
            assert data["schema"] is None
            assert data["introspected"] is False

    @pytest.mark.asyncio
    async def test_schema_prefix_match_is_path_boundary_aware(self, app_and_store):
        # Regression: a bare startswith() would incorrectly match /graphql-internal
        # against a stored /graphql key. Path-boundary-aware matching must not.
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = _SCHEMA
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/schema?endpoint=https://example.com/graphql-internal")
            assert resp.json()["schema"] is None

    @pytest.mark.asyncio
    async def test_schema_prefix_match_with_trailing_path_segment(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = _SCHEMA
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/schema?endpoint=https://example.com/graphql/v2?x=1")
            assert resp.json()["schema"] == _SCHEMA


class TestGraphqlEndpointsAddAndRescan:
    @pytest.mark.asyncio
    async def test_add_endpoint_manually(self, app_and_store):
        app, store = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/endpoints", json={"endpoint": "https://example.com/graphql"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True
            assert data["added"] is True
        assert store.graphql_schemas["https://example.com/graphql"] == {"introspected": False}

    @pytest.mark.asyncio
    async def test_add_endpoint_missing_url_400(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/endpoints", json={})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_add_endpoint_twice_reports_not_added(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = _SCHEMA
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/endpoints", json={"endpoint": "https://example.com/graphql"})
            assert resp.json()["added"] is False
        # Must not clobber an already-introspected schema.
        assert store.graphql_schemas["https://example.com/graphql"] == _SCHEMA

    @pytest.mark.asyncio
    async def test_rescan_history_catalogues_missed_endpoint(self, app_and_store):
        app, store = app_and_store
        store.new_entry("POST", "https://example.com/vis/graphql", {}, b'{"query": "query{x}"}')
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/rescan-history")
            assert resp.status_code == 200
            assert resp.json()["new_endpoints"] == 1
        assert "https://example.com/vis/graphql" in store.graphql_schemas

    @pytest.mark.asyncio
    async def test_rescan_history_skips_non_graphql_traffic(self, app_and_store):
        app, store = app_and_store
        store.new_entry("GET", "https://example.com/api/users", {}, None)
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/rescan-history")
            assert resp.json()["new_endpoints"] == 0


class TestGraphqlBuild:
    @pytest.mark.asyncio
    async def test_build_returns_query_and_variables(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = _SCHEMA
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/build", json={
                "endpoint": "https://example.com/graphql",
                "operation": "query",
                "field_name": "user",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "query User" in data["query"]
            assert data["variables"] == {"var0": "1"}

    @pytest.mark.asyncio
    async def test_build_unknown_endpoint_404(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/build", json={
                "endpoint": "https://nope.com/graphql", "operation": "query", "field_name": "user",
            })
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_build_unknown_field_400(self, app_and_store):
        app, store = app_and_store
        store.graphql_schemas["https://example.com/graphql"] = _SCHEMA
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/build", json={
                "endpoint": "https://example.com/graphql", "operation": "query", "field_name": "doesNotExist",
            })
            assert resp.status_code == 400


class TestGraphqlIntrospectRoute:
    @pytest.mark.asyncio
    async def test_introspect_updates_schema_on_success(self, app_and_store):
        app, store = app_and_store

        raw_response = {
            "data": {
                "__schema": {
                    "mutationType": {"name": "Mutation"},
                    "queryType": {"name": "Query"},
                    "types": [
                        {"name": "Query", "kind": "OBJECT", "fields": [
                            {"name": "ping", "type": {"name": "String", "kind": "SCALAR"}, "args": []},
                        ]},
                    ],
                }
            }
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_make_response(200, __import__("json").dumps(raw_response)))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        # Build the test transport client BEFORE patching httpx.AsyncClient —
        # patching replaces it on the shared httpx module, which would also
        # hijack the test client itself if created inside the patch context.
        async with await _client(app) as client:
            with patch("dast.plugins.graphql_introspection.httpx.AsyncClient", return_value=mock_client):
                resp = await client.post("/api/graphql/introspect", json={"endpoint": "https://example.com/graphql"})
                assert resp.status_code == 200
                assert resp.json()["ok"] is True

        assert "ping" in store.graphql_schemas["https://example.com/graphql"]["queries"]

    @pytest.mark.asyncio
    async def test_introspect_missing_endpoint_400(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/introspect", json={})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_introspect_failure_reports_not_ok(self, app_and_store):
        app, store = app_and_store
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_make_response(500, "server error"))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        async with await _client(app) as client:
            with patch("dast.plugins.graphql_introspection.httpx.AsyncClient", return_value=mock_client):
                resp = await client.post("/api/graphql/introspect", json={"endpoint": "https://example.com/graphql"})
                data = resp.json()
                assert data["ok"] is False
                assert "500" in data["error"]

        assert "https://example.com/graphql" not in store.graphql_schemas

    @pytest.mark.asyncio
    async def test_introspect_error_message_surfaces_directly_not_send_to_logs(self, app_and_store):
        # Regression: the error used to say "see Logs tab", but the Logs tab's
        # default filter hides "warn"-level events, so the user saw nothing
        # there. The route must return the actual reason directly.
        app, store = app_and_store
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_make_response(
            200, '{"errors": [{"message": "GraphQL introspection is not allowed"}]}',
        ))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        async with await _client(app) as client:
            with patch("dast.plugins.graphql_introspection.httpx.AsyncClient", return_value=mock_client):
                resp = await client.post("/api/graphql/introspect", json={"endpoint": "https://example.com/graphql"})
                data = resp.json()
                assert data["ok"] is False
                assert "Logs tab" not in data["error"]
                assert "GraphQL introspection is not allowed" in data["error"]

    @pytest.mark.asyncio
    async def test_introspect_uses_explicit_header_override(self, app_and_store):
        # Explicit headers must win over the most-recent-traffic guess, so a
        # user can point introspection at a different session's auth.
        app, store = app_and_store
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_make_response(200, '{"data": {"__schema": {"types": []}}}'))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        async with await _client(app) as client:
            with patch("dast.plugins.graphql_introspection.httpx.AsyncClient", return_value=mock_client):
                await client.post("/api/graphql/introspect", json={
                    "endpoint": "https://example.com/graphql",
                    "headers": {"cookie": "session=admin-override"},
                })

        sent_headers = mock_client.post.call_args.kwargs["headers"]
        assert sent_headers["cookie"] == "session=admin-override"


class TestGraphqlHeadersForEndpoint:
    @pytest.mark.asyncio
    async def test_missing_endpoint_400(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/headers-for-endpoint")
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_returns_headers_from_most_recent_matching_request(self, app_and_store):
        app, store = app_and_store
        store.new_entry("POST", "https://example.com/graphql", {"cookie": "session=abc", "authorization": "Bearer x"}, b"{}")
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/headers-for-endpoint?endpoint=https://example.com/graphql")
            headers = resp.json()["headers"]
            assert headers.get("cookie") == "session=abc"
            assert headers.get("authorization") == "Bearer x"

    @pytest.mark.asyncio
    async def test_named_session_headers_take_precedence(self, app_and_store):
        from dast.proxy.session_store import NamedSession

        app, store = app_and_store
        store.new_entry("POST", "https://example.com/graphql", {"cookie": "session=from-traffic"}, b"{}")
        store.named_sessions["admin"] = NamedSession(
            name="admin", role="admin",
            cookies={"session": {"name": "session", "value": "from-named-session"}},
            auth_headers={},
        )
        async with await _client(app) as client:
            resp = await client.get(
                "/api/graphql/headers-for-endpoint?endpoint=https://example.com/graphql&named_session=admin"
            )
            headers = resp.json()["headers"]
            assert headers["cookie"] == "session=from-named-session"

    @pytest.mark.asyncio
    async def test_unknown_named_session_returns_empty_headers(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.get(
                "/api/graphql/headers-for-endpoint?endpoint=https://example.com/graphql&named_session=nope"
            )
            assert resp.json()["headers"] == {}


class TestGraphqlFuzzExtractVars:
    @pytest.mark.asyncio
    async def test_extract_vars_returns_variable_list(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/fuzz/extract-vars", json={
                "body": '{"query": "query{x}", "variables": {"id": "1"}}',
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["variables"] == [{"name": "id", "original_value": "1", "inferred_type": "string"}]

    @pytest.mark.asyncio
    async def test_extract_vars_no_variables_400(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/fuzz/extract-vars", json={"body": '{"query": "query{x}"}'})
            assert resp.status_code == 400


class TestGraphqlFuzzJob:
    @pytest.mark.asyncio
    async def test_run_returns_job_id_immediately(self, app_and_store):
        app, _ = app_and_store
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200, '{"data": {}}'))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        async with await _client(app) as client:
            with patch("dast.proxy.api.graphql_routes.httpx.AsyncClient", return_value=mock_client), \
                 patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
                resp = await client.post("/api/graphql/fuzz/run", json={
                    "method": "POST",
                    "url": "https://example.com/graphql",
                    "headers": {},
                    "body": '{"query": "query{x}", "variables": {"id": "1"}}',
                    "payload_source": "custom",
                    "custom_payloads": "p1\np2",
                })
                assert resp.status_code == 200
                data = resp.json()
                assert "job_id" in data
                assert data["total"] == 2

    @pytest.mark.asyncio
    async def test_run_missing_url_400(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/fuzz/run", json={"body": "{}"})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_run_no_variables_400(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/fuzz/run", json={
                "url": "https://example.com/graphql", "body": '{"query": "query{x}"}',
            })
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_poll_reaches_done(self, app_and_store):
        app, _ = app_and_store
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200, '{"data": {}}'))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        async with await _client(app) as client:
            with patch("dast.proxy.api.graphql_routes.httpx.AsyncClient", return_value=mock_client), \
                 patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
                resp = await client.post("/api/graphql/fuzz/run", json={
                    "url": "https://example.com/graphql",
                    "body": '{"query": "query{x}", "variables": {"id": "1"}}',
                    "payload_source": "custom",
                    "custom_payloads": "p1",
                })
                job_id = resp.json()["job_id"]

                data = None
                for _ in range(50):
                    poll = await client.get(f"/api/graphql/fuzz/results/{job_id}")
                    data = poll.json()
                    if data["status"] not in ("queued", "running"):
                        break
                    await asyncio.sleep(0.02)

                assert data["status"] == "done"
                assert len(data["results"]) == 1

    @pytest.mark.asyncio
    async def test_unknown_job_id_404(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.get("/api/graphql/fuzz/results/does-not-exist")
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_stop_sets_cancel(self, app_and_store):
        app, _ = app_and_store
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(200, '{"data": {}}'))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        async with await _client(app) as client:
            with patch("dast.proxy.api.graphql_routes.httpx.AsyncClient", return_value=mock_client), \
                 patch("dast.graphql.variable_fuzzer.httpx.AsyncClient", return_value=mock_client):
                resp = await client.post("/api/graphql/fuzz/run", json={
                    "url": "https://example.com/graphql",
                    "body": '{"query": "query{x}", "variables": {"id": "1"}}',
                    "payload_source": "custom",
                    "custom_payloads": "p1\np2\np3",
                })
                job_id = resp.json()["job_id"]
                stop_resp = await client.post(f"/api/graphql/fuzz/stop/{job_id}")
                assert stop_resp.json()["ok"] is True

    @pytest.mark.asyncio
    async def test_stop_unknown_job_id_404(self, app_and_store):
        app, _ = app_and_store
        async with await _client(app) as client:
            resp = await client.post("/api/graphql/fuzz/stop/does-not-exist")
            assert resp.status_code == 404

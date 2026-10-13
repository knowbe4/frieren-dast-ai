"""OriginGuardMiddleware — the dashboard must reject cross-site and DNS-rebinding traffic."""

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from dast.proxy.api.origin_guard import OriginGuardMiddleware, is_allowed_host, is_allowed_origin


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(OriginGuardMiddleware)

    @app.get("/api/thing")
    async def read_thing():
        return {"ok": True}

    @app.post("/api/thing")
    async def write_thing():
        return {"ok": True}

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await ws.accept()
        await ws.send_text("hello")
        await ws.close()

    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_app(), base_url="http://127.0.0.1:8088")


class TestHostCheck:
    def test_loopback_hosts_allowed(self):
        allowed = {"127.0.0.1", "localhost", "[::1]"}
        assert is_allowed_host("127.0.0.1:8088", allowed)
        assert is_allowed_host("localhost", allowed)
        assert is_allowed_host("[::1]:8088", allowed)

    def test_rebinding_host_rejected(self, client):
        resp = client.get("/api/thing", headers={"Host": "evil.example.com:8088"})
        assert resp.status_code == 403

    def test_missing_host_rejected(self):
        assert not is_allowed_host(None, {"127.0.0.1"})


class TestOriginCheck:
    def test_same_origin_post_allowed(self, client):
        resp = client.post("/api/thing", headers={"Origin": "http://127.0.0.1:8088"})
        assert resp.status_code == 200

    def test_no_origin_post_allowed(self, client):
        assert client.post("/api/thing").status_code == 200

    def test_cross_origin_text_plain_post_rejected(self, client):
        resp = client.post(
            "/api/thing",
            content='{"content": "x"}',
            headers={"Origin": "https://evil.example.com", "Content-Type": "text/plain"},
        )
        assert resp.status_code == 403

    def test_null_origin_rejected(self):
        assert not is_allowed_origin("null", "127.0.0.1:8088")

    def test_other_local_port_rejected(self):
        assert not is_allowed_origin("http://127.0.0.1:3000", "127.0.0.1:8088")

    def test_cross_origin_get_allowed(self, client):
        # Reads are protected by the browser's same-origin policy; only the Host
        # check applies (CA cert download links etc. must keep working).
        resp = client.get("/api/thing", headers={"Origin": "https://evil.example.com"})
        assert resp.status_code == 200


class TestWebSocket:
    def test_same_origin_ws_accepted(self, client):
        with client.websocket_connect("ws://127.0.0.1:8088/ws", headers={"Origin": "http://127.0.0.1:8088"}) as ws:
            assert ws.receive_text() == "hello"

    def test_cross_origin_ws_rejected(self, client):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("ws://127.0.0.1:8088/ws", headers={"Origin": "https://evil.example.com"}) as ws:
                ws.receive_text()

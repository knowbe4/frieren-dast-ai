"""
Human-readable SignalR / Blazor body decoding (dast.proxy.signalr), used by the
HTTP history view. Also pins the backward-compatible aliases in session_store.
"""

from __future__ import annotations

import json
from typing import Any

import msgpack

from dast.proxy import session_store
from dast.proxy.signalr import (
    annotate_blazor_args,
    body_preview,
    decode_body,
    decode_msgpack_signalr,
    decode_signalr_body,
    encode_varint,
    is_signalr_body,
    is_signalr_path,
)


def _frame(message: Any) -> bytes:
    payload = msgpack.packb(message)
    return encode_varint(len(payload)) + payload


class TestTextProtocol:
    def test_invocation_result_ping_close(self) -> None:
        raw = (
            b'{"type":1,"target":"Send","arguments":["hi"],"invocationId":"7"}\x1e'
            b'{"type":3,"result":{"ok":true}}\x1e{"type":6}\x1e{"type":7,"error":"bye"}\x1e'
        )
        assert decode_signalr_body(raw).split("\n") == [
            '[invoke] [7] Send(["hi"])',
            '[result] {"ok": true}',
            "[ping]",
            "[close] bye",
        ]

    def test_invalid_json_segment_falls_back_to_readable_text(self) -> None:
        assert decode_signalr_body(b"{not json\x1e") == "{not json"

    def test_handshake_is_signalr_body(self) -> None:
        assert is_signalr_body(b'{"protocol":"json","version":1}\x1e')
        assert not is_signalr_body(b"plain text")


class TestBinaryProtocol:
    def test_connect_circuit_token_is_labelled(self) -> None:
        raw = _frame([1, {}, "3", "ConnectCircuit", ["CfDJ8" + "a" * 40]])
        decoded = decode_msgpack_signalr(raw)
        assert decoded.startswith("[invoke] [3] ConnectCircuit(")
        assert "ASP.NET DataProtection token" in decoded

    def test_dotnet_invoke_and_js_result(self) -> None:
        raw = (
            _frame([1, {}, None, "BeginInvokeDotNetFromJS", ["1", "App", "Save", 0, "[1,2]"]])
            + _frame([1, {}, None, "EndInvokeJSFromDotNet", [4, True, '{"a":1}']])
            + _frame([6])
        )
        assert decode_signalr_body(raw).split("\n") == [
            "[dotnet-invoke] App::Save([1, 2])",
            '[js-result] [4] ok {"a": 1}',
            "[ping]",
        ]

    def test_non_json_dotnet_args_fall_back_to_raw_text(self) -> None:
        raw = _frame([1, {}, None, "BeginInvokeDotNetFromJS", ["1", "", "M", 0, "{bad"]])
        assert decode_msgpack_signalr(raw) == "[dotnet-invoke] M({bad)"

    def test_completion_variants(self) -> None:
        raw = (
            _frame([3, {}, "1"])
            + _frame([3, {}, "1", 1, "boom"])
            + _frame([3, {}, "1", 2, {"r": 1}])
        )
        assert decode_msgpack_signalr(raw).split("\n") == [
            "[result:void]",
            "[result:error] boom",
            '[result] {"r": 1}',
        ]


class TestAnnotateBlazorArgs:
    def test_update_root_components_summary(self) -> None:
        operations = json.dumps([{"type": "add", "marker": "m"}] * 4)
        assert annotate_blazor_args("UpdateRootComponents", [operations]) == (
            "[add:m, add:m, add:m…] (4 ops)"
        )

    def test_update_root_components_invalid_json_falls_through(self) -> None:
        assert annotate_blazor_args("UpdateRootComponents", ["{bad"]) == '["{bad"]'

    def test_infra_call_shows_arg_count(self) -> None:
        assert annotate_blazor_args("JsInitialized", [1, 2]) == "(2 args)"


class TestBodyRendering:
    def test_decode_body_strips_leading_binary_on_hub_path(self) -> None:
        assert decode_body(b"\x01\x02hello", "/_blazor") == "hello"
        assert decode_body(b"\x01\x02hello", "/api") == "  hello"

    def test_body_preview_uses_first_decoded_line(self) -> None:
        raw = b'{"type":6}\x1e{"type":7}\x1e'
        assert body_preview(raw) == "[ping]"

    def test_is_signalr_path(self) -> None:
        assert is_signalr_path("/hubs/chat")
        assert not is_signalr_path("/api/users")


def test_session_store_keeps_backward_compatible_aliases() -> None:
    assert session_store._decode_signalr_body is decode_signalr_body
    assert session_store._decode_msgpack_signalr is decode_msgpack_signalr
    assert session_store._annotate_blazor_args is annotate_blazor_args
    assert session_store._decode_body is decode_body
    assert session_store._body_preview is body_preview
    assert session_store._is_signalr_body is is_signalr_body
    assert session_store._is_signalr_path is is_signalr_path
    assert session_store._SIGNALR_SEP == "\x1e"

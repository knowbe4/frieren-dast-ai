"""Unit tests for the CollaboratorService redirect endpoint (5-B-2).

The listener's ``_handle`` is exercised directly with mock reader/writer — no
real socket. Covers: internal ``to`` → 302 + Location, external ``to`` → 403,
and the bare-token hit recording that lets ``was_hit(token)`` match both the
initial /redirect/<token> fetch and the followed /follow/<token> second stage.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from dast.scanners.collaborator import (
    CollaboratorService,
    _is_internal_redirect_target,
)


def _run_handle(service: CollaboratorService, request_line: str):
    reader = MagicMock()

    async def fake_read(timeout=None):
        return request_line.encode()

    reader.read = fake_read

    writer = MagicMock()
    written: list = []

    async def fake_drain():
        return None

    def fake_write(data):
        written.append(data)

    writer.drain = fake_drain
    writer.write = fake_write
    writer.close = lambda: None
    writer.wait_closed = None  # not awaited in _handle's finally (close only)

    asyncio.run(service._handle(reader, writer))
    return b"".join(written).decode()


def test_internal_redirect_target_gets_302():
    service = CollaboratorService()
    raw = _run_handle(
        service,
        "GET /redirect/dast123?to=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F HTTP/1.1\r\n"
        "Host: collab\r\n\r\n",
    )
    assert raw.startswith("HTTP/1.0 302 Found")
    assert "Location: http://169.254.169.254/latest/meta-data/" in raw
    # both the raw path and the bare token are recorded as hits
    assert service.was_hit("dast123")


def test_external_redirect_target_gets_403():
    service = CollaboratorService()
    raw = _run_handle(
        service,
        "GET /redirect/dast456?to=http%3A%2F%2Fevil.example.com%2Fsteal HTTP/1.1\r\n\r\n",
    )
    assert raw.startswith("HTTP/1.0 403 Forbidden")


def test_follow_path_records_bare_token_for_was_hit():
    service = CollaboratorService()
    _run_handle(service, "GET /follow/dast789 HTTP/1.1\r\n\r\n")
    assert service.was_hit("follow/dast789")   # exact raw path
    assert service.was_hit("dast789")          # bare token (redirect group logic)


def test_plain_token_callback_unchanged():
    service = CollaboratorService()
    _run_handle(service, "GET /dast111 HTTP/1.1\r\n\r\n")
    assert service.was_hit("dast111")


# ── the internal-target gate ─────────────────────────────────────────────────

def test_gate_allows_internal_and_metadata_hosts():
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://192.168.1.10/",
        "http://172.20.3.4/",
        "http://169.254.170.2/v2/metadata",
    ):
        assert _is_internal_redirect_target(url), url


def test_gate_refuses_external_hosts_and_schemes():
    for url in (
        "http://evil.example.com/",
        "https://attacker.io/steal",
        "ftp://169.254.169.254/",
        "javascript:alert(1)",
        "not a url",
        "",
    ):
        assert not _is_internal_redirect_target(url), url

"""
Unit tests for dast.proxy.cert_authority — per-host leaf certificate generation.

Regression: a hostname longer than 64 chars raised ValueError from the
cryptography lib (X.509 CommonName is capped at 64 chars by RFC 5280),
crashing the CONNECT handler and breaking MITM interception for that host
entirely (see traceback in proxy log: "Attribute's length must be >= 1 and
<= 64, but it was 71").
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID


@pytest.fixture
def ca(tmp_path, monkeypatch):
    from dast.proxy import cert_authority as ca_mod

    monkeypatch.setattr(ca_mod, "_CA_DIR", tmp_path)
    monkeypatch.setattr(ca_mod, "_CA_KEY_PATH", tmp_path / "ca.key")
    monkeypatch.setattr(ca_mod, "_CA_CERT_PATH", tmp_path / "ca.crt")
    return ca_mod.CertAuthority()


def _load_cert(cert_pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_pem)


class TestGetLeafCert:
    def test_short_hostname_uses_hostname_as_common_name(self, ca):
        cert_pem, _ = ca.get_leaf_cert("example.com")
        cert = _load_cert(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "example.com"

    def test_short_hostname_present_in_san(self, ca):
        cert_pem, _ = ca.get_leaf_cert("example.com")
        cert = _load_cert(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert "example.com" in san.get_values_for_type(x509.DNSName)

    def test_hostname_longer_than_64_chars_does_not_raise(self, ca):
        long_host = "a" * 71 + ".example.com"
        cert_pem, _ = ca.get_leaf_cert(long_host)
        assert cert_pem  # no exception, and a cert came back

    def test_hostname_longer_than_64_chars_still_in_san(self, ca):
        # The browser validates against SAN, not CN, so interception must
        # still work correctly even though the CN had to be replaced.
        long_host = "a" * 71 + ".example.com"
        cert_pem, _ = ca.get_leaf_cert(long_host)
        cert = _load_cert(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert long_host in san.get_values_for_type(x509.DNSName)

    def test_hostname_exactly_64_chars_keeps_hostname_as_common_name(self, ca):
        host_64 = "a" * 52 + ".example.com"  # 64 chars exactly
        assert len(host_64) == 64
        cert_pem, _ = ca.get_leaf_cert(host_64)
        cert = _load_cert(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == host_64

    def test_ip_address_hostname_uses_ip_san(self, ca):
        cert_pem, _ = ca.get_leaf_cert("192.168.1.1")
        cert = _load_cert(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert san.get_values_for_type(x509.IPAddress)

    def test_leaf_cert_is_cached_per_hostname(self, ca):
        first = ca.get_leaf_cert("example.com")
        second = ca.get_leaf_cert("example.com")
        assert first == second

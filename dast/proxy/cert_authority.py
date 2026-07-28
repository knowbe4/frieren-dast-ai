"""
On-the-fly certificate authority for HTTPS MITM interception.

On first run, generates a root CA (key + self-signed cert) and saves it to
~/.dast-ai/ca.key and ~/.dast-ai/ca.crt.

The user installs ca.crt in their browser/OS trust store once. After that,
per-domain leaf certificates are generated and signed by this CA so the
browser accepts them without warnings.

Leaf certs are cached in memory — one per hostname.
"""

import ipaddress
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

_CA_DIR = Path.home() / ".dast-ai"
_CA_KEY_PATH = _CA_DIR / "ca.key"
_CA_CERT_PATH = _CA_DIR / "ca.crt"


class CertAuthority:
    def __init__(self):
        self._lock = threading.Lock()
        self._leaf_cache: Dict[str, Tuple[bytes, bytes]] = {}  # host → (cert_pem, key_pem)
        self._ca_key = None
        self._ca_cert = None
        self._ca_key_pem: bytes = b""
        self._ca_cert_pem: bytes = b""
        # Shared EC key reused across all leaf certs — avoids per-host key generation (~10x faster than RSA)
        self._shared_leaf_key = ec.generate_private_key(ec.SECP256R1())
        self._shared_leaf_key_pem = self._shared_leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._ensure_ca()

    @property
    def ca_cert_path(self) -> Path:
        return _CA_CERT_PATH

    @property
    def ca_cert_pem(self) -> bytes:
        return self._ca_cert_pem

    def _ensure_ca(self) -> None:
        _CA_DIR.mkdir(parents=True, exist_ok=True)

        if _CA_KEY_PATH.exists() and _CA_CERT_PATH.exists():
            self._ca_key_pem = _CA_KEY_PATH.read_bytes()
            self._ca_cert_pem = _CA_CERT_PATH.read_bytes()
            self._ca_key = serialization.load_pem_private_key(self._ca_key_pem, password=None)
            self._ca_cert = x509.load_pem_x509_certificate(self._ca_cert_pem)
            return

        # Generate new CA
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Frieren DAST-AI CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Frieren DAST-AI"),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        _CA_KEY_PATH.write_bytes(key_pem)
        _CA_CERT_PATH.write_bytes(cert_pem)

        self._ca_key = key
        self._ca_cert = cert
        self._ca_key_pem = key_pem
        self._ca_cert_pem = cert_pem

    def get_leaf_cert(self, hostname: str) -> Tuple[bytes, bytes]:
        """Return (cert_pem, key_pem) for hostname, generating if needed."""
        with self._lock:
            if hostname in self._leaf_cache:
                return self._leaf_cache[hostname]

        cert_pem = self._generate_leaf_cert(hostname)
        with self._lock:
            self._leaf_cache[hostname] = (cert_pem, self._shared_leaf_key_pem)
        return cert_pem, self._shared_leaf_key_pem

    def _generate_leaf_cert(self, hostname: str) -> bytes:
        """Sign a new cert for hostname using the shared leaf key — no key generation needed."""
        # X.509 CommonName is capped at 64 chars by RFC 5280 (enforced by the
        # cryptography lib) — a long real-world hostname would raise ValueError
        # here. Browsers validate against the SAN below, not the CN, so a
        # generic placeholder CN is harmless when the hostname doesn't fit.
        common_name = hostname if len(hostname) <= 64 else "dast-ai-leaf-cert"
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(timezone.utc)

        # Build SAN — support both hostnames and IP addresses
        try:
            san = x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address(hostname))
            ])
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(self._ca_cert.subject)
            .public_key(self._shared_leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        return cert.public_bytes(serialization.Encoding.PEM)

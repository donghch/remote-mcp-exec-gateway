"""mTLS authentication and client identity extraction."""

from __future__ import annotations

import hashlib
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


@dataclass(frozen=True)
class ClientIdentity:
    """Authenticated client identity extracted from mTLS certificate."""

    cn: str
    organization: str | None = None
    fingerprint: str = ""
    not_before: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    not_after: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def display_name(self) -> str:
        org = f",O={self.organization}" if self.organization else ""
        return f"CN={self.cn}{org}"


class MTLSValidator:
    """Validates client certificates against a CA certificate."""

    def __init__(self, ca_cert_path: Path) -> None:
        self._ca_cert_path = ca_cert_path
        self._ca_cert = self._load_ca(ca_cert_path)

    @staticmethod
    def _load_ca(path: Path) -> x509.Certificate:
        pem = path.read_bytes()
        return x509.load_pem_x509_certificate(pem)

    def validate(self, cert_pem: bytes) -> ClientIdentity:
        """Validate a PEM-encoded client certificate against the CA.

        Raises ValueError if the certificate is invalid or not signed by the CA.
        """
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Check expiry
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            raise ValueError("Client certificate is not yet valid")
        if now > cert.not_valid_after_utc:
            raise ValueError("Client certificate has expired")

        # Verify signature against CA
        try:
            self._ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_oid._name,  # type: ignore[arg-type]
            )
        except Exception as exc:
            raise ValueError(f"Certificate not signed by trusted CA: {exc}") from exc

        # Extract identity
        cn = self._extract_cn(cert)
        org = self._extract_org(cert)
        fingerprint = cert.fingerprint(cert.signature_hash_algorithm).hex()

        return ClientIdentity(
            cn=cn,
            organization=org,
            fingerprint=fingerprint,
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
        )

    @staticmethod
    def _extract_cn(cert: x509.Certificate) -> str:
        try:
            cn_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            return cn_attr[0].value if cn_attr else "unknown"
        except Exception:
            return "unknown"

    @staticmethod
    def _extract_org(cert: x509.Certificate) -> str | None:
        try:
            org_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            return org_attr[0].value if org_attr else None
        except Exception:
            return None


def create_ssl_context(
    server_cert: Path,
    server_key: Path,
    ca_cert: Path,
    min_version: int = ssl.TLSVersion.TLSv1_3,
) -> ssl.SSLContext:
    """Create an SSL context configured for mTLS."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = min_version
    ctx.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.verify_mode = ssl.CERT_REQUIRED  # Require client certificate
    return ctx

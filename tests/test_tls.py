"""Tests for TLS on/off toggle and SSL context creation."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from config.models import TLSConfig, ServerConfig, ServerBlock, LoggingConfig
from config.models import SessionConfig, TimeoutConfig, SandboxConfig
from security.auth import create_ssl_context


class TestTLSConfig:
    def test_tls_enabled_by_default(self) -> None:
        cfg = TLSConfig()
        assert cfg.enabled is True

    def test_tls_disabled(self) -> None:
        cfg = TLSConfig(enabled=False)
        assert cfg.enabled is False
        assert cfg.cert_path is None
        assert cfg.key_path is None
        assert cfg.ca_cert_path is None

    def test_tls_disabled_no_cert_paths_required(self) -> None:
        """When TLS is disabled, cert paths should not be required."""
        cfg = TLSConfig(enabled=False)
        # Should not raise — paths are optional
        assert cfg.enabled is False

    def test_tls_enabled_with_paths(self) -> None:
        cfg = TLSConfig(
            enabled=True,
            cert_path=Path("/etc/oc-broker/server.crt"),
            key_path=Path("/etc/oc-broker/server.key"),
            ca_cert_path=Path("/etc/oc-broker/ca.crt"),
        )
        assert cfg.enabled is True
        assert cfg.cert_path == Path("/etc/oc-broker/server.crt")

    def test_server_config_tls_disabled(self) -> None:
        """Full server config should work with TLS disabled."""
        cfg = ServerConfig(
            server=ServerBlock(
                tls=TLSConfig(enabled=False),
                logging=LoggingConfig(audit_log=Path("/tmp/audit.log")),
                sessions=SessionConfig(),
                timeouts=TimeoutConfig(),
                sandbox=SandboxConfig(enable_cgroups=False),
            )
        )
        assert cfg.server.tls.enabled is False
        assert cfg.server.tls.cert_path is None


class TestCreateSSLContext:
    def test_creates_ssl_context(self, tmp_path: Path) -> None:
        """Verify create_ssl_context returns a properly configured SSLContext."""
        # Generate self-signed certs for testing
        import subprocess

        ca_key = tmp_path / "ca.key"
        ca_cert = tmp_path / "ca.crt"
        server_key = tmp_path / "server.key"
        server_cert = tmp_path / "server.crt"

        # CA
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-days",
                "1",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_cert),
                "-subj",
                "/CN=Test CA",
            ],
            check=True,
            capture_output=True,
        )

        # Server key + CSR
        server_csr = tmp_path / "server.csr"
        subprocess.run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(server_key),
                "-out",
                str(server_csr),
                "-subj",
                "/CN=Test Server",
            ],
            check=True,
            capture_output=True,
        )

        # Sign server cert
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-days",
                "1",
                "-in",
                str(server_csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(server_cert),
            ],
            check=True,
            capture_output=True,
        )

        ctx = create_ssl_context(server_cert, server_key, ca_cert)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3

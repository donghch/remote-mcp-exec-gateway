"""Tests for filesystem operations (append mode, edge cases)."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.models import (
    PolicyConfig,
    PolicyBlock,
    FileLimits,
    ResourceLimits,
    ConfirmationGates,
    ServerConfig,
    ServerBlock,
    TLSConfig,
    LoggingConfig,
    SessionConfig,
    TimeoutConfig,
    SandboxConfig,
)
from session.manager import SessionManager
from tools.filesystem import FileSystemTools


@pytest.fixture
async def session_manager() -> SessionManager:
    cfg = ServerConfig(
        server=ServerBlock(
            tls=TLSConfig(
                cert_path=Path("/tmp/cert"),
                key_path=Path("/tmp/key"),
                ca_cert_path=Path("/tmp/ca"),
            ),
            logging=LoggingConfig(audit_log=Path("/tmp/audit.log")),
            sessions=SessionConfig(),
            timeouts=TimeoutConfig(),
            sandbox=SandboxConfig(enable_cgroups=False),
        )
    )
    return SessionManager(cfg, cgroup_manager=None)


def _make_policy(allowed_root: Path) -> PolicyConfig:
    return PolicyConfig(
        policy=PolicyBlock(
            allowed_paths=[f"{allowed_root}/**"],
            blocked_paths=[],
            file_limits=FileLimits(),
            resource_limits=ResourceLimits(),
            confirmation_gates=ConfirmationGates(),
        )
    )


class TestFileAppend:
    @pytest.mark.asyncio
    async def test_append_mode(self, session_manager: SessionManager, tmp_path: Path) -> None:
        policy = _make_policy(tmp_path)
        await session_manager.create_session(
            "append-test",
            tmp_path,
            None,
            None,  # type: ignore[arg-type]
        )
        fs = FileSystemTools(session_manager, policy)

        await fs.write_file("append-test", "log.txt", "line1\n")
        await fs.write_file("append-test", "log.txt", "line2\n", mode="append")

        result = await fs.read_file("append-test", "log.txt")
        assert result.content == "line1\nline2\n"

        await session_manager.kill_session("append-test")

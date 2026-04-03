"""Integration tests for command execution and file operations."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from config.loader import load_policy_config
from config.models import PolicyConfig
from security.sanitizer import PathSanitizer
from session.manager import Session, SessionManager
from tools.command import CommandExecutor
from tools.filesystem import FileSystemTools

FIXTURES = Path(__file__).parent.parent / "config"


@pytest.fixture
def policy() -> PolicyConfig:
    return load_policy_config(FIXTURES / "policy.yaml")


@pytest.fixture
async def session_manager(policy: PolicyConfig) -> SessionManager:
    from config.models import ServerConfig, ServerBlock, TLSConfig, LoggingConfig
    from config.models import SessionConfig, TimeoutConfig, SandboxConfig

    cfg = ServerConfig(
        server=ServerBlock(
            tls=TLSConfig(
                cert_path=Path("/tmp/cert"),
                key_path=Path("/tmp/key"),
                ca_cert_path=Path("/tmp/ca"),
            ),
            logging=LoggingConfig(audit_log=Path("/tmp/audit.log")),
            sessions=SessionConfig(max_session_age=3600, max_concurrent=5, cleanup_interval=60),
            timeouts=TimeoutConfig(),
            sandbox=SandboxConfig(enable_cgroups=False),
        )
    )
    mgr = SessionManager(cfg, cgroup_manager=None)
    return mgr


@pytest.fixture
async def tmp_session(session_manager: SessionManager) -> Session:
    with tempfile.TemporaryDirectory() as tmpdir:
        session = await session_manager.create_session(
            session_id="test-session",
            working_dir=Path(tmpdir),
            environment=None,
            client_identity=None,  # type: ignore[arg-type]
        )
        yield session
        await session_manager.kill_session("test-session")


@pytest.fixture
def fs_policy(tmp_path: Path) -> PolicyConfig:
    """Policy that allows the temp directory for filesystem tests."""
    from config.models import PolicyBlock, FileLimits, ResourceLimits, ConfirmationGates

    return PolicyConfig(
        policy=PolicyBlock(
            allowed_paths=[f"{tmp_path}/**"],
            blocked_paths=["**/.ssh/**"],
            file_limits=FileLimits(),
            resource_limits=ResourceLimits(),
            confirmation_gates=ConfirmationGates(),
        )
    )


# ---- Command execution ----


class TestCommandExecution:
    @pytest.mark.asyncio
    async def test_ls_allowed(
        self, session_manager: SessionManager, policy: PolicyConfig, tmp_session: Session
    ) -> None:
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        result = await executor.execute("test-session", ["ls", "/tmp"])
        assert result.success
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_blocked_command(
        self, session_manager: SessionManager, policy: PolicyConfig, tmp_session: Session
    ) -> None:
        from tools.base import ToolError

        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError, match="not in the allowed"):
            await executor.execute("test-session", ["rm", "-rf", "/"])

    @pytest.mark.asyncio
    async def test_session_not_found(
        self, session_manager: SessionManager, policy: PolicyConfig
    ) -> None:
        from tools.base import ToolError

        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError, match="not found"):
            await executor.execute("nonexistent", ["ls"])


# ---- File operations ----


class TestFileOperations:
    @pytest.mark.asyncio
    async def test_write_and_read(self, session_manager: SessionManager, tmp_path: Path) -> None:
        from config.models import PolicyBlock, FileLimits, ResourceLimits, ConfirmationGates

        policy = PolicyConfig(
            policy=PolicyBlock(
                allowed_paths=[f"{tmp_path}/**"],
                blocked_paths=[],
                file_limits=FileLimits(),
                resource_limits=ResourceLimits(),
                confirmation_gates=ConfirmationGates(),
            )
        )
        await session_manager.create_session("fs-test", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)

        write_result = await fs.write_file("fs-test", "test.txt", "hello world")
        assert write_result.success
        assert write_result.bytes_written == 11

        read_result = await fs.read_file("fs-test", "test.txt")
        assert read_result.success
        assert read_result.content == "hello world"

        await session_manager.kill_session("fs-test")

    @pytest.mark.asyncio
    async def test_list_directory(self, session_manager: SessionManager, tmp_path: Path) -> None:
        from config.models import PolicyBlock, FileLimits, ResourceLimits, ConfirmationGates

        policy = PolicyConfig(
            policy=PolicyBlock(
                allowed_paths=[f"{tmp_path}/**"],
                blocked_paths=[],
                file_limits=FileLimits(),
                resource_limits=ResourceLimits(),
                confirmation_gates=ConfirmationGates(),
            )
        )
        await session_manager.create_session("fs-list", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)

        await fs.write_file("fs-list", "a.txt", "aaa")
        await fs.write_file("fs-list", "b.txt", "bbb")

        listing = await fs.list_directory("fs-list", ".")
        assert listing.success
        names = [e.name for e in listing.entries]
        assert "a.txt" in names
        assert "b.txt" in names

        await session_manager.kill_session("fs-list")

    @pytest.mark.asyncio
    async def test_read_nonexistent(self, session_manager: SessionManager, tmp_path: Path) -> None:
        from tools.base import ToolError
        from config.models import PolicyBlock, FileLimits, ResourceLimits, ConfirmationGates

        policy = PolicyConfig(
            policy=PolicyBlock(
                allowed_paths=[f"{tmp_path}/**"],
                blocked_paths=[],
                file_limits=FileLimits(),
                resource_limits=ResourceLimits(),
                confirmation_gates=ConfirmationGates(),
            )
        )
        await session_manager.create_session("fs-noread", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)
        with pytest.raises(ToolError, match="not found"):
            await fs.read_file("fs-noread", "does_not_exist.txt")

        await session_manager.kill_session("fs-noread")

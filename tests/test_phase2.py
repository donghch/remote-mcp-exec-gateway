"""Phase 2 tests: download_file, upload_file, confirmation gate, resource quotas."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from config.models import (
    BannedCommand,
    CommandOverride,
    ConfirmationGates,
    ConfirmationRequired,
    FileLimits,
    PolicyBlock,
    PolicyConfig,
    ResourceLimits,
    SandboxConfig,
    ServerBlock,
    ServerConfig,
    SessionConfig,
    LoggingConfig,
    TimeoutConfig,
    TLSConfig,
)
from session.manager import SessionManager
from tools.base import ToolError
from tools.command import CommandExecutor
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


def _make_policy(
    tmp_path: Path,
    *,
    banned_commands: list[BannedCommand] | None = None,
    confirmation_required: list[ConfirmationRequired] | None = None,
    command_overrides: dict[str, CommandOverride] | None = None,
) -> PolicyConfig:
    """Build a blacklist-based policy scoped to tmp_path.

    All commands are allowed by default.  Pass banned_commands,
    confirmation_required, and/or command_overrides to shape the policy.
    """
    return PolicyConfig(
        policy=PolicyBlock(
            banned_commands=banned_commands or [],
            confirmation_required=confirmation_required or [],
            command_overrides=command_overrides or {},
            allowed_paths=[f"{tmp_path}/**"],
            blocked_paths=[],
            file_limits=FileLimits(),
            resource_limits=ResourceLimits(),
            confirmation_gates=ConfirmationGates(),
        )
    )


# =====================================================================
# Download / Upload
# =====================================================================


class TestDownloadFile:
    @pytest.mark.asyncio
    async def test_single_chunk_download(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        policy = _make_policy(tmp_path)
        await session_manager.create_session("dl", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)

        # Create a test file
        await fs.write_file("dl", "data.bin", "hello world")

        # Download in one chunk
        result = await fs.download_file("dl", "data.bin", chunk_size=1024)
        assert result.success
        assert result.is_complete
        assert result.total_size == 11
        assert base64.b64decode(result.chunk_data) == b"hello world"
        assert result.sha256 != ""
        assert result.filename == "data.bin"

        await session_manager.kill_session("dl")

    @pytest.mark.asyncio
    async def test_multi_chunk_download(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        policy = _make_policy(tmp_path)
        await session_manager.create_session("dl2", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)

        content = "A" * 100
        await fs.write_file("dl2", "big.txt", content)

        # Download in 30-byte chunks
        chunks = []
        offset = 0
        for _ in range(10):
            result = await fs.download_file("dl2", "big.txt", chunk_size=30, offset=offset)
            chunks.append(base64.b64decode(result.chunk_data))
            offset += result.chunk_size
            if result.is_complete:
                break

        assert b"".join(chunks) == content.encode()
        assert result.is_complete

        await session_manager.kill_session("dl2")

    @pytest.mark.asyncio
    async def test_download_nonexistent(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        policy = _make_policy(tmp_path)
        await session_manager.create_session("dl3", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)

        with pytest.raises(ToolError, match="not found"):
            await fs.download_file("dl3", "nope.bin")

        await session_manager.kill_session("dl3")


class TestUploadFile:
    @pytest.mark.asyncio
    async def test_single_chunk_upload(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        policy = _make_policy(tmp_path)
        await session_manager.create_session("ul", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)

        data = base64.b64encode(b"uploaded content").decode()
        result = await fs.upload_file("ul", "uploaded.txt", chunk_data=data, is_last=True)

        assert result.success
        assert result.is_complete
        assert result.bytes_received == 16
        assert result.sha256 != ""

        # Verify file exists and content matches
        read_result = await fs.read_file("ul", "uploaded.txt")
        assert read_result.content == "uploaded content"

        await session_manager.kill_session("ul")

    @pytest.mark.asyncio
    async def test_multi_chunk_upload(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        policy = _make_policy(tmp_path)
        await session_manager.create_session("ul2", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)

        part1 = base64.b64encode(b"hello ").decode()
        part2 = base64.b64encode(b"world").decode()

        r1 = await fs.upload_file("ul2", "multi.txt", chunk_data=part1, chunk_offset=0)
        assert not r1.is_complete
        transfer_id = r1.transfer_id

        r2 = await fs.upload_file(
            "ul2",
            "multi.txt",
            chunk_data=part2,
            transfer_id=transfer_id,
            chunk_offset=6,
            is_last=True,
        )
        assert r2.is_complete
        assert r2.bytes_received == 11

        read_result = await fs.read_file("ul2", "multi.txt")
        assert read_result.content == "hello world"

        await session_manager.kill_session("ul2")

    @pytest.mark.asyncio
    async def test_upload_offset_mismatch(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        policy = _make_policy(tmp_path)
        await session_manager.create_session("ul3", tmp_path, None, None)  # type: ignore[arg-type]
        fs = FileSystemTools(session_manager, policy)

        part1 = base64.b64encode(b"first").decode()
        r1 = await fs.upload_file("ul3", "bad.txt", chunk_data=part1, chunk_offset=0)
        transfer_id = r1.transfer_id

        # Send second chunk with wrong offset (should be 5, sending 0)
        part2 = base64.b64encode(b"second").decode()
        with pytest.raises(ToolError, match="offset mismatch"):
            await fs.upload_file(
                "ul3",
                "bad.txt",
                chunk_data=part2,
                transfer_id=transfer_id,
                chunk_offset=0,
            )

        await session_manager.kill_session("ul3")


# =====================================================================
# Confirmation Gate
# =====================================================================


class TestConfirmationGate:
    @pytest.mark.asyncio
    async def test_confirmation_required_blocks(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        # Arrange: python3 requires confirmation
        policy = _make_policy(
            tmp_path,
            confirmation_required=[
                ConfirmationRequired(name="python3", reason="Can execute arbitrary code"),
            ],
        )
        await session_manager.create_session("cg", tmp_path, None, None)  # type: ignore[arg-type]
        executor = CommandExecutor(session_manager, policy, user_ctx=None)

        # Act + Assert: confirm=False → blocked
        with pytest.raises(ToolError, match="requires confirmation"):
            await executor.execute("cg", ["python3", "--version"])

        await session_manager.kill_session("cg")

    @pytest.mark.asyncio
    async def test_confirmation_passed(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        # Arrange: ls requires confirmation
        policy = _make_policy(
            tmp_path,
            confirmation_required=[
                ConfirmationRequired(name="ls", reason="Lists directory contents"),
            ],
        )
        await session_manager.create_session("cg2", tmp_path, None, None)  # type: ignore[arg-type]
        executor = CommandExecutor(session_manager, policy, user_ctx=None)

        # Act: confirm=True → allowed
        result = await executor.execute("cg2", ["ls"], confirm=True)
        assert result.success

        await session_manager.kill_session("cg2")

    @pytest.mark.asyncio
    async def test_no_confirmation_needed(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        # Arrange: ls is NOT in confirmation_required — runs freely
        policy = _make_policy(tmp_path)
        await session_manager.create_session("cg3", tmp_path, None, None)  # type: ignore[arg-type]
        executor = CommandExecutor(session_manager, policy, user_ctx=None)

        # Act: no confirm flag needed
        result = await executor.execute("cg3", ["ls"])
        assert result.success

        await session_manager.kill_session("cg3")


# =====================================================================
# Resource Quota Override
# =====================================================================


class TestResourceOverride:
    def test_resource_override_stored(self) -> None:
        """Verify CommandOverride stores resource_override correctly."""
        override = CommandOverride(
            max_args=10,
            resource_override=ResourceLimits(
                memory_max="268435456",  # 256MB
                pids_max=16,
                cpu_quota_us=50000,
            ),
        )
        assert override.resource_override is not None
        assert override.resource_override.memory_max == "268435456"
        assert override.resource_override.pids_max == 16

    @pytest.mark.asyncio
    async def test_execute_without_cgroup_mgr(
        self, session_manager: SessionManager, tmp_path: Path
    ) -> None:
        """Resource override is silently skipped when cgroup manager is unavailable."""
        policy = _make_policy(
            tmp_path,
            command_overrides={
                "ls": CommandOverride(
                    max_args=10,
                    resource_override=ResourceLimits(memory_max="128M", pids_max=8),
                ),
            },
        )
        await session_manager.create_session("rq", tmp_path, None, None)  # type: ignore[arg-type]
        executor = CommandExecutor(session_manager, policy, user_ctx=None, cgroup_manager=None)

        # Should still work — override is skipped gracefully
        result = await executor.execute("rq", ["ls", "/tmp"])
        assert result.success

        await session_manager.kill_session("rq")

"""Integration tests for command execution with blacklist security model.

Tests verify CommandExecutor behavior against the blacklist policy:
- All commands allowed by default (blacklist model)
- Banned commands are blocked with POLICY_COMMAND_BLOCKED
- Confirmation-required commands need confirm=True
- Command overrides (max_args, allowed_prefixes) are enforced
"""

from __future__ import annotations

import tempfile
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
)
from config.loader import load_policy_config
from session.manager import Session, SessionManager
from tools.base import ErrorCode, ToolError
from tools.command import CommandExecutor

FIXTURES = Path(__file__).parent.parent / "config"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_server_config() -> ServerConfig:
    """Minimal server config for test session manager."""
    return ServerConfig(
        server=ServerBlock(
            logging=LoggingConfig(audit_log=Path("/tmp/audit.log")),
            sessions=SessionConfig(max_session_age=3600, max_concurrent=5, cleanup_interval=60),
            timeouts=TimeoutConfig(),
            sandbox=SandboxConfig(enable_cgroups=False),
        )
    )


@pytest.fixture
def policy() -> PolicyConfig:
    """Load the real policy.yaml (blacklist model)."""
    return load_policy_config(FIXTURES / "policy.yaml")


@pytest.fixture
def inline_policy() -> PolicyConfig:
    """Inline policy for targeted tests — bans rm/sudo, confirms curl, overrides git."""
    return PolicyConfig(
        policy=PolicyBlock(
            banned_commands=[
                BannedCommand(name="rm", reason="Destructive file deletion"),
                BannedCommand(name="sudo", reason="Privilege escalation"),
            ],
            confirmation_required=[
                ConfirmationRequired(name="curl", reason="Can download arbitrary content"),
            ],
            command_overrides={
                "git": CommandOverride(
                    max_args=5,
                    allowed_prefixes=["status", "log", "diff", "init"],
                ),
            },
            allowed_paths=["/tmp/**"],
            blocked_paths=[],
            file_limits=FileLimits(),
            resource_limits=ResourceLimits(),
            confirmation_gates=ConfirmationGates(),
        )
    )


@pytest.fixture
async def session_manager() -> SessionManager:
    """Session manager with no cgroup support."""
    mgr = SessionManager(_make_server_config(), cgroup_manager=None)
    return mgr


@pytest.fixture
async def tmp_session(session_manager: SessionManager) -> Session:
    """Create a temporary session, cleaned up after test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        session = await session_manager.create_session(
            session_id="test-session",
            working_dir=Path(tmpdir),
            environment=None,
        )
        yield session
        await session_manager.kill_session("test-session")


# ---------------------------------------------------------------------------
# Blacklist model: non-banned commands execute successfully
# ---------------------------------------------------------------------------


class TestAllowedCommands:
    """Any command NOT in banned_commands should execute successfully."""

    @pytest.mark.asyncio
    async def test_ls_allowed(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """ls is not banned — should run and return exit_code 0."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        result = await executor.execute("test-session", ["ls", "/tmp"])
        assert result.success
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_echo_allowed(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """echo is not banned — should run and produce output."""
        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        result = await executor.execute("test-session", ["echo", "hello"])
        assert result.success
        assert result.exit_code == 0
        assert "hello" in (result.stdout or "")

    @pytest.mark.asyncio
    async def test_cat_allowed(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """cat is not banned — should run even if file doesn't exist (non-zero exit)."""
        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        result = await executor.execute("test-session", ["cat", "/tmp/no_such_file"])
        # cat returns non-zero for missing file, but the command itself is allowed
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Banned commands raise ToolError with POLICY_COMMAND_BLOCKED
# ---------------------------------------------------------------------------


class TestBannedCommands:
    """Commands in banned_commands must be blocked with POLICY_COMMAND_BLOCKED."""

    @pytest.mark.asyncio
    async def test_rm_banned(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """rm is in the banned list — must raise POLICY_COMMAND_BLOCKED."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", ["rm", "-rf", "/tmp"])
        assert exc_info.value.code == ErrorCode.POLICY_COMMAND_BLOCKED

    @pytest.mark.asyncio
    async def test_sudo_banned(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """sudo is in the banned list — must raise POLICY_COMMAND_BLOCKED."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", ["sudo", "ls"])
        assert exc_info.value.code == ErrorCode.POLICY_COMMAND_BLOCKED

    @pytest.mark.asyncio
    async def test_dd_banned(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """dd is in the banned list — must raise POLICY_COMMAND_BLOCKED."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", ["dd", "if=/dev/zero", "of=/dev/sda"])
        assert exc_info.value.code == ErrorCode.POLICY_COMMAND_BLOCKED

    @pytest.mark.asyncio
    async def test_shutdown_banned(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """shutdown is in the banned list — must raise POLICY_COMMAND_BLOCKED."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", ["shutdown", "-h", "now"])
        assert exc_info.value.code == ErrorCode.POLICY_COMMAND_BLOCKED

    @pytest.mark.asyncio
    async def test_inline_banned_command(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """Verify inline policy bans work (rm, sudo)."""
        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", ["sudo", "cat", "/etc/shadow"])
        assert exc_info.value.code == ErrorCode.POLICY_COMMAND_BLOCKED


# ---------------------------------------------------------------------------
# Confirmation required commands
# ---------------------------------------------------------------------------


class TestConfirmationRequired:
    """Commands in confirmation_required must block without confirm=True."""

    @pytest.mark.asyncio
    async def test_curl_blocked_without_confirm(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """curl requires confirmation — blocked when confirm=False (default)."""
        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", ["curl", "https://example.com"])
        assert exc_info.value.code == ErrorCode.POLICY_CONFIRMATION_REQUIRED

    @pytest.mark.asyncio
    async def test_curl_allowed_with_confirm(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """curl requires confirmation — allowed when confirm=True."""
        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        # curl will fail to connect in test env, but the command itself should be allowed
        result = await executor.execute(
            "test-session",
            ["curl", "--max-time", "1", "https://192.0.2.1"],  # RFC 5737 — non-routable
            timeout_seconds=5,
            confirm=True,
        )
        # Command was allowed to run (not blocked by policy)
        # It may fail due to network, but that's a CMD failure, not a policy block
        assert result.error_code != ErrorCode.POLICY_COMMAND_BLOCKED
        assert result.error_code != ErrorCode.POLICY_CONFIRMATION_REQUIRED

    @pytest.mark.asyncio
    async def test_python3_blocked_without_confirm(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """python3 requires confirmation — blocked when confirm=False."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", ["python3", "--version"])
        assert exc_info.value.code == ErrorCode.POLICY_CONFIRMATION_REQUIRED

    @pytest.mark.asyncio
    async def test_python3_allowed_with_confirm(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """python3 requires confirmation — allowed when confirm=True."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        result = await executor.execute("test-session", ["python3", "--version"], confirm=True)
        assert result.success
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Session not found still raises SESSION_NOT_FOUND
# ---------------------------------------------------------------------------


class TestSessionNotFound:
    """Session validation must still work — nonexistent session raises SESSION_NOT_FOUND."""

    @pytest.mark.asyncio
    async def test_session_not_found(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
    ) -> None:
        """Executing on a nonexistent session raises SESSION_NOT_FOUND."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("nonexistent-session", ["ls"])
        assert exc_info.value.code == ErrorCode.SESSION_NOT_FOUND

    @pytest.mark.asyncio
    async def test_session_not_found_message(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
    ) -> None:
        """Error message includes the session id."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError, match="nonexistent-session") as exc_info:
            await executor.execute("nonexistent-session", ["echo", "hi"])
        assert exc_info.value.code == ErrorCode.SESSION_NOT_FOUND


# ---------------------------------------------------------------------------
# Command overrides (max_args, allowed_prefixes)
# ---------------------------------------------------------------------------


class TestCommandOverrides:
    """Per-command overrides must be enforced: max_args, allowed_prefixes."""

    @pytest.mark.asyncio
    async def test_git_allowed_subcommand(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """git status is in allowed_prefixes — should execute."""
        # Initialize a git repo in the temp directory
        init_executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        await init_executor.execute("test-session", ["git", "init"])

        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        result = await executor.execute("test-session", ["git", "status"])
        assert result.success
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_git_blocked_subcommand(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """git push is NOT in allowed_prefixes — must raise POLICY_COMMAND_BLOCKED."""
        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", ["git", "push"])
        assert exc_info.value.code == ErrorCode.POLICY_COMMAND_BLOCKED

    @pytest.mark.asyncio
    async def test_git_exceeds_max_args(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """git with more than max_args (5) should raise POLICY_COMMAND_BLOCKED."""
        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        too_many = ["git", "log", "--oneline", "--all", "--graph", "--decorate", "--stat"]
        assert len(too_many) > 5
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", too_many)
        assert exc_info.value.code == ErrorCode.POLICY_COMMAND_BLOCKED

    @pytest.mark.asyncio
    async def test_git_within_max_args(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """git status with args within max_args (5) should execute."""
        # Initialize a git repo in the temp directory
        init_executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        await init_executor.execute("test-session", ["git", "init"])

        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        result = await executor.execute("test-session", ["git", "status", "--short"])
        assert result.success
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_no_override_allows_any_subcommand(
        self,
        session_manager: SessionManager,
        inline_policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """Commands without overrides have no subcommand restrictions."""
        executor = CommandExecutor(session_manager, inline_policy, user_ctx=None)
        # ls has no override — any args are fine (within default max_args)
        result = await executor.execute("test-session", ["ls", "-la", "/tmp"])
        assert result.success
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Empty argv edge case
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_argv_raises(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        tmp_session: Session,
    ) -> None:
        """Empty argv must raise CMD_EXEC_FAILED."""
        executor = CommandExecutor(session_manager, policy, user_ctx=None)
        with pytest.raises(ToolError) as exc_info:
            await executor.execute("test-session", [])
        assert exc_info.value.code == ErrorCode.CMD_EXEC_FAILED


# ---------------------------------------------------------------------------
# File operations (unchanged — not affected by blacklist model)
# ---------------------------------------------------------------------------


class TestFileOperations:
    @pytest.mark.asyncio
    async def test_write_and_read(self, session_manager: SessionManager, tmp_path: Path) -> None:
        from security.sanitizer import PathSanitizer
        from tools.filesystem import FileSystemTools

        policy = PolicyConfig(
            policy=PolicyBlock(
                allowed_paths=[f"{tmp_path}/**"],
                blocked_paths=[],
                file_limits=FileLimits(),
                resource_limits=ResourceLimits(),
                confirmation_gates=ConfirmationGates(),
            )
        )
        await session_manager.create_session("fs-test", tmp_path, None)
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
        from tools.filesystem import FileSystemTools

        policy = PolicyConfig(
            policy=PolicyBlock(
                allowed_paths=[f"{tmp_path}/**"],
                blocked_paths=[],
                file_limits=FileLimits(),
                resource_limits=ResourceLimits(),
                confirmation_gates=ConfirmationGates(),
            )
        )
        await session_manager.create_session("fs-list", tmp_path, None)
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
        from tools.filesystem import FileSystemTools

        policy = PolicyConfig(
            policy=PolicyBlock(
                allowed_paths=[f"{tmp_path}/**"],
                blocked_paths=[],
                file_limits=FileLimits(),
                resource_limits=ResourceLimits(),
                confirmation_gates=ConfirmationGates(),
            )
        )
        await session_manager.create_session("fs-noread", tmp_path, None)
        fs = FileSystemTools(session_manager, policy)
        with pytest.raises(ToolError, match="not found"):
            await fs.read_file("fs-noread", "does_not_exist.txt")

        await session_manager.kill_session("fs-noread")

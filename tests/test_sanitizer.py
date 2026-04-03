"""Unit tests for path sanitization and command blacklist enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.loader import load_policy_config
from config.models import PolicyConfig
from security.sanitizer import CommandSanitizer, PathSanitizer

FIXTURES = Path(__file__).parent.parent / "config"


@pytest.fixture
def policy() -> PolicyConfig:
    return load_policy_config(FIXTURES / "policy.yaml")


@pytest.fixture
def path_sanitizer() -> PathSanitizer:
    """Path sanitizer with absolute patterns for testing."""
    return PathSanitizer(
        allowed_patterns=["/home/oc-runner/workspace/**", "/tmp/**"],
        blocked_patterns=["**/.ssh/**", "**/.env", "**/etc/passwd"],
    )


@pytest.fixture
def cmd_sanitizer(policy: PolicyConfig) -> CommandSanitizer:
    return CommandSanitizer(policy)


# ---- Path sanitization ----


class TestPathSanitizer:
    def test_allowed_path(self, path_sanitizer: PathSanitizer) -> None:
        result = path_sanitizer.sanitize("/home/oc-runner/workspace/src/main.py")
        assert result.is_valid

    def test_blocked_ssh(self, path_sanitizer: PathSanitizer) -> None:
        result = path_sanitizer.sanitize("/home/user/.ssh/id_rsa")
        assert not result.is_valid
        assert "blocked" in (result.rejection_reason or "").lower()

    def test_blocked_env(self, path_sanitizer: PathSanitizer) -> None:
        result = path_sanitizer.sanitize("/home/oc-runner/workspace/.env")
        assert not result.is_valid

    def test_outside_workspace(self, path_sanitizer: PathSanitizer) -> None:
        result = path_sanitizer.sanitize("/etc/passwd")
        assert not result.is_valid
        # /etc/passwd matches the blocked pattern **/etc/passwd
        assert (
            "blocked" in (result.rejection_reason or "").lower()
            or "outside" in (result.rejection_reason or "").lower()
        )

    def test_path_traversal(self, path_sanitizer: PathSanitizer) -> None:
        result = path_sanitizer.sanitize("/home/oc-runner/workspace/../../etc/passwd")
        # Resolved path is /etc/passwd which is outside allowed paths
        assert not result.is_valid


# ---- Command blacklist enforcement ----


class TestCommandSanitizerAllowed:
    """Any command not in the banned list should pass validation."""

    def test_common_tool_passes(self, cmd_sanitizer: CommandSanitizer) -> None:
        """ls is not banned and not in confirmation_required — should pass."""
        result = cmd_sanitizer.validate(["ls", "-la"])
        assert result.command_name == "ls"
        assert result.argv == ["ls", "-la"]
        assert not result.requires_confirmation
        assert result.confirmation_reason == ""
        assert result.override is None

    def test_git_passes_with_override(self, cmd_sanitizer: CommandSanitizer) -> None:
        """git has an override but is not banned — should pass and attach override."""
        result = cmd_sanitizer.validate(["git", "status"])
        assert result.command_name == "git"
        assert result.argv == ["git", "status"]
        assert not result.requires_confirmation
        assert result.override is not None
        assert result.override.max_args == 20

    def test_unknown_command_passes(self, cmd_sanitizer: CommandSanitizer) -> None:
        """An arbitrary command not in any list should pass (blacklist model)."""
        result = cmd_sanitizer.validate(["htop"])
        assert result.command_name == "htop"
        assert not result.requires_confirmation


class TestCommandSanitizerBanned:
    """Banned commands must be rejected with a clear reason."""

    def test_rm_banned(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="banned.*Destructive file deletion"):
            cmd_sanitizer.validate(["rm", "-rf", "/"])

    def test_sudo_banned(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="banned.*Privilege escalation"):
            cmd_sanitizer.validate(["sudo", "apt", "update"])

    def test_dd_banned(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="banned.*Raw disk"):
            cmd_sanitizer.validate(["dd", "if=/dev/sda"])

    def test_shutdown_banned(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="banned.*shutdown"):
            cmd_sanitizer.validate(["shutdown", "-h", "now"])

    def test_kill_banned(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="banned.*kill_process"):
            cmd_sanitizer.validate(["kill", "-9", "1234"])

    def test_chmod_banned(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="banned.*Permission"):
            cmd_sanitizer.validate(["chmod", "777", "/tmp/x"])


class TestCommandSanitizerConfirmation:
    """Commands in confirmation_required must gate on the confirm flag."""

    def test_python3_blocked_without_confirm(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="requires confirmation.*arbitrary code"):
            cmd_sanitizer.validate(["python3", "--version"])

    def test_python3_passes_with_confirm(self, cmd_sanitizer: CommandSanitizer) -> None:
        result = cmd_sanitizer.validate(["python3", "--version"], confirm=True)
        assert result.command_name == "python3"
        assert result.requires_confirmation
        assert "arbitrary code" in result.confirmation_reason

    def test_curl_blocked_without_confirm(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="requires confirmation"):
            cmd_sanitizer.validate(["curl", "https://example.com"])

    def test_curl_passes_with_confirm(self, cmd_sanitizer: CommandSanitizer) -> None:
        result = cmd_sanitizer.validate(["curl", "https://example.com"], confirm=True)
        assert result.command_name == "curl"
        assert result.requires_confirmation

    def test_pip_blocked_without_confirm(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="requires confirmation.*arbitrary packages"):
            cmd_sanitizer.validate(["pip", "install", "numpy"])

    def test_wget_passes_with_confirm(self, cmd_sanitizer: CommandSanitizer) -> None:
        result = cmd_sanitizer.validate(["wget", "https://example.com/file"], confirm=True)
        assert result.command_name == "wget"
        assert result.requires_confirmation


class TestCommandSanitizerArgCount:
    """Arg count enforcement via command_overrides."""

    def test_git_within_arg_limit(self, cmd_sanitizer: CommandSanitizer) -> None:
        """git has max_args=20 in overrides — 10 args should pass."""
        argv = [
            "git",
            "log",
            "--oneline",
            "--graph",
            "--all",
            "--decorate",
            "--date=short",
            "--since=2025-01-01",
            "--author=test",
            "--no-merges",
        ]
        result = cmd_sanitizer.validate(argv)
        assert result.command_name == "git"

    def test_git_exceeds_arg_limit(self, cmd_sanitizer: CommandSanitizer) -> None:
        """git with 22 args exceeds max_args=20."""
        argv = ["git", "log"] + [f"--flag{i}" for i in range(20)]
        with pytest.raises(ValueError, match="exceeds max args"):
            cmd_sanitizer.validate(argv)

    def test_find_custom_arg_limit(self, cmd_sanitizer: CommandSanitizer) -> None:
        """find has max_args=15 in overrides."""
        flags: list[str] = []
        for i in range(8):
            flags.extend(["-name", f"*.{i}"])
        argv = ["find", "/tmp"] + flags
        # 1 + 1 + 16 = 18 args > 15
        with pytest.raises(ValueError, match="exceeds max args"):
            cmd_sanitizer.validate(argv)

    def test_default_arg_limit_for_no_override(self, cmd_sanitizer: CommandSanitizer) -> None:
        """Commands without overrides get default max_args=20."""
        argv = ["echo"] + [f"arg{i}" for i in range(21)]
        with pytest.raises(ValueError, match="exceeds max args"):
            cmd_sanitizer.validate(argv)


class TestCommandSanitizerSubcommandPrefix:
    """Subcommand prefix enforcement via command_overrides.allowed_prefixes."""

    def test_git_allowed_subcommand(self, cmd_sanitizer: CommandSanitizer) -> None:
        """git status is in allowed_prefixes — should pass."""
        result = cmd_sanitizer.validate(["git", "status"])
        assert result.command_name == "git"

    def test_git_blocked_subcommand(self, cmd_sanitizer: CommandSanitizer) -> None:
        """git push is NOT in allowed_prefixes — should fail."""
        with pytest.raises(ValueError, match="Subcommand 'push' is not allowed"):
            cmd_sanitizer.validate(["git", "push"])

    def test_git_rebase_blocked(self, cmd_sanitizer: CommandSanitizer) -> None:
        """git rebase is NOT in allowed_prefixes."""
        with pytest.raises(ValueError, match="Subcommand 'rebase' is not allowed"):
            cmd_sanitizer.validate(["git", "rebase", "-i", "HEAD~3"])

    def test_git_clone_allowed(self, cmd_sanitizer: CommandSanitizer) -> None:
        """git clone is in allowed_prefixes — should pass."""
        result = cmd_sanitizer.validate(["git", "clone", "https://example.com/repo"])
        assert result.command_name == "git"

    def test_no_prefix_check_without_override(self, cmd_sanitizer: CommandSanitizer) -> None:
        """Commands without overrides have no subcommand restrictions."""
        result = cmd_sanitizer.validate(["ls", "--all", "--long"])
        assert result.command_name == "ls"


class TestCommandSanitizerEmptyArgv:
    """Empty argv must be rejected."""

    def test_empty_argv(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="Empty"):
            cmd_sanitizer.validate([])


class TestCommandSanitizerHelpers:
    """is_banned() and requires_confirmation() helper methods."""

    def test_is_banned_true(self, cmd_sanitizer: CommandSanitizer) -> None:
        assert cmd_sanitizer.is_banned("rm")
        assert cmd_sanitizer.is_banned("sudo")
        assert cmd_sanitizer.is_banned("dd")
        assert cmd_sanitizer.is_banned("shutdown")

    def test_is_banned_false(self, cmd_sanitizer: CommandSanitizer) -> None:
        assert not cmd_sanitizer.is_banned("git")
        assert not cmd_sanitizer.is_banned("ls")
        assert not cmd_sanitizer.is_banned("python3")

    def test_requires_confirmation_true(self, cmd_sanitizer: CommandSanitizer) -> None:
        assert cmd_sanitizer.requires_confirmation("python3")
        assert cmd_sanitizer.requires_confirmation("curl")
        assert cmd_sanitizer.requires_confirmation("pip")
        assert cmd_sanitizer.requires_confirmation("wget")

    def test_requires_confirmation_false(self, cmd_sanitizer: CommandSanitizer) -> None:
        assert not cmd_sanitizer.requires_confirmation("git")
        assert not cmd_sanitizer.requires_confirmation("ls")
        assert not cmd_sanitizer.requires_confirmation("rm")  # banned, not confirmation_required

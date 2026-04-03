"""Unit tests for config loading and validation.

Covers the blacklist security model:
- banned_commands list blocks dangerous commands
- confirmation_required list gates risky commands
- command_overrides dict provides per-command restrictions
- server.yaml loading is unchanged
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from config.loader import load_policy_config, load_server_config
from config.models import (
    BannedCommand,
    CommandOverride,
    ConfirmationRequired,
    PolicyConfig,
    ServerConfig,
)

FIXTURES = Path(__file__).parent.parent / "config"


# =====================================================================
# Server config — unchanged from whitelist era
# =====================================================================


class TestServerConfig:
    """server.yaml structure is unchanged — verify it still loads."""

    def test_load_server_config(self) -> None:
        # Arrange
        path = FIXTURES / "server.yaml"

        # Act
        cfg = load_server_config(path)

        # Assert
        assert isinstance(cfg, ServerConfig)
        assert cfg.server.port == 8080
        assert cfg.server.host == "127.0.0.1"
        assert cfg.server.tls.enabled is False
        assert cfg.server.tls.min_version == "TLSv1.3"
        assert cfg.server.sessions.max_session_age == 1800

    def test_server_config_missing_file(self, tmp_path: Path) -> None:
        # Arrange — path that does not exist
        missing = tmp_path / "nonexistent.yaml"

        # Act / Assert
        with pytest.raises(FileNotFoundError, match="not found"):
            load_server_config(missing)

    def test_server_config_empty_file(self, tmp_path: Path) -> None:
        # Arrange
        p = tmp_path / "empty.yaml"
        p.write_text("")

        # Act / Assert
        with pytest.raises(ValueError, match="empty"):
            load_server_config(p)

    def test_server_config_validation_error(self, tmp_path: Path) -> None:
        # Arrange — port out of range
        p = tmp_path / "bad.yaml"
        p.write_text(yaml.dump({"server": {"port": -1}}))

        # Act / Assert
        with pytest.raises(Exception):
            load_server_config(p)


# =====================================================================
# Policy config — blacklist model
# =====================================================================


class TestPolicyConfigLoading:
    """policy.yaml loads and validates under the new blacklist structure."""

    def test_load_policy_config(self) -> None:
        # Arrange
        path = FIXTURES / "policy.yaml"

        # Act
        cfg = load_policy_config(path)

        # Assert — top-level shape
        assert isinstance(cfg, PolicyConfig)
        assert isinstance(cfg.policy.banned_commands, list)
        assert isinstance(cfg.policy.confirmation_required, list)
        assert isinstance(cfg.policy.command_overrides, dict)

    def test_policy_config_missing_file(self, tmp_path: Path) -> None:
        # Arrange
        missing = tmp_path / "no_policy.yaml"

        # Act / Assert
        with pytest.raises(FileNotFoundError, match="not found"):
            load_policy_config(missing)

    def test_policy_config_empty_file(self, tmp_path: Path) -> None:
        # Arrange
        p = tmp_path / "empty.yaml"
        p.write_text("")

        # Act / Assert
        with pytest.raises(ValueError, match="empty"):
            load_policy_config(p)


class TestBannedCommands:
    """banned_commands list is populated with expected dangerous commands."""

    @pytest.fixture
    def policy(self) -> PolicyConfig:
        return load_policy_config(FIXTURES / "policy.yaml")

    def test_banned_commands_is_list(self, policy: PolicyConfig) -> None:
        # Assert
        assert isinstance(policy.policy.banned_commands, list)
        assert len(policy.policy.banned_commands) > 0

    def test_banned_commands_contain_rm(self, policy: PolicyConfig) -> None:
        # Assert — rm is banned for destructive file deletion
        names = [cmd.name for cmd in policy.policy.banned_commands]
        assert "rm" in names

    def test_banned_commands_contain_sudo(self, policy: PolicyConfig) -> None:
        # Assert — sudo is banned for privilege escalation
        names = [cmd.name for cmd in policy.policy.banned_commands]
        assert "sudo" in names

    def test_banned_commands_contain_su(self, policy: PolicyConfig) -> None:
        # Assert — su is banned for privilege escalation
        names = [cmd.name for cmd in policy.policy.banned_commands]
        assert "su" in names

    def test_banned_commands_contain_dd(self, policy: PolicyConfig) -> None:
        # Assert — dd is banned for raw disk operations
        names = [cmd.name for cmd in policy.policy.banned_commands]
        assert "dd" in names

    def test_banned_commands_contain_shutdown(self, policy: PolicyConfig) -> None:
        # Assert
        names = [cmd.name for cmd in policy.policy.banned_commands]
        assert "shutdown" in names

    def test_banned_commands_contain_kill_variants(self, policy: PolicyConfig) -> None:
        # Assert — kill, pkill, killall all banned
        names = [cmd.name for cmd in policy.policy.banned_commands]
        assert "kill" in names
        assert "pkill" in names
        assert "killall" in names

    def test_banned_commands_have_reasons(self, policy: PolicyConfig) -> None:
        # Assert — every banned command has a non-empty reason
        for cmd in policy.policy.banned_commands:
            assert isinstance(cmd, BannedCommand)
            assert cmd.name, "banned command must have a name"
            assert cmd.reason, f"banned command '{cmd.name}' must have a reason"

    def test_banned_command_model_fields(self) -> None:
        # Arrange / Act
        cmd = BannedCommand(name="test", reason="testing")

        # Assert
        assert cmd.name == "test"
        assert cmd.reason == "testing"

    def test_banned_command_default_reason(self) -> None:
        # Arrange / Act
        cmd = BannedCommand(name="test")

        # Assert — reason defaults to empty string
        assert cmd.reason == ""


class TestConfirmationRequired:
    """confirmation_required list gates risky commands behind user consent."""

    @pytest.fixture
    def policy(self) -> PolicyConfig:
        return load_policy_config(FIXTURES / "policy.yaml")

    def test_confirmation_required_is_list(self, policy: PolicyConfig) -> None:
        # Assert
        assert isinstance(policy.policy.confirmation_required, list)
        assert len(policy.policy.confirmation_required) > 0

    def test_confirmation_required_contains_python3(self, policy: PolicyConfig) -> None:
        # Assert — python3 can execute arbitrary code
        names = [cmd.name for cmd in policy.policy.confirmation_required]
        assert "python3" in names

    def test_confirmation_required_contains_curl(self, policy: PolicyConfig) -> None:
        # Assert — curl can download arbitrary content
        names = [cmd.name for cmd in policy.policy.confirmation_required]
        assert "curl" in names

    def test_confirmation_required_contains_wget(self, policy: PolicyConfig) -> None:
        # Assert
        names = [cmd.name for cmd in policy.policy.confirmation_required]
        assert "wget" in names

    def test_confirmation_required_contains_pip(self, policy: PolicyConfig) -> None:
        # Assert — pip can install arbitrary packages
        names = [cmd.name for cmd in policy.policy.confirmation_required]
        assert "pip" in names

    def test_confirmation_required_contains_ssh(self, policy: PolicyConfig) -> None:
        # Assert — ssh is remote access
        names = [cmd.name for cmd in policy.policy.confirmation_required]
        assert "ssh" in names

    def test_confirmation_required_have_reasons(self, policy: PolicyConfig) -> None:
        # Assert — every entry has a non-empty reason
        for cmd in policy.policy.confirmation_required:
            assert isinstance(cmd, ConfirmationRequired)
            assert cmd.name, "confirmation_required entry must have a name"
            assert cmd.reason, f"confirmation_required '{cmd.name}' must have a reason"

    def test_confirmation_required_model_fields(self) -> None:
        # Arrange / Act
        cmd = ConfirmationRequired(name="curl", reason="downloads stuff")

        # Assert
        assert cmd.name == "curl"
        assert cmd.reason == "downloads stuff"

    def test_no_overlap_with_banned(self, policy: PolicyConfig) -> None:
        # Assert — a command cannot be both banned and confirmation_required
        banned_names = {cmd.name for cmd in policy.policy.banned_commands}
        confirm_names = {cmd.name for cmd in policy.policy.confirmation_required}
        overlap = banned_names & confirm_names
        assert not overlap, f"commands in both banned and confirmation_required: {overlap}"


class TestCommandOverrides:
    """command_overrides dict provides per-command resource restrictions."""

    @pytest.fixture
    def policy(self) -> PolicyConfig:
        return load_policy_config(FIXTURES / "policy.yaml")

    def test_command_overrides_is_dict(self, policy: PolicyConfig) -> None:
        # Assert
        assert isinstance(policy.policy.command_overrides, dict)
        assert len(policy.policy.command_overrides) > 0

    def test_git_override_exists(self, policy: PolicyConfig) -> None:
        # Assert
        assert "git" in policy.policy.command_overrides

    def test_git_override_has_prefixes(self, policy: PolicyConfig) -> None:
        # Arrange
        git = policy.policy.command_overrides["git"]

        # Assert
        assert isinstance(git, CommandOverride)
        assert git.allowed_prefixes is not None
        assert "status" in git.allowed_prefixes
        assert "log" in git.allowed_prefixes
        assert "diff" in git.allowed_prefixes
        assert "clone" in git.allowed_prefixes
        assert "commit" in git.allowed_prefixes

    def test_git_override_max_args(self, policy: PolicyConfig) -> None:
        # Assert
        git = policy.policy.command_overrides["git"]
        assert git.max_args == 20

    def test_find_override_exists(self, policy: PolicyConfig) -> None:
        # Assert
        assert "find" in policy.policy.command_overrides

    def test_find_override_max_args(self, policy: PolicyConfig) -> None:
        # Assert
        find = policy.policy.command_overrides["find"]
        assert isinstance(find, CommandOverride)
        assert find.max_args == 15

    def test_override_model_defaults(self) -> None:
        # Arrange / Act — default CommandOverride
        override = CommandOverride()

        # Assert
        assert override.max_args == 20
        assert override.allowed_prefixes is None
        assert override.resource_override is None

    def test_override_model_with_prefixes(self) -> None:
        # Arrange / Act
        override = CommandOverride(max_args=5, allowed_prefixes=["a", "b"])

        # Assert
        assert override.max_args == 5
        assert override.allowed_prefixes == ["a", "b"]


class TestPolicyUnchangedSections:
    """Sections that did NOT change from the whitelist era still load correctly."""

    @pytest.fixture
    def policy(self) -> PolicyConfig:
        return load_policy_config(FIXTURES / "policy.yaml")

    def test_allowed_paths(self, policy: PolicyConfig) -> None:
        # Assert - sessions now default to user's home directory
        assert "~//**" in policy.policy.allowed_paths
        assert "/home/**" in policy.policy.allowed_paths
        assert "/tmp/**" in policy.policy.allowed_paths

    def test_blocked_paths(self, policy: PolicyConfig) -> None:
        # Assert
        assert any(".ssh" in p for p in policy.policy.blocked_paths)
        assert any(".env" in p for p in policy.policy.blocked_paths)

    def test_file_limits(self, policy: PolicyConfig) -> None:
        # Assert
        assert policy.policy.file_limits.max_read_size == 10_485_760
        assert policy.policy.file_limits.max_write_size == 52_428_800
        assert ".exe" in policy.policy.file_limits.blocked_extensions

    def test_resource_limits(self, policy: PolicyConfig) -> None:
        # Assert
        assert policy.policy.resource_limits.pids_max == 32
        assert policy.policy.resource_limits.cpu_period_us == 100_000

    def test_confirmation_gates(self, policy: PolicyConfig) -> None:
        # Assert
        assert policy.policy.confirmation_gates.destructive_operations is True
        assert policy.policy.confirmation_gates.command_with_overrides is True

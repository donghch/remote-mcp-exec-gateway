"""Unit tests for path sanitization and command whitelist enforcement."""

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
def path_sanitizer(policy: PolicyConfig) -> PathSanitizer:
    return PathSanitizer(
        allowed_patterns=policy.policy.allowed_paths,
        blocked_patterns=policy.policy.blocked_paths,
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


# ---- Command sanitization ----


class TestCommandSanitizer:
    def test_allowed_command(self, cmd_sanitizer: CommandSanitizer) -> None:
        result = cmd_sanitizer.validate(["git", "status"])
        assert result.executable == "/usr/bin/git"
        assert result.argv == ["/usr/bin/git", "status"]

    def test_blocked_command(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="not in the allowed"):
            cmd_sanitizer.validate(["rm", "-rf", "/"])

    def test_blocked_subcommand(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="not allowed"):
            cmd_sanitizer.validate(["git", "push"])

    def test_too_many_args(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="exceeds max args"):
            cmd_sanitizer.validate(["ls"] + [f"arg{i}" for i in range(20)])

    def test_empty_argv(self, cmd_sanitizer: CommandSanitizer) -> None:
        with pytest.raises(ValueError, match="Empty"):
            cmd_sanitizer.validate([])

    def test_confirmation_required(self, cmd_sanitizer: CommandSanitizer) -> None:
        result = cmd_sanitizer.validate(["python3", "--version"])
        assert result.requires_confirmation

    def test_is_allowed(self, cmd_sanitizer: CommandSanitizer) -> None:
        assert cmd_sanitizer.is_allowed("git")
        assert not cmd_sanitizer.is_allowed("curl")

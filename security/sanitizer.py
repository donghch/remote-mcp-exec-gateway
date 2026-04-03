"""Input sanitization: path canonicalization, command whitelist enforcement."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path

from config.models import CommandPolicy, PolicyConfig


# =====================================================================
# Path sanitization
# =====================================================================


@dataclass(frozen=True)
class SanitizedPath:
    original: str
    resolved: Path
    is_valid: bool
    rejection_reason: str | None = None


class PathSanitizer:
    """Canonicalizes and validates file paths against workspace boundaries."""

    def __init__(self, allowed_patterns: list[str], blocked_patterns: list[str]) -> None:
        self._allowed = allowed_patterns
        self._blocked = blocked_patterns

    @staticmethod
    def _path_matches(path_str: str, pattern: str) -> bool:
        """Match a path against a glob pattern, handling /** suffix correctly."""
        # Direct fnmatch
        if fnmatch.fnmatch(path_str, pattern):
            return True
        # For patterns ending with /**, also match the base directory itself
        if pattern.endswith("/**"):
            base = pattern[:-3]
            if path_str.rstrip("/") == base.rstrip("/"):
                return True
        return False

    def sanitize(self, path_str: str) -> SanitizedPath:
        """Resolve and validate a path.

        Returns a SanitizedPath with is_valid=True only if the resolved
        path falls within an allowed pattern and does not match any blocked pattern.
        """
        try:
            resolved = Path(os.path.realpath(path_str)).resolve()
        except (OSError, ValueError) as exc:
            return SanitizedPath(
                original=path_str,
                resolved=Path(path_str),
                is_valid=False,
                rejection_reason=f"Cannot resolve path: {exc}",
            )

        # Check blocked first (deny wins)
        for pattern in self._blocked:
            if self._path_matches(str(resolved), pattern):
                return SanitizedPath(
                    original=path_str,
                    resolved=resolved,
                    is_valid=False,
                    rejection_reason=f"Path matches blocked pattern: {pattern}",
                )

        # Check allowed
        for pattern in self._allowed:
            if self._path_matches(str(resolved), pattern):
                return SanitizedPath(
                    original=path_str,
                    resolved=resolved,
                    is_valid=True,
                )

        return SanitizedPath(
            original=path_str,
            resolved=resolved,
            is_valid=False,
            rejection_reason="Path is outside all allowed workspace roots",
        )


# =====================================================================
# Command sanitization
# =====================================================================


@dataclass(frozen=True)
class ValidatedCommand:
    policy: CommandPolicy
    executable: str
    argv: list[str]
    requires_confirmation: bool


class CommandSanitizer:
    """Validates commands against the whitelist policy."""

    def __init__(self, policy: PolicyConfig) -> None:
        self._commands = policy.policy.allowed_commands

    def validate(self, argv: list[str]) -> ValidatedCommand:
        """Validate an argv list against the command whitelist.

        Raises ValueError on any policy violation.
        """
        if not argv:
            raise ValueError("Empty command argv")

        executable_name = argv[0]

        # Look up in whitelist
        cmd_policy = self._commands.get(executable_name)
        if cmd_policy is None:
            raise ValueError(
                f"Command '{executable_name}' is not in the allowed commands whitelist"
            )

        # Check arg count
        if len(argv) > cmd_policy.max_args:
            raise ValueError(
                f"Command '{executable_name}' exceeds max args "
                f"({len(argv)} > {cmd_policy.max_args})"
            )

        # Check subcommand prefix if restricted
        if cmd_policy.allowed_prefixes and len(argv) > 1:
            subcommand = argv[1]
            if subcommand not in cmd_policy.allowed_prefixes:
                raise ValueError(
                    f"Subcommand '{subcommand}' is not allowed for '{executable_name}'. "
                    f"Allowed: {cmd_policy.allowed_prefixes}"
                )

        return ValidatedCommand(
            policy=cmd_policy,
            executable=cmd_policy.executable,
            argv=[cmd_policy.executable, *argv[1:]],  # Replace name with full path
            requires_confirmation=cmd_policy.requires_confirmation,
        )

    def is_allowed(self, executable_name: str) -> bool:
        return executable_name in self._commands

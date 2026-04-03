"""Input sanitization: path canonicalization, command blacklist enforcement."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path

from config.models import CommandOverride, PolicyConfig


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
    """Result of command validation against the blacklist policy."""

    command_name: str
    argv: list[str]
    requires_confirmation: bool
    confirmation_reason: str
    override: CommandOverride | None


class CommandSanitizer:
    """Validates commands against the blacklist policy.

    All commands are allowed by default. Only banned commands are blocked.
    Commands in confirmation_required need explicit user consent.
    """

    def __init__(self, policy: PolicyConfig) -> None:
        self._banned = {cmd.name for cmd in policy.policy.banned_commands}
        self._banned_reasons = {cmd.name: cmd.reason for cmd in policy.policy.banned_commands}
        self._confirmation = {cmd.name for cmd in policy.policy.confirmation_required}
        self._confirmation_reasons = {
            cmd.name: cmd.reason for cmd in policy.policy.confirmation_required
        }
        self._overrides = policy.policy.command_overrides

    def validate(self, argv: list[str], confirm: bool = False) -> ValidatedCommand:
        """Validate an argv list against the blacklist policy.

        Raises ValueError on any policy violation.
        """
        if not argv:
            raise ValueError("Empty command argv")

        command_name = argv[0]

        # Check banned (deny wins)
        if command_name in self._banned:
            reason = self._banned_reasons.get(command_name, "Command is banned")
            raise ValueError(f"Command '{command_name}' is banned: {reason}")

        # Check confirmation required
        requires_confirmation = command_name in self._confirmation
        confirmation_reason = self._confirmation_reasons.get(command_name, "")

        if requires_confirmation and not confirm:
            raise ValueError(
                f"Command '{command_name}' requires confirmation: {confirmation_reason}. "
                f"Set confirm=true to proceed."
            )

        # Apply overrides if present
        override = self._overrides.get(command_name)

        # Check arg count against override or default
        max_args = override.max_args if override else 20
        if len(argv) > max_args:
            raise ValueError(
                f"Command '{command_name}' exceeds max args ({len(argv)} > {max_args})"
            )

        # Check subcommand prefix if restricted
        if override and override.allowed_prefixes and len(argv) > 1:
            subcommand = argv[1]
            if subcommand not in override.allowed_prefixes:
                raise ValueError(
                    f"Subcommand '{subcommand}' is not allowed for '{command_name}'. "
                    f"Allowed: {override.allowed_prefixes}"
                )

        return ValidatedCommand(
            command_name=command_name,
            argv=argv,
            requires_confirmation=requires_confirmation,
            confirmation_reason=confirmation_reason,
            override=override,
        )

    def is_banned(self, command_name: str) -> bool:
        """Check if a command is banned."""
        return command_name in self._banned

    def requires_confirmation(self, command_name: str) -> bool:
        """Check if a command requires user confirmation."""
        return command_name in self._confirmation

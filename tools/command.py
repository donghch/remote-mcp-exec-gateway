"""Command execution tool: argv-style subprocess with sandboxing."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from config.models import PolicyConfig, ResourceLimits
from security.sandbox import CGroupContext, CGroupManager, UserContext, make_preexec_fn
from session.manager import Session, SessionManager
from tools.base import ErrorCode, ToolError, ToolResult


class CommandResult(ToolResult):
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    duration_ms: int = 0
    pid: int | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False


MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB


class CommandExecutor:
    """Executes whitelisted commands in a sandboxed subprocess."""

    def __init__(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
        user_ctx: UserContext | None = None,
        cgroup_manager: CGroupManager | None = None,
    ) -> None:
        self._sessions = session_manager
        self._policy = policy
        self._user_ctx = user_ctx
        self._cgroup_mgr = cgroup_manager

    async def execute(
        self,
        session_id: str,
        argv: list[str],
        timeout_seconds: int | None = None,
        stdin_input: str | None = None,
        confirm: bool = False,
    ) -> CommandResult:
        """Execute a command within a session context.

        Args:
            session_id: Session to execute within.
            argv: Command as argv array (e.g. ["git", "status"]).
            timeout_seconds: Max execution time (default 30s, max 300s).
            stdin_input: Optional stdin content.
            confirm: Set True to pass confirmation gate for destructive commands.
        """
        session = self._sessions.get_session(session_id)
        if session is None:
            raise ToolError(
                ErrorCode.SESSION_NOT_FOUND,
                f"Session '{session_id}' not found or expired",
            )

        if not argv:
            raise ToolError(ErrorCode.CMD_EXEC_FAILED, "Empty command argv")

        # Validate against whitelist
        cmd_name = argv[0]
        cmd_policy = self._policy.policy.allowed_commands.get(cmd_name)
        if cmd_policy is None:
            raise ToolError(
                ErrorCode.POLICY_COMMAND_BLOCKED,
                f"Command '{cmd_name}' is not in the allowed whitelist",
            )

        # Confirmation gate
        if cmd_policy.requires_confirmation and not confirm:
            raise ToolError(
                ErrorCode.POLICY_CONFIRMATION_REQUIRED,
                f"Command '{cmd_name}' requires explicit confirmation. "
                f"Set confirm=true to proceed.",
                details={"command": cmd_name, "hint": "Pass confirm=true to acknowledge"},
            )

        # Build argv with full executable path
        exec_argv = [cmd_policy.executable, *argv[1:]]

        # Resolve timeout
        timeout = timeout_seconds or 30
        max_timeout = (
            self._policy.server.timeouts.command_max if hasattr(self._policy, "server") else 300
        )
        timeout = min(timeout, 300)

        # Apply per-command resource override (Phase 2)
        command_cgroup = await self._apply_resource_override(session, cmd_policy.resource_override)

        # Build preexec_fn
        preexec = None
        if self._user_ctx:
            cgroup_ctx = command_cgroup or session.cgroup
            preexec = make_preexec_fn(
                user_ctx=self._user_ctx,
                cgroup_ctx=cgroup_ctx,
                working_dir=session.working_dir,
            )

        # Execute
        proc = None
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *exec_argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_input else asyncio.subprocess.DEVNULL,
                cwd=str(session.working_dir),
                env=self._build_env(session),
                preexec_fn=preexec,
            )

            session.add_process(proc.pid, argv)

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(input=stdin_input.encode() if stdin_input else None),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                duration = int((time.monotonic() - start) * 1000)
                return CommandResult(
                    success=False,
                    error_code=ErrorCode.CMD_TIMEOUT,
                    error_message=f"Command timed out after {timeout}s",
                    duration_ms=duration,
                    pid=proc.pid,
                )

            duration = int((time.monotonic() - start) * 1000)

            stdout_str, stdout_trunc = self._truncate(stdout_bytes)
            stderr_str, stderr_trunc = self._truncate(stderr_bytes)

            return CommandResult(
                success=proc.returncode == 0,
                exit_code=proc.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_ms=duration,
                pid=proc.pid,
                stdout_truncated=stdout_trunc,
                stderr_truncated=stderr_trunc,
            )
        finally:
            if proc:
                session.remove_process(proc.pid)
            # Cleanup per-command cgroup if we created one
            if command_cgroup and self._cgroup_mgr:
                self._cgroup_mgr.destroy_session_cgroup(command_cgroup.session_id)

    async def _apply_resource_override(
        self,
        session: Session,
        override: ResourceLimits | None,
    ) -> CGroupContext | None:
        """Create a temporary cgroup with per-command resource limits if override is set."""
        if not override or not self._cgroup_mgr or not self._cgroup_mgr.is_available():
            return None

        import uuid

        cmd_cgroup_id = f"{session.session_id}-cmd-{uuid.uuid4().hex[:8]}"
        try:
            return self._cgroup_mgr.create_session_cgroup(cmd_cgroup_id, override)
        except Exception:
            return None

    @staticmethod
    def _truncate(data: bytes, limit: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
        if len(data) <= limit:
            return data.decode(errors="replace"), False
        return data[:limit].decode(errors="replace"), True

    @staticmethod
    def _build_env(session: Session) -> dict[str, str]:
        import os

        env = os.environ.copy()
        env.update(session.environment)
        return env

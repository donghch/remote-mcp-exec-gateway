"""OpenClaw Remote Broker MCP — main entry point.

Wires together config, security, session, tools, and audit into a FastMCP server
exposed over Streamable HTTP transport.
"""

from __future__ import annotations

import argparse
import asyncio
import signal as _signal
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from mcp.server.fastmcp import FastMCP

from audit.logger import AuditLogger, EventType
from config.loader import load_configs
from config.models import PolicyConfig, ServerConfig
from security.sandbox import CGroupManager, UserContext
from session.manager import SessionManager
from tools.base import ToolError, ToolResult
from tools.command import CommandExecutor, CommandResult
from tools.filesystem import (
    DirectoryList,
    DownloadResult,
    FileContent,
    FileWriteResult,
    FileSystemTools,
    UploadResult,
)
from tools.system import KillResult, ProcessList, SystemInfo, SystemTools

# =====================================================================
# Globals (initialized in lifespan)
# =====================================================================

_server_config: ServerConfig | None = None
_policy_config: PolicyConfig | None = None
_session_mgr: SessionManager | None = None
_cgroup_mgr: CGroupManager | None = None
_audit: AuditLogger | None = None
_cmd_executor: CommandExecutor | None = None
_fs_tools: FileSystemTools | None = None
_sys_tools: SystemTools | None = None
_user_ctx: UserContext | None = None


def _require(value: Any, name: str) -> Any:
    if value is None:
        raise RuntimeError(f"{name} not initialized")
    return value


# =====================================================================
# Lifespan
# =====================================================================


@asynccontextmanager
async def _lifespan(app: FastMCP) -> AsyncIterator[None]:
    """Initialize all subsystems on startup, tear down on shutdown."""
    global _server_config, _policy_config, _session_mgr, _cgroup_mgr
    global _audit, _cmd_executor, _fs_tools, _sys_tools, _user_ctx

    config_dir = Path(getattr(app, "_config_dir", "config"))
    _server_config, _policy_config = load_configs(config_dir)
    srv = _server_config.server

    # Audit logger
    _audit = AuditLogger(
        log_path=srv.logging.audit_log,
        error_log_path=srv.logging.error_log,
    )
    _audit.log(EventType.SERVER_START)

    # CGroup manager (optional)
    _cgroup_mgr = CGroupManager(srv.sandbox.cgroup_base)
    if srv.sandbox.enable_cgroups and _cgroup_mgr.is_available():
        if not _cgroup_mgr.initialize():
            _audit.log_error(
                "CGroup initialization failed, running without sandbox",
                event_type=EventType.ERROR,
                error_details={"component": "CGroupManager"},
            )

    # Session manager
    _session_mgr = SessionManager(_server_config, _cgroup_mgr)
    await _session_mgr.start()

    # User context (optional — skip if user is empty or doesn't exist)
    if srv.sandbox.unprivileged_user:
        try:
            _user_ctx = UserContext(srv.sandbox.unprivileged_user)
        except ValueError as exc:
            _audit.log_error(
                exc,
                event_type=EventType.ERROR,
                error_details={
                    "component": "UserContext",
                    "hint": "Sandbox user not available, running without privilege separation",
                },
            )
            _user_ctx = None
    else:
        _user_ctx = None

    # Tool instances
    _cmd_executor = CommandExecutor(_session_mgr, _policy_config, _user_ctx, _cgroup_mgr)
    _fs_tools = FileSystemTools(_session_mgr, _policy_config)
    _sys_tools = SystemTools(_session_mgr, _cgroup_mgr)

    try:
        yield
    finally:
        _audit.log(EventType.SERVER_STOP)
        await _session_mgr.stop()
        _audit.close()


# =====================================================================
# MCP Server
# =====================================================================


def create_server(config_dir: str = "config") -> FastMCP:
    """Create and configure the FastMCP server with all tools."""
    mcp = FastMCP(
        "OpenClaw Remote Broker",
        json_response=True,
        stateless_http=False,
        lifespan=_lifespan,
    )
    # Stash config dir for lifespan
    mcp._config_dir = config_dir  # type: ignore[attr-defined]

    # ---- Tools ----

    @mcp.tool()
    async def create_session(
        id: str | None = None,
        working_dir: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Create a new execution session with sandboxed context.

        Args:
            id: Optional session ID (auto-generated if omitted).
            working_dir: Initial working directory for the session (defaults to user's home directory).
            environment: Optional environment variables for commands.
        """
        sm = _require(_session_mgr, "SessionManager")
        audit = _require(_audit, "AuditLogger")

        # Default to user's home directory if not specified
        if working_dir is None:
            working_dir = str(Path.home())

        try:
            session = await sm.create_session(
                session_id=id,
                working_dir=Path(working_dir),
                environment=environment,
            )
            audit.log(EventType.SESSION_CREATED, session_id=session.session_id)
            return {
                "success": True,
                "session_id": session.session_id,
                "working_dir": str(session.working_dir),
                "created_at": session.created_at.isoformat(),
            }
        except Exception as exc:
            audit.log_error(
                exc,
                event_type=EventType.ERROR,
                tool_name="create_session",
                arguments={"id": id, "working_dir": working_dir},
                error_details={"error_code": "SESSION_004"},
            )
            return ToolResult(success=False, error_message=str(exc)).model_dump()

    @mcp.tool()
    async def kill_session(session_id: str, force: bool = False) -> dict[str, Any]:
        """Terminate a session and clean up all its processes.

        Args:
            session_id: The session to terminate.
            force: If True, send SIGKILL immediately instead of SIGTERM.
        """
        sm = _require(_session_mgr, "SessionManager")
        audit = _require(_audit, "AuditLogger")

        ok = await sm.kill_session(session_id, force=force)
        if ok:
            audit.log(EventType.SESSION_KILLED, session_id=session_id)
            return {"success": True, "session_id": session_id}
        audit.log(
            EventType.ERROR,
            session_id=session_id,
            tool_name="kill_session",
            error=f"Session '{session_id}' not found",
            error_code="SESSION_001",
        )
        return {"success": False, "error_message": f"Session '{session_id}' not found"}

    @mcp.tool()
    async def execute_command(
        session_id: str,
        argv: list[str],
        timeout_seconds: int | None = None,
        stdin_input: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Execute a whitelisted command within a session.

        Args:
            session_id: Session to execute within.
            argv: Command and arguments as a list (e.g. ["git", "status"]).
            timeout_seconds: Max execution time (default 30s, max 300s).
            stdin_input: Optional stdin content to pipe into the command.
            confirm: Set true to pass confirmation gate for destructive commands.
        """
        executor = _require(_cmd_executor, "CommandExecutor")
        audit = _require(_audit, "AuditLogger")

        audit.log(
            EventType.COMMAND_STARTED,
            session_id=session_id,
            tool_name="execute_command",
            arguments={"argv": argv},
        )
        try:
            result = await executor.execute(
                session_id=session_id,
                argv=argv,
                timeout_seconds=timeout_seconds,
                stdin_input=stdin_input,
                confirm=confirm,
            )
            audit.log(
                EventType.COMMAND_COMPLETED if result.success else EventType.COMMAND_FAILED,
                session_id=session_id,
                exit_code=result.exit_code,
                duration_ms=result.duration_ms,
            )
            return result.model_dump()
        except ToolError as exc:
            audit.log(EventType.COMMAND_FAILED, session_id=session_id, error=str(exc))
            return exc.to_result().model_dump()

    @mcp.tool()
    async def read_file(
        session_id: str,
        path: str,
        offset: int = 0,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Read a file from the session workspace.

        Args:
            session_id: Active session.
            path: File path (absolute or relative to working_dir).
            offset: Byte offset to start reading from.
            limit: Max bytes to read.
        """
        fs = _require(_fs_tools, "FileSystemTools")
        audit = _require(_audit, "AuditLogger")

        try:
            result = await fs.read_file(session_id, path, offset=offset, limit=limit)
            audit.log(EventType.FILE_READ, session_id=session_id, arguments={"path": path})
            return result.model_dump()
        except ToolError as exc:
            audit.log_error(
                exc,
                event_type=EventType.ERROR,
                error_code=exc.code.value,
                session_id=session_id,
                tool_name="read_file",
                arguments={"path": path},
            )
            return exc.to_result().model_dump()

    @mcp.tool()
    async def write_file(
        session_id: str,
        path: str,
        content: str,
        mode: str = "overwrite",
    ) -> dict[str, Any]:
        """Write content to a file in the session workspace.

        Args:
            session_id: Active session.
            path: File path (absolute or relative to working_dir).
            content: Text content to write.
            mode: "overwrite" or "append".
        """
        fs = _require(_fs_tools, "FileSystemTools")
        audit = _require(_audit, "AuditLogger")

        try:
            result = await fs.write_file(session_id, path, content, mode=mode)  # type: ignore[arg-type]
            audit.log(EventType.FILE_WRITE, session_id=session_id, arguments={"path": path})
            return result.model_dump()
        except ToolError as exc:
            audit.log_error(
                exc,
                event_type=EventType.ERROR,
                error_code=exc.code.value,
                session_id=session_id,
                tool_name="write_file",
                arguments={"path": path},
            )
            return exc.to_result().model_dump()

    @mcp.tool()
    async def list_directory(
        session_id: str,
        path: str = ".",
        include_hidden: bool = False,
    ) -> dict[str, Any]:
        """List contents of a directory in the session workspace.

        Args:
            session_id: Active session.
            path: Directory path.
            include_hidden: Include hidden files/directories.
        """
        fs = _require(_fs_tools, "FileSystemTools")
        audit = _require(_audit, "AuditLogger")

        try:
            result = await fs.list_directory(session_id, path, include_hidden=include_hidden)
            audit.log(EventType.FILE_LIST, session_id=session_id, arguments={"path": path})
            return result.model_dump()
        except ToolError as exc:
            audit.log_error(
                exc,
                event_type=EventType.ERROR,
                error_code=exc.code.value,
                session_id=session_id,
                tool_name="list_directory",
                arguments={"path": path},
            )
            return exc.to_result().model_dump()

    @mcp.tool()
    async def download_file(
        session_id: str,
        path: str,
        chunk_size: int = 1048576,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Download a file from the workspace in chunks.

        Call repeatedly with increasing offset until is_complete=true.
        The final chunk includes a SHA-256 hash for integrity verification.

        Args:
            session_id: Active session.
            path: File path to download.
            chunk_size: Bytes per chunk (default 1MB).
            offset: Byte offset for this chunk.
        """
        fs = _require(_fs_tools, "FileSystemTools")
        audit = _require(_audit, "AuditLogger")

        try:
            result = await fs.download_file(session_id, path, chunk_size=chunk_size, offset=offset)
            audit.log(
                EventType.FILE_DOWNLOAD,
                session_id=session_id,
                arguments={"path": path, "offset": offset},
            )
            return result.model_dump()
        except ToolError as exc:
            audit.log_error(
                exc,
                event_type=EventType.ERROR,
                error_code=exc.code.value,
                session_id=session_id,
                tool_name="download_file",
                arguments={"path": path},
            )
            return exc.to_result().model_dump()

    @mcp.tool()
    async def upload_file(
        session_id: str,
        path: str,
        chunk_data: str,
        transfer_id: str = "",
        chunk_offset: int = 0,
        is_last: bool = False,
    ) -> dict[str, Any]:
        """Upload a file to the workspace in chunks.

        Send chunk_data as base64-encoded content. On the final chunk, set is_last=true.
        The response includes a SHA-256 hash for integrity verification.

        Args:
            session_id: Active session.
            path: Destination file path.
            chunk_data: Base64-encoded chunk data.
            transfer_id: Transfer ID from first chunk response (auto-generated if empty).
            chunk_offset: Byte offset of this chunk.
            is_last: True if this is the final chunk.
        """
        fs = _require(_fs_tools, "FileSystemTools")
        audit = _require(_audit, "AuditLogger")

        try:
            result = await fs.upload_file(
                session_id,
                path,
                chunk_data=chunk_data,
                transfer_id=transfer_id,
                chunk_offset=chunk_offset,
                is_last=is_last,
            )
            if result.is_complete:
                audit.log(
                    EventType.FILE_UPLOAD,
                    session_id=session_id,
                    arguments={"path": path, "bytes": result.bytes_received},
                )
            return result.model_dump()
        except ToolError as exc:
            audit.log_error(
                exc,
                event_type=EventType.ERROR,
                error_code=exc.code.value,
                session_id=session_id,
                tool_name="upload_file",
                arguments={"path": path},
            )
            return exc.to_result().model_dump()

    @mcp.tool()
    async def get_system_info() -> dict[str, Any]:
        """Get host system information: CPU, memory, disk usage."""
        sys_tools = _require(_sys_tools, "SystemTools")
        result = await sys_tools.get_system_info()
        return result.model_dump()

    @mcp.tool()
    async def get_process_list(session_id: str | None = None) -> dict[str, Any]:
        """List running processes, optionally scoped to a session.

        Args:
            session_id: If provided, only list processes in this session's cgroup.
        """
        sys_tools = _require(_sys_tools, "SystemTools")
        result = await sys_tools.get_process_list(session_id)
        return result.model_dump()

    @mcp.tool()
    async def kill_process(
        session_id: str,
        pid: int,
        signal: int = 15,
    ) -> dict[str, Any]:
        """Kill a process within a session.

        Args:
            session_id: Session the process belongs to.
            pid: Process ID to kill.
            signal: Signal number (default 15 = SIGTERM).
        """
        sys_tools = _require(_sys_tools, "SystemTools")
        audit = _require(_audit, "AuditLogger")

        try:
            result = await sys_tools.kill_process(session_id, pid, sig=signal)
            audit.log(
                EventType.PROCESS_KILLED,
                session_id=session_id,
                arguments={"pid": pid, "signal": signal},
            )
            return result.model_dump()
        except ToolError as exc:
            audit.log_error(
                exc,
                event_type=EventType.ERROR,
                error_code=exc.code.value,
                session_id=session_id,
                tool_name="kill_process",
                arguments={"pid": pid, "signal": signal},
            )
            return exc.to_result().model_dump()

    return mcp


# =====================================================================
# Entry point
# =====================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenClaw Remote Broker MCP")
    parser.add_argument(
        "--config-dir",
        default="config",
        help="Path to configuration directory (default: config)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override server bind address",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override server port",
    )
    args = parser.parse_args()

    # Load config
    config_dir = Path(args.config_dir)
    server_cfg, _ = load_configs(config_dir)
    srv = server_cfg.server

    host = args.host or srv.host
    port = args.port or srv.port

    mcp = create_server(config_dir=args.config_dir)

    print(f"Starting broker on http://{host}:{port}")
    uvicorn.run(
        mcp.streamable_http_app(),
        host=host,
        port=port,
        log_level=srv.logging.level.value.lower(),
    )


if __name__ == "__main__":
    main()

"""Structured audit logging for all tool invocations and errors."""

from __future__ import annotations

import json
import traceback
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import structlog


class EventType(str, Enum):
    SERVER_START = "SERVER_START"
    SERVER_STOP = "SERVER_STOP"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_KILLED = "SESSION_KILLED"
    COMMAND_STARTED = "COMMAND_STARTED"
    COMMAND_COMPLETED = "COMMAND_COMPLETED"
    COMMAND_FAILED = "COMMAND_FAILED"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_LIST = "FILE_LIST"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"
    FILE_UPLOAD = "FILE_UPLOAD"
    PROCESS_KILLED = "PROCESS_KILLED"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ERROR = "ERROR"


# Event types that represent errors (written to error log)
_ERROR_EVENT_TYPES = frozenset(
    {
        EventType.COMMAND_FAILED,
        EventType.AUTH_FAILURE,
        EventType.POLICY_VIOLATION,
        EventType.ERROR,
    }
)


class AuditLogger:
    """Structured audit logging with separate error log file.

    All events go to the audit log. Error events additionally go to
    the error log for fast triage.
    """

    def __init__(
        self,
        log_path: Path | None = None,
        error_log_path: Path | None = None,
        console: bool = True,
    ) -> None:
        processors: list[Any] = [
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
        structlog.configure(processors=processors)

        self._logger = structlog.get_logger("audit")
        self._file: Any = None
        self._error_file: Any = None

        if log_path:
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                self._file = open(log_path, "a")  # noqa: SIM115
            except (OSError, PermissionError):
                # Fall back to console-only logging
                self._logger.warning(f"Cannot open audit log {log_path}, using console only")

        # Error log defaults to audit_log + .errors suffix
        if error_log_path is None and log_path is not None:
            error_log_path = log_path.parent / f"{log_path.stem}-errors{log_path.suffix}"

        if error_log_path:
            try:
                error_log_path.parent.mkdir(parents=True, exist_ok=True)
                self._error_file = open(error_log_path, "a")  # noqa: SIM115
            except (OSError, PermissionError):
                self._logger.warning(f"Cannot open error log {error_log_path}, using console only")

    def log(
        self,
        event_type: EventType,
        session_id: str | None = None,
        client_dn: str | None = None,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        duration_ms: int | None = None,
        exit_code: int | None = None,
        error: str | None = None,
        error_code: str | None = None,
        error_details: dict[str, Any] | None = None,
    ) -> None:
        """Write a structured audit event.

        Error events are also written to the dedicated error log.
        """
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type.value,
        }
        if session_id:
            record["session_id"] = session_id
        if client_dn:
            record["client_dn"] = client_dn
        if tool_name:
            record["tool_name"] = tool_name
        if arguments:
            record["arguments"] = self._redact(arguments)
        if result:
            record["result"] = result
        if duration_ms is not None:
            record["duration_ms"] = duration_ms
        if exit_code is not None:
            record["exit_code"] = exit_code
        if error:
            record["error"] = error
        if error_code:
            record["error_code"] = error_code
        if error_details:
            record["error_details"] = error_details

        line = json.dumps(record, default=str)

        # Always write to audit log
        if self._file:
            self._file.write(line + "\n")
            self._file.flush()

        # Write error events to dedicated error log
        if self._error_file and (event_type in _ERROR_EVENT_TYPES or error):
            self._error_file.write(line + "\n")
            self._error_file.flush()

        self._logger.msg(line)

    def log_error(
        self,
        error: str | Exception,
        event_type: EventType = EventType.ERROR,
        error_code: str | None = None,
        session_id: str | None = None,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        error_details: dict[str, Any] | None = None,
        include_traceback: bool = True,
    ) -> None:
        """Log an error with full context and optional traceback.

        This is the primary method for error logging. It always writes
        to both the audit log and the dedicated error log.
        """
        error_str = str(error)
        tb = None

        if include_traceback and isinstance(error, Exception):
            tb = traceback.format_exception(type(error), error, error.__traceback__)
            tb_str = "".join(tb)
        else:
            tb_str = None

        details = error_details or {}
        if tb_str:
            details["traceback"] = tb_str

        self.log(
            event_type=event_type,
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            error=error_str,
            error_code=error_code,
            error_details=details if details else None,
        )

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
        if self._error_file:
            self._error_file.close()
            self._error_file = None

    @staticmethod
    def _redact(data: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive fields from logged arguments."""
        redacted = data.copy()
        for key in ("password", "token", "secret", "key", "authorization"):
            if key in redacted:
                redacted[key] = "***REDACTED***"
        return redacted

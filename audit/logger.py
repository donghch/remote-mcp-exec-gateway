"""Structured audit logging for all tool invocations."""

from __future__ import annotations

import json
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
    PROCESS_KILLED = "PROCESS_KILLED"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ERROR = "ERROR"


class AuditLogger:
    """Structured audit logging with structlog (JSON lines output)."""

    def __init__(self, log_path: Path | None = None, console: bool = True) -> None:
        processors: list[Any] = [
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
        structlog.configure(processors=processors)

        self._logger = structlog.get_logger("audit")
        self._file = None

        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(log_path, "a")  # noqa: SIM115

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
    ) -> None:
        """Write a structured audit event."""
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

        line = json.dumps(record, default=str)

        if self._file:
            self._file.write(line + "\n")
            self._file.flush()

        self._logger.msg(line)

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    @staticmethod
    def _redact(data: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive fields from logged arguments."""
        redacted = data.copy()
        for key in ("password", "token", "secret", "key", "authorization"):
            if key in redacted:
                redacted[key] = "***REDACTED***"
        return redacted

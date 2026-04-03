"""Shared tool infrastructure: context, result models, error types."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ErrorCode(str, Enum):
    """Structured error codes for all tool failures."""

    AUTH_INVALID_CERT = "AUTH_001"
    AUTH_EXPIRED_CERT = "AUTH_002"
    AUTH_UNAUTHORIZED = "AUTH_003"

    SESSION_NOT_FOUND = "SESSION_001"
    SESSION_EXPIRED = "SESSION_002"
    SESSION_LIMIT_REACHED = "SESSION_003"
    SESSION_CREATION_FAILED = "SESSION_004"

    POLICY_COMMAND_BLOCKED = "POLICY_001"
    POLICY_PATH_VIOLATION = "POLICY_002"
    POLICY_RESOURCE_EXCEEDED = "POLICY_003"
    POLICY_CONFIRMATION_REQUIRED = "POLICY_004"

    CMD_EXEC_FAILED = "CMD_001"
    CMD_TIMEOUT = "CMD_002"
    CMD_KILLED = "CMD_003"

    FILE_NOT_FOUND = "FILE_001"
    FILE_ACCESS_DENIED = "FILE_002"
    FILE_TOO_LARGE = "FILE_003"
    FILE_WRITE_ERROR = "FILE_004"

    PROC_NOT_FOUND = "PROC_001"
    PROC_ACCESS_DENIED = "PROC_002"

    SYSTEM_INTERNAL_ERROR = "SYS_999"


class ToolResult(BaseModel):
    """Base result model for all tool outputs."""

    success: bool = True
    error_code: ErrorCode | None = None
    error_message: str | None = None
    error_details: dict[str, Any] | None = None


class ToolError(Exception):
    """Exception raised by tool implementations."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.details = details or {}
        super().__init__(message)

    def to_result(self) -> ToolResult:
        return ToolResult(
            success=False,
            error_code=self.code,
            error_message=str(self),
            error_details=self.details,
        )

"""Tests for error logging to dedicated error audit file."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit.logger import AuditLogger, EventType
from tools.base import ErrorCode, ToolError


class TestErrorLogFile:
    def test_errors_written_to_separate_file(self, tmp_path: Path) -> None:
        """Error events should appear in both audit and error log."""
        audit_path = tmp_path / "audit.log"
        error_path = tmp_path / "errors.log"

        logger = AuditLogger(log_path=audit_path, error_log_path=error_path)

        # Log a success event
        logger.log(EventType.SESSION_CREATED, session_id="s1")

        # Log an error event
        logger.log(
            EventType.COMMAND_FAILED,
            session_id="s1",
            error="Command not allowed",
            error_code="POLICY_001",
        )

        logger.close()

        # Audit log should have both
        audit_lines = audit_path.read_text().strip().split("\n")
        assert len(audit_lines) == 2

        # Error log should have only the error
        error_lines = error_path.read_text().strip().split("\n")
        assert len(error_lines) == 1
        error_record = json.loads(error_lines[0])
        assert error_record["event_type"] == "COMMAND_FAILED"
        assert error_record["error_code"] == "POLICY_001"

    def test_log_error_method(self, tmp_path: Path) -> None:
        """log_error() should write to error log with traceback."""
        audit_path = tmp_path / "audit.log"
        error_path = tmp_path / "errors.log"

        logger = AuditLogger(log_path=audit_path, error_log_path=error_path)

        try:
            raise ValueError("something broke")
        except ValueError as exc:
            logger.log_error(
                exc,
                session_id="s1",
                tool_name="test_tool",
                error_code="SYS_999",
            )

        logger.close()

        error_lines = error_path.read_text().strip().split("\n")
        assert len(error_lines) == 1
        record = json.loads(error_lines[0])
        assert record["error"] == "something broke"
        assert record["error_code"] == "SYS_999"
        assert record["session_id"] == "s1"
        assert record["tool_name"] == "test_tool"
        assert "traceback" in record["error_details"]
        assert "ValueError" in record["error_details"]["traceback"]

    def test_log_error_without_traceback(self, tmp_path: Path) -> None:
        """log_error() with include_traceback=False should skip traceback."""
        audit_path = tmp_path / "audit.log"
        error_path = tmp_path / "errors.log"

        logger = AuditLogger(log_path=audit_path, error_log_path=error_path)

        exc = ToolError(ErrorCode.FILE_NOT_FOUND, "File missing")
        logger.log_error(exc, include_traceback=False)
        logger.close()

        error_lines = error_path.read_text().strip().split("\n")
        record = json.loads(error_lines[0])
        assert record["error"] == "File missing"
        assert "traceback" not in (record.get("error_details") or {})

    def test_success_not_in_error_log(self, tmp_path: Path) -> None:
        """Non-error events should NOT appear in error log."""
        audit_path = tmp_path / "audit.log"
        error_path = tmp_path / "errors.log"

        logger = AuditLogger(log_path=audit_path, error_log_path=error_path)

        logger.log(EventType.SERVER_START)
        logger.log(EventType.SESSION_CREATED, session_id="s1")
        logger.log(EventType.COMMAND_COMPLETED, session_id="s1", exit_code=0)

        logger.close()

        # Audit log has all 3
        audit_lines = audit_path.read_text().strip().split("\n")
        assert len(audit_lines) == 3

        # Error log is empty
        assert not error_path.exists() or error_path.read_text().strip() == ""

    def test_error_log_defaults_to_audit_suffix(self, tmp_path: Path) -> None:
        """When error_log_path is not set, it defaults to audit_log + -errors suffix."""
        audit_path = tmp_path / "my-audit.log"

        logger = AuditLogger(log_path=audit_path)
        logger.log(EventType.ERROR, error="test error")
        logger.close()

        expected_error_path = tmp_path / "my-audit-errors.log"
        assert expected_error_path.exists()
        lines = expected_error_path.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_error_event_types_in_error_log(self, tmp_path: Path) -> None:
        """All error event types should be written to error log."""
        audit_path = tmp_path / "audit.log"
        error_path = tmp_path / "errors.log"

        logger = AuditLogger(log_path=audit_path, error_log_path=error_path)

        error_events = [
            EventType.COMMAND_FAILED,
            EventType.AUTH_FAILURE,
            EventType.POLICY_VIOLATION,
            EventType.ERROR,
        ]
        for evt in error_events:
            logger.log(evt, error=f"test {evt.value}")

        logger.close()

        error_lines = error_path.read_text().strip().split("\n")
        assert len(error_lines) == 4
        for i, evt in enumerate(error_events):
            record = json.loads(error_lines[i])
            assert record["event_type"] == evt.value

    def test_graceful_fallback_on_permission_error(self, tmp_path: Path) -> None:
        """AuditLogger should not crash when log files can't be opened."""
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o555)
        try:
            log_path = readonly_dir / "audit.log"
            # Should not raise — falls back to console-only
            logger = AuditLogger(log_path=log_path)
            # Should still be able to log (to console via structlog)
            logger.log(EventType.SERVER_START)
            logger.log_error("test error")
            logger.close()
        finally:
            readonly_dir.chmod(0o755)

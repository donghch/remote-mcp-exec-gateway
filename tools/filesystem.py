"""File system tools: read, write, list, download, upload."""

from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
from pathlib import Path
from typing import Literal

import aiofiles
from pydantic import BaseModel

from config.models import PolicyConfig
from security.sanitizer import PathSanitizer
from session.manager import SessionManager
from tools.base import ErrorCode, ToolError, ToolResult


class FileContent(ToolResult):
    content: str | None = None
    size_bytes: int = 0
    mime_type: str | None = None
    is_binary: bool = False
    truncated: bool = False


class FileWriteResult(ToolResult):
    bytes_written: int = 0
    path: str = ""


class DirectoryEntry(BaseModel):
    name: str
    type: Literal["file", "directory", "symlink", "other"]
    size_bytes: int | None = None


class DirectoryList(ToolResult):
    entries: list[DirectoryEntry] = []
    total_count: int = 0
    path: str = ""


class DownloadResult(ToolResult):
    """Result of a file download chunk."""

    transfer_id: str = ""
    filename: str = ""
    mime_type: str = ""
    total_size: int = 0
    chunk_data: str = ""  # base64-encoded chunk
    chunk_offset: int = 0
    chunk_size: int = 0
    is_complete: bool = False
    sha256: str = ""  # full-file hash (set when complete)


class UploadResult(ToolResult):
    """Result of a file upload chunk."""

    transfer_id: str = ""
    path: str = ""
    bytes_received: int = 0
    is_complete: bool = False
    sha256: str = ""  # full-file hash (set when complete)


# In-progress upload state: transfer_id → {path, buffer, session_id}
_UPLOAD_TRANSFERS: dict[str, dict] = {}


MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MB per chunk


class FileSystemTools:
    """File operation implementations with path validation."""

    def __init__(
        self,
        session_manager: SessionManager,
        policy: PolicyConfig,
    ) -> None:
        self._sessions = session_manager
        self._sanitizer = PathSanitizer(
            allowed_patterns=policy.policy.allowed_paths,
            blocked_patterns=policy.policy.blocked_paths,
        )
        self._max_read = policy.policy.file_limits.max_read_size
        self._max_write = policy.policy.file_limits.max_write_size

    async def read_file(
        self,
        session_id: str,
        path: str,
        offset: int = 0,
        limit: int | None = None,
    ) -> FileContent:
        """Read file contents with path validation."""
        session = self._sessions.get_session(session_id)
        if session is None:
            raise ToolError(ErrorCode.SESSION_NOT_FOUND, f"Session '{session_id}' not found")

        resolved = self._resolve(session, path)

        if not resolved.exists():
            raise ToolError(ErrorCode.FILE_NOT_FOUND, f"File not found: {path}")

        if not resolved.is_file():
            raise ToolError(ErrorCode.FILE_ACCESS_DENIED, f"Not a file: {path}")

        size = resolved.stat().st_size
        read_limit = min(limit or self._max_read, self._max_read)

        # Detect binary
        is_binary = self._is_binary(resolved)
        mime_type, _ = mimetypes.guess_type(str(resolved))

        if is_binary:
            async with aiofiles.open(resolved, "rb") as fh:
                await fh.seek(offset)
                data = await fh.read(read_limit)
            import base64

            return FileContent(
                content=base64.b64encode(data).decode(),
                size_bytes=size,
                mime_type=mime_type or "application/octet-stream",
                is_binary=True,
                truncated=(offset + len(data)) < size,
            )

        async with aiofiles.open(resolved, "r", errors="replace") as fh:
            await fh.seek(offset)
            text = await fh.read(read_limit)

        return FileContent(
            content=text,
            size_bytes=size,
            mime_type=mime_type or "text/plain",
            is_binary=False,
            truncated=(offset + len(text.encode())) < size,
        )

    async def write_file(
        self,
        session_id: str,
        path: str,
        content: str,
        mode: Literal["overwrite", "append"] = "overwrite",
    ) -> FileWriteResult:
        """Write content to a file with path validation."""
        session = self._sessions.get_session(session_id)
        if session is None:
            raise ToolError(ErrorCode.SESSION_NOT_FOUND, f"Session '{session_id}' not found")

        resolved = self._resolve(session, path)

        content_bytes = content.encode()
        if len(content_bytes) > self._max_write:
            raise ToolError(
                ErrorCode.FILE_TOO_LARGE,
                f"Content size ({len(content_bytes)} bytes) exceeds limit ({self._max_write} bytes)",
            )

        # Create parent dirs if needed
        resolved.parent.mkdir(parents=True, exist_ok=True)

        file_mode = "a" if mode == "append" else "w"
        async with aiofiles.open(resolved, file_mode) as fh:
            await fh.write(content)

        return FileWriteResult(
            bytes_written=len(content_bytes),
            path=str(resolved),
        )

    async def list_directory(
        self,
        session_id: str,
        path: str,
        include_hidden: bool = False,
    ) -> DirectoryList:
        """List directory contents with path validation."""
        session = self._sessions.get_session(session_id)
        if session is None:
            raise ToolError(ErrorCode.SESSION_NOT_FOUND, f"Session '{session_id}' not found")

        resolved = self._resolve(session, path)

        if not resolved.exists():
            raise ToolError(ErrorCode.FILE_NOT_FOUND, f"Path not found: {path}")
        if not resolved.is_dir():
            raise ToolError(ErrorCode.FILE_ACCESS_DENIED, f"Not a directory: {path}")

        entries: list[DirectoryEntry] = []
        for entry in sorted(resolved.iterdir(), key=lambda e: e.name):
            if not include_hidden and entry.name.startswith("."):
                continue

            if entry.is_symlink():
                entry_type = "symlink"
            elif entry.is_dir():
                entry_type = "directory"
            elif entry.is_file():
                entry_type = "file"
            else:
                entry_type = "other"

            size = None
            if entry_type == "file":
                try:
                    size = entry.stat().st_size
                except OSError:
                    pass

            entries.append(DirectoryEntry(name=entry.name, type=entry_type, size_bytes=size))

        return DirectoryList(
            entries=entries,
            total_count=len(entries),
            path=str(resolved),
        )

    async def download_file(
        self,
        session_id: str,
        path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        offset: int = 0,
    ) -> DownloadResult:
        """Download a file chunk from the workspace.

        Call repeatedly with increasing offset until is_complete=True.
        The final chunk includes the full-file SHA-256 hash for integrity verification.

        Args:
            session_id: Active session.
            path: File path to download.
            chunk_size: Bytes per chunk (default 1MB).
            offset: Byte offset for this chunk.
        """
        session = self._sessions.get_session(session_id)
        if session is None:
            raise ToolError(ErrorCode.SESSION_NOT_FOUND, f"Session '{session_id}' not found")

        resolved = self._resolve(session, path)

        if not resolved.exists():
            raise ToolError(ErrorCode.FILE_NOT_FOUND, f"File not found: {path}")
        if not resolved.is_file():
            raise ToolError(ErrorCode.FILE_ACCESS_DENIED, f"Not a file: {path}")

        total_size = resolved.stat().st_size
        chunk_size = min(chunk_size, self._max_read)
        mime_type, _ = mimetypes.guess_type(str(resolved))

        async with aiofiles.open(resolved, "rb") as fh:
            await fh.seek(offset)
            data = await fh.read(chunk_size)

        is_complete = (offset + len(data)) >= total_size
        transfer_id = hashlib.sha256(f"{session_id}:{path}".encode()).hexdigest()[:16]

        # Compute full-file hash on final chunk
        sha256 = ""
        if is_complete:
            sha256 = await self._file_hash(resolved)

        return DownloadResult(
            transfer_id=transfer_id,
            filename=resolved.name,
            mime_type=mime_type or "application/octet-stream",
            total_size=total_size,
            chunk_data=base64.b64encode(data).decode(),
            chunk_offset=offset,
            chunk_size=len(data),
            is_complete=is_complete,
            sha256=sha256,
        )

    async def upload_file(
        self,
        session_id: str,
        path: str,
        chunk_data: str,
        transfer_id: str = "",
        chunk_offset: int = 0,
        is_last: bool = False,
    ) -> UploadResult:
        """Upload a file chunk to the workspace.

        Call with chunk_data (base64) and is_last=True on the final chunk.
        The file is written atomically (temp file → rename) on completion.

        Args:
            session_id: Active session.
            path: Destination file path.
            chunk_data: Base64-encoded chunk data.
            transfer_id: Transfer ID from first chunk (auto-generated if empty).
            chunk_offset: Byte offset of this chunk (for verification).
            is_last: True if this is the final chunk.
        """
        session = self._sessions.get_session(session_id)
        if session is None:
            raise ToolError(ErrorCode.SESSION_NOT_FOUND, f"Session '{session_id}' not found")

        resolved = self._resolve(session, path)

        if not transfer_id:
            transfer_id = hashlib.sha256(f"{session_id}:{path}".encode()).hexdigest()[:16]

        decoded = base64.b64decode(chunk_data)

        if len(decoded) > self._max_write:
            raise ToolError(
                ErrorCode.FILE_TOO_LARGE,
                f"Chunk size ({len(decoded)} bytes) exceeds limit ({self._max_write} bytes)",
            )

        # Get or create transfer state
        if transfer_id not in _UPLOAD_TRANSFERS:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = resolved.with_suffix(resolved.suffix + ".tmp")
            _UPLOAD_TRANSFERS[transfer_id] = {
                "path": resolved,
                "tmp_path": tmp_path,
                "bytes_received": 0,
                "hasher": hashlib.sha256(),
            }
            # Truncate temp file
            async with aiofiles.open(tmp_path, "wb") as fh:
                await fh.write(b"")

        transfer = _UPLOAD_TRANSFERS[transfer_id]

        # Verify offset continuity
        if chunk_offset != transfer["bytes_received"]:
            raise ToolError(
                ErrorCode.FILE_WRITE_ERROR,
                f"Chunk offset mismatch: expected {transfer['bytes_received']}, got {chunk_offset}",
            )

        # Check total size
        new_total = transfer["bytes_received"] + len(decoded)
        if new_total > self._max_write:
            raise ToolError(
                ErrorCode.FILE_TOO_LARGE,
                f"Total upload size ({new_total} bytes) exceeds limit ({self._max_write} bytes)",
            )

        # Append chunk to temp file
        async with aiofiles.open(transfer["tmp_path"], "ab") as fh:
            await fh.write(decoded)

        transfer["bytes_received"] = new_total
        transfer["hasher"].update(decoded)

        sha256 = ""
        complete = False

        if is_last:
            # Atomic rename: tmp → final
            tmp_path = transfer["tmp_path"]
            if resolved.exists():
                resolved.unlink()
            tmp_path.rename(resolved)
            sha256 = transfer["hasher"].hexdigest()
            complete = True
            del _UPLOAD_TRANSFERS[transfer_id]

        return UploadResult(
            transfer_id=transfer_id,
            path=str(resolved),
            bytes_received=new_total,
            is_complete=complete,
            sha256=sha256,
        )

    def _resolve(self, session: object, path: str) -> Path:
        """Resolve and validate a path against the workspace."""
        # Resolve relative to session working dir
        working_dir = getattr(session, "working_dir", Path("."))
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = working_dir / candidate

        sanitized = self._sanitizer.sanitize(str(candidate))
        if not sanitized.is_valid:
            raise ToolError(
                ErrorCode.FILE_ACCESS_DENIED,
                f"Path access denied: {sanitized.rejection_reason}",
                details={"path": path, "resolved": str(sanitized.resolved)},
            )
        return sanitized.resolved

    @staticmethod
    def _is_binary(path: Path, sample_size: int = 8192) -> bool:
        try:
            with open(path, "rb") as fh:
                chunk = fh.read(sample_size)
            return b"\x00" in chunk
        except OSError:
            return False

    @staticmethod
    async def _file_hash(path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        async with aiofiles.open(path, "rb") as fh:
            while True:
                chunk = await fh.read(65536)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

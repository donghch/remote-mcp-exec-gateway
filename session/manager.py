"""In-memory session lifecycle management with cgroup-backed isolation."""

from __future__ import annotations

import asyncio
import os
import signal
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from config.models import ServerConfig
from security.sandbox import CGroupContext, CGroupManager


@dataclass
class ProcessRecord:
    """Tracks a running process within a session."""

    pid: int
    command: list[str]
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Session:
    """Represents an active execution session."""

    session_id: str
    created_at: datetime
    last_activity: datetime
    working_dir: Path
    environment: dict[str, str]
    cgroup: CGroupContext | None
    processes: dict[int, ProcessRecord] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)

    def is_expired(self, max_age_seconds: int) -> bool:
        """Check if session has been inactive beyond the timeout."""
        elapsed = (datetime.now(timezone.utc) - self.last_activity).total_seconds()
        return elapsed > max_age_seconds

    def add_process(self, pid: int, command: list[str]) -> ProcessRecord:
        record = ProcessRecord(pid=pid, command=command)
        self.processes[pid] = record
        return record

    def remove_process(self, pid: int) -> None:
        self.processes.pop(pid, None)

    async def kill_all_processes(self, sig: int = signal.SIGTERM) -> None:
        """Send a signal to all tracked processes, then SIGKILL stragglers."""
        for pid in list(self.processes):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                self.processes.pop(pid, None)

        if sig != signal.SIGKILL:
            await asyncio.sleep(2)
            for pid in list(self.processes):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.processes.pop(pid, None)


class SessionManager:
    """Manages creation, lookup, and cleanup of execution sessions."""

    def __init__(self, config: ServerConfig, cgroup_manager: CGroupManager | None = None) -> None:
        self._sessions: dict[str, Session] = {}
        self._config = config
        self._cgroup_mgr = cgroup_manager
        self._cleanup_task: asyncio.Task[None] | None = None

    # ---- Lifecycle ----

    async def start(self) -> None:
        """Start the background cleanup loop."""
        interval = self._config.server.sessions.cleanup_interval
        self._cleanup_task = asyncio.create_task(self._cleanup_loop(interval))

    async def stop(self) -> None:
        """Stop cleanup and kill all sessions."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        for sid in list(self._sessions):
            await self.kill_session(sid, force=True)

    # ---- Public API ----

    async def create_session(
        self,
        session_id: str | None,
        working_dir: Path,
        environment: dict[str, str] | None,
    ) -> Session:
        """Create a new session with optional cgroup isolation."""
        sid = session_id or str(uuid.uuid4())
        if sid in self._sessions:
            raise ValueError(f"Session '{sid}' already exists")

        max_concurrent = self._config.server.sessions.max_concurrent
        if len(self._sessions) >= max_concurrent:
            raise ValueError(f"Maximum concurrent sessions ({max_concurrent}) reached")

        # Validate working directory
        resolved = working_dir.resolve()
        if not resolved.is_dir():
            raise ValueError(f"Working directory does not exist: {resolved}")

        # Create cgroup if available
        cgroup: CGroupContext | None = None
        if self._cgroup_mgr and self._cgroup_mgr.is_available():
            from config.models import ResourceLimits

            limits = ResourceLimits()  # Use defaults
            cgroup = self._cgroup_mgr.create_session_cgroup(sid, limits)

        now = datetime.now(timezone.utc)
        session = Session(
            session_id=sid,
            created_at=now,
            last_activity=now,
            working_dir=resolved,
            environment=environment or {},
            cgroup=cgroup,
        )
        self._sessions[sid] = session
        return session

    def get_session(self, session_id: str) -> Session | None:
        session = self._sessions.get(session_id)
        if session:
            session.touch()
        return session

    def list_sessions(self) -> list[dict[str, object]]:
        return [
            {
                "session_id": s.session_id,
                "created_at": s.created_at.isoformat(),
                "last_activity": s.last_activity.isoformat(),
                "working_dir": str(s.working_dir),
                "process_count": len(s.processes),
            }
            for s in self._sessions.values()
        ]

    async def kill_session(self, session_id: str, force: bool = False) -> bool:
        """Terminate a session and clean up all resources."""
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False

        sig = signal.SIGKILL if force else signal.SIGTERM
        await session.kill_all_processes(sig)

        if session.cgroup:
            self._cgroup_mgr.destroy_session_cgroup(session_id)  # type: ignore[union-attr]

        return True

    # ---- Internal ----

    async def _cleanup_loop(self, interval: int) -> None:
        """Background task that expires stale sessions."""
        while True:
            await asyncio.sleep(interval)
            max_age = self._config.server.sessions.max_session_age
            expired = [
                sid for sid, session in self._sessions.items() if session.is_expired(max_age)
            ]
            for sid in expired:
                await self.kill_session(sid, force=False)

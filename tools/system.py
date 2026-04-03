"""System info and process management tools."""

from __future__ import annotations

import os
import signal
from datetime import datetime, timezone
from typing import Literal

import psutil
from pydantic import BaseModel

from security.sandbox import CGroupManager
from session.manager import SessionManager
from tools.base import ErrorCode, ToolError, ToolResult


class CPUInfo(BaseModel):
    cores: int
    usage_percent: float


class MemoryInfo(BaseModel):
    total_bytes: int
    available_bytes: int
    used_bytes: int
    usage_percent: float


class DiskInfo(BaseModel):
    mount_point: str
    total_bytes: int
    free_bytes: int
    usage_percent: float


class SystemInfo(ToolResult):
    hostname: str = ""
    platform: str = ""
    cpu: CPUInfo | None = None
    memory: MemoryInfo | None = None
    disks: list[DiskInfo] = []
    uptime_seconds: int = 0


class ProcessInfo(BaseModel):
    pid: int
    name: str
    cmdline: str
    status: str
    cpu_percent: float | None = None
    memory_rss: int | None = None


class ProcessList(ToolResult):
    processes: list[ProcessInfo] = []
    total_count: int = 0
    session_id: str | None = None


class KillResult(ToolResult):
    pid: int = 0
    signal_sent: int = 0
    was_running: bool = False


class SystemTools:
    """System information and process management."""

    def __init__(
        self,
        session_manager: SessionManager,
        cgroup_manager: CGroupManager | None = None,
    ) -> None:
        self._sessions = session_manager
        self._cgroup_mgr = cgroup_manager

    async def get_system_info(self) -> SystemInfo:
        """Return CPU, memory, and disk usage."""
        cpu_count = psutil.cpu_count(logical=True) or 1
        cpu_percent = psutil.cpu_percent(interval=0.1)

        mem = psutil.virtual_memory()

        disks: list[DiskInfo] = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append(
                    DiskInfo(
                        mount_point=part.mountpoint,
                        total_bytes=usage.total,
                        free_bytes=usage.free,
                        usage_percent=usage.percent,
                    )
                )
            except PermissionError:
                continue

        boot = psutil.boot_time()
        uptime = int(datetime.now(timezone.utc).timestamp() - boot)

        return SystemInfo(
            hostname=psutil.os.uname().nodename,
            platform=f"{psutil.os.uname().sysname} {psutil.os.uname().release}",
            cpu=CPUInfo(cores=cpu_count, usage_percent=cpu_percent),
            memory=MemoryInfo(
                total_bytes=mem.total,
                available_bytes=mem.available,
                used_bytes=mem.used,
                usage_percent=mem.percent,
            ),
            disks=disks,
            uptime_seconds=uptime,
        )

    async def get_process_list(self, session_id: str | None = None) -> ProcessList:
        """List processes, optionally scoped to a session's cgroup."""
        processes: list[ProcessInfo] = []

        if session_id and self._cgroup_mgr:
            cgroup = self._cgroup_mgr.get_session_cgroup(session_id)
            if cgroup:
                pids = self._read_cgroup_pids(cgroup.path)
                for pid in pids:
                    info = self._proc_info(pid)
                    if info:
                        processes.append(info)
                return ProcessList(
                    processes=processes,
                    total_count=len(processes),
                    session_id=session_id,
                )

        # Fallback: list all processes owned by current user
        current_uid = os.getuid()
        for proc in psutil.process_iter(["pid", "name", "cmdline", "status", "memory_info"]):
            try:
                if proc.uids().real == current_uid:  # type: ignore[attr-defined]
                    processes.append(
                        ProcessInfo(
                            pid=proc.pid,
                            name=proc.info["name"] or "",
                            cmdline=" ".join(proc.info["cmdline"] or []),
                            status=proc.info["status"] or "",
                            memory_rss=proc.info["memory_info"].rss
                            if proc.info["memory_info"]
                            else None,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return ProcessList(processes=processes, total_count=len(processes))

    async def kill_process(
        self,
        session_id: str,
        pid: int,
        sig: int = signal.SIGTERM,
    ) -> KillResult:
        """Kill a process within a session, with ownership verification."""
        session = self._sessions.get_session(session_id)
        if session is None:
            raise ToolError(ErrorCode.SESSION_NOT_FOUND, f"Session '{session_id}' not found")

        # Verify process belongs to session
        if pid not in session.processes:
            raise ToolError(
                ErrorCode.PROC_ACCESS_DENIED,
                f"Process {pid} does not belong to session '{session_id}'",
            )

        was_running = True
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            was_running = False
        except PermissionError:
            raise ToolError(ErrorCode.PROC_ACCESS_DENIED, f"Permission denied to kill PID {pid}")

        if was_running:
            session.remove_process(pid)

        return KillResult(pid=pid, signal_sent=sig, was_running=was_running)

    @staticmethod
    def _read_cgroup_pids(cgroup_path: object) -> list[int]:
        from pathlib import Path

        p = Path(str(cgroup_path)) / "cgroup.procs"
        if not p.exists():
            return []
        return [int(x) for x in p.read_text().split() if x]

    @staticmethod
    def _proc_info(pid: int) -> ProcessInfo | None:
        try:
            proc = psutil.Process(pid)
            return ProcessInfo(
                pid=pid,
                name=proc.name(),
                cmdline=" ".join(proc.cmdline()),
                status=proc.status(),
                memory_rss=proc.memory_info().rss,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

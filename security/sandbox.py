"""Sandbox backend: cgroups v2 resource limits and unprivileged user execution."""

from __future__ import annotations

import ctypes
import os
import pwd
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from config.models import ResourceLimits


@dataclass
class CGroupContext:
    """Lifecycle-managed handle to a session cgroup."""

    path: Path
    session_id: str

    def write_pid(self, pid: int) -> None:
        """Move a process into this cgroup."""
        procs_file = self.path / "cgroup.procs"
        procs_file.write_text(str(pid))

    def kill_all(self) -> None:
        """Kill all processes in this cgroup."""
        kill_file = self.path / "cgroup.kill"
        if kill_file.exists():
            kill_file.write_text("1")
        else:
            # Fallback: read PIDs and SIGKILL individually
            for pid in self._read_pids():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def remove(self) -> None:
        """Remove the cgroup directory (must be empty first)."""
        self.kill_all()
        try:
            self.path.rmdir()
        except OSError:
            pass  # Already removed or not empty yet

    def _read_pids(self) -> list[int]:
        procs_file = self.path / "cgroup.procs"
        if not procs_file.exists():
            return []
        text = procs_file.read_text().strip()
        return [int(p) for p in text.split() if p]


class CGroupManager:
    """Creates and manages cgroups v2 hierarchies for sandboxing."""

    REQUIRED_CONTROLLERS = ["cpu", "memory", "pids", "io"]

    def __init__(self, base_path: Path) -> None:
        self._base = base_path
        self._active: dict[str, CGroupContext] = {}

    # ---- Setup ----

    def initialize(self) -> None:
        """Create the base cgroup and enable subtree controllers."""
        self._base.mkdir(parents=True, exist_ok=True)

        controllers = " ".join(f"+{c}" for c in self.REQUIRED_CONTROLLERS)
        subtree_file = self._base / "cgroup.subtree_control"
        if subtree_file.exists():
            subtree_file.write_text(controllers)

    def is_available(self) -> bool:
        """Check if cgroups v2 is mounted and usable."""
        unified = Path("/sys/fs/cgroup")
        return (unified / "cgroup.controllers").exists()

    # ---- Per-session cgroup ----

    def create_session_cgroup(self, session_id: str, limits: ResourceLimits) -> CGroupContext:
        """Create a cgroup for a session and apply resource limits."""
        cgroup_path = self._base / f"session-{session_id}"
        cgroup_path.mkdir(exist_ok=False)

        self._apply_limits(cgroup_path, limits)
        ctx = CGroupContext(path=cgroup_path, session_id=session_id)
        self._active[session_id] = ctx
        return ctx

    def get_session_cgroup(self, session_id: str) -> CGroupContext | None:
        return self._active.get(session_id)

    def destroy_session_cgroup(self, session_id: str) -> None:
        ctx = self._active.pop(session_id, None)
        if ctx:
            ctx.remove()

    # ---- Internal ----

    def _apply_limits(self, cgroup_path: Path, limits: ResourceLimits) -> None:
        if limits.cpu_quota_us:
            cpu_max = f"{limits.cpu_quota_us} {limits.cpu_period_us}"
            self._safe_write(cgroup_path / "cpu.max", cpu_max)

        self._safe_write(cgroup_path / "memory.max", str(limits.memory_max))
        self._safe_write(cgroup_path / "pids.max", str(limits.pids_max))

        if limits.io_weight:
            io_file = cgroup_path / "io.weight"
            if io_file.exists():
                self._safe_write(io_file, str(limits.io_weight))

    @staticmethod
    def _safe_write(path: Path, value: str) -> None:
        try:
            path.write_text(value)
        except OSError:
            pass  # Best-effort; controller may not be available


# =====================================================================
# Unprivileged user context
# =====================================================================


class UserContext:
    """Manages privilege dropping for sandboxed subprocess execution."""

    def __init__(self, username: str) -> None:
        self._username = username
        try:
            pw = pwd.getpwnam(username)
        except KeyError:
            raise ValueError(f"User '{username}' does not exist on this system")
        self._uid = pw.pw_uid
        self._gid = pw.pw_gid
        self._home = Path(pw.pw_dir)

        if self._uid == 0:
            raise ValueError("Sandbox user must not be root")

    @property
    def uid(self) -> int:
        return self._uid

    @property
    def gid(self) -> int:
        return self._gid

    @property
    def home(self) -> Path:
        return self._home

    def get_env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Minimal environment for sandboxed processes."""
        env: dict[str, str] = {
            "HOME": str(self._home),
            "USER": self._username,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TMPDIR": "/tmp",
            "LD_PRELOAD": "",
            "LD_LIBRARY_PATH": "",
        }
        if extra:
            env.update(extra)
        return env


def make_preexec_fn(
    user_ctx: UserContext,
    cgroup_ctx: CGroupContext | None,
    working_dir: Path,
) -> Callable[[], None]:
    """Build a preexec_fn for subprocess that drops privileges and joins cgroup."""

    def preexec() -> None:
        # 1. Move into cgroup (before dropping privileges)
        if cgroup_ctx:
            try:
                cgroup_ctx.write_pid(os.getpid())
            except OSError:
                pass

        # 2. Drop supplementary groups
        try:
            os.setgroups([])
        except OSError:
            pass

        # 3. Drop to unprivileged user
        os.setgid(user_ctx.gid)
        os.setuid(user_ctx.uid)

        # 4. Set working directory
        try:
            os.chdir(working_dir)
        except OSError:
            os.chdir(user_ctx.home)

        # 5. Disable core dumps (prevent ptrace)
        try:
            PR_SET_DUMPABLE = 4
            ctypes.CDLL("libc.so.6").prctl(PR_SET_DUMPABLE, 0)
        except Exception:
            pass

    return preexec

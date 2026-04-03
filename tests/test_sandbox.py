"""Mock tests for sandbox/cgroups (no real cgroups required)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security.sandbox import CGroupContext, CGroupManager, UserContext


class TestCGroupManager:
    def test_is_available_true(self, tmp_path: Path) -> None:
        with patch("security.sandbox.Path") as MockPath:
            mock_cgroup = MagicMock()
            mock_cgroup.exists.return_value = True
            MockPath.return_value = mock_cgroup
            # The /sys/fs/cgroup/cgroup.controllers check
            mock_cgroup.__truediv__ = MagicMock(
                return_value=MagicMock(exists=MagicMock(return_value=True))
            )

    def test_is_available_writable(self, tmp_path: Path) -> None:
        """is_available() returns True when base dir is writable."""
        base = tmp_path / "cgroup"
        mgr = CGroupManager(base)
        # Patch controllers file check to return True
        with patch("security.sandbox.Path") as MockPath:
            mock_unified = MagicMock()
            mock_unified.__truediv__ = MagicMock(
                return_value=MagicMock(exists=MagicMock(return_value=True))
            )
            MockPath.return_value = mock_unified
            assert mgr.is_available() is True

    def test_initialize_returns_true_on_success(self, tmp_path: Path) -> None:
        """initialize() returns True when it succeeds."""
        base = tmp_path / "cgroup"
        mgr = CGroupManager(base)
        result = mgr.initialize()
        assert result is True
        assert base.exists()

    def test_initialize_returns_false_on_permission_error(self, tmp_path: Path) -> None:
        """initialize() returns False, not crash, on permission errors."""
        readonly_parent = tmp_path / "readonly"
        readonly_parent.mkdir()
        readonly_parent.chmod(0o555)
        try:
            mgr = CGroupManager(readonly_parent / "cgroup")
            result = mgr.initialize()
            assert result is False
        finally:
            readonly_parent.chmod(0o755)

    def test_create_session_cgroup(self, tmp_path: Path) -> None:
        base = tmp_path / "cgroup"
        mgr = CGroupManager(base)
        # Manually create base (skip real cgroup setup)
        base.mkdir(parents=True, exist_ok=True)

        from config.models import ResourceLimits

        limits = ResourceLimits()

        # Patch the _apply_limits to avoid writing to real cgroup files
        with patch.object(mgr, "_apply_limits"):
            ctx = mgr.create_session_cgroup("test-sess", limits)
            assert ctx.session_id == "test-sess"
            assert ctx.path == base / "session-test-sess"

        # Cleanup
        mgr.destroy_session_cgroup("test-sess")

    def test_destroy_nonexistent(self, tmp_path: Path) -> None:
        base = tmp_path / "cgroup"
        mgr = CGroupManager(base)
        # Should not raise
        mgr.destroy_session_cgroup("nonexistent")


class TestCGroupContext:
    def test_remove_nonexistent(self, tmp_path: Path) -> None:
        ctx = CGroupContext(path=tmp_path / "nonexistent", session_id="x")
        # Should not raise
        ctx.remove()


class TestUserContext:
    def test_root_rejected(self) -> None:
        with patch("security.sandbox.pwd.getpwnam") as mock_pwd:
            mock_pwd.return_value = MagicMock(pw_uid=0, pw_gid=0, pw_dir="/root")
            with pytest.raises(ValueError, match="root"):
                UserContext("root")

    def test_nonexistent_user(self) -> None:
        import pwd

        with patch("security.sandbox.pwd.getpwnam", side_effect=KeyError("nope")):
            with pytest.raises(ValueError, match="does not exist"):
                UserContext("nonexistent")

    def test_get_env(self) -> None:
        with patch("security.sandbox.pwd.getpwnam") as mock_pwd:
            mock_pwd.return_value = MagicMock(pw_uid=1001, pw_gid=1001, pw_dir="/home/testuser")
            ctx = UserContext("testuser")
            env = ctx.get_env(extra={"FOO": "bar"})
            assert env["USER"] == "testuser"
            assert env["FOO"] == "bar"
            assert env["LD_PRELOAD"] == ""

"""Unit tests for config loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from config.loader import load_policy_config, load_server_config
from config.models import PolicyConfig, ServerConfig

FIXTURES = Path(__file__).parent.parent / "config"


def test_load_server_config() -> None:
    cfg = load_server_config(FIXTURES / "server.yaml")
    assert isinstance(cfg, ServerConfig)
    assert cfg.server.port == 8443
    assert cfg.server.tls.min_version == "TLSv1.3"
    assert cfg.server.sessions.max_session_age == 1800


def test_load_policy_config() -> None:
    cfg = load_policy_config(FIXTURES / "policy.yaml")
    assert isinstance(cfg, PolicyConfig)
    assert "git" in cfg.policy.allowed_commands
    assert "ls" in cfg.policy.allowed_commands
    assert cfg.policy.resource_limits.pids_max == 32


def test_server_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_server_config(tmp_path / "nonexistent.yaml")


def test_policy_config_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.yaml"
    p.write_text("")
    with pytest.raises(ValueError, match="empty"):
        load_policy_config(p)


def test_server_config_validation_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.dump({"server": {"port": -1}}))
    with pytest.raises(Exception):
        load_server_config(p)

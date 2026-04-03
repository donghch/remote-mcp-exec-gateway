"""YAML configuration loader with validation."""

from __future__ import annotations

from pathlib import Path

import yaml

from config.models import PolicyConfig, ServerConfig


def load_server_config(path: Path | str) -> ServerConfig:
    """Load and validate server configuration from YAML."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Server config not found: {path}")

    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)

    if raw is None:
        raise ValueError(f"Server config is empty: {path}")

    return ServerConfig.model_validate(raw)


def load_policy_config(path: Path | str) -> PolicyConfig:
    """Load and validate security policy from YAML."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy config not found: {path}")

    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)

    if raw is None:
        raise ValueError(f"Policy config is empty: {path}")

    return PolicyConfig.model_validate(raw)


def load_configs(
    config_dir: Path | str = "config",
) -> tuple[ServerConfig, PolicyConfig]:
    """Load both server and policy configs from a directory."""
    config_dir = Path(config_dir)
    server = load_server_config(config_dir / "server.yaml")
    policy = load_policy_config(config_dir / "policy.yaml")
    return server, policy

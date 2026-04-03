"""Pydantic models for server and policy configuration."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


# --- TLS ---


class TLSConfig(BaseModel):
    cert_path: Path
    key_path: Path
    ca_cert_path: Path
    min_version: Literal["TLSv1.2", "TLSv1.3"] = "TLSv1.3"


# --- Logging ---


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class LoggingConfig(BaseModel):
    level: LogLevel = LogLevel.INFO
    format: Literal["json", "console"] = "json"
    audit_log: Path
    max_size_mb: int = Field(ge=1, default=100)
    backup_count: int = Field(ge=0, default=10)


# --- Sessions ---


class SessionConfig(BaseModel):
    max_session_age: int = Field(ge=60, default=1800)
    max_concurrent: int = Field(ge=1, default=10)
    cleanup_interval: int = Field(ge=10, default=60)


# --- Timeouts ---


class TimeoutConfig(BaseModel):
    command_default: int = Field(ge=1, default=30)
    command_max: int = Field(ge=1, default=300)


# --- Sandbox ---


class SandboxConfig(BaseModel):
    unprivileged_user: str = "oc-runner"
    cgroup_base: Path = Path("/sys/fs/cgroup/oc-broker")
    enable_cgroups: bool = True


# --- Server block ---


class ServerBlock(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(ge=1, le=65535, default=8443)
    tls: TLSConfig
    logging: LoggingConfig
    sessions: SessionConfig
    timeouts: TimeoutConfig
    sandbox: SandboxConfig


class ServerConfig(BaseModel):
    """Top-level server configuration loaded from server.yaml."""

    server: ServerBlock


# =====================================================================
# Policy models
# =====================================================================


class ResourceLimits(BaseModel):
    cpu_quota_us: int | None = Field(ge=0, default=100000)
    cpu_period_us: int = Field(ge=1, default=100000)
    memory_max: str = "536870912"
    pids_max: int = Field(ge=1, default=32)
    io_weight: int | None = Field(ge=10, le=1000, default=100)


class CommandPolicy(BaseModel):
    executable: str
    max_args: int = Field(ge=1, default=20)
    allowed_prefixes: list[str] | None = None
    requires_confirmation: bool = False
    resource_override: ResourceLimits | None = None


class FileLimits(BaseModel):
    max_read_size: int = Field(ge=1, default=10_485_760)
    max_write_size: int = Field(ge=1, default=52_428_800)
    blocked_extensions: list[str] = []


class ConfirmationGates(BaseModel):
    destructive_operations: bool = True
    command_with_overrides: bool = True


class PolicyBlock(BaseModel):
    allowed_commands: dict[str, CommandPolicy] = {}
    allowed_paths: list[str] = []
    blocked_paths: list[str] = []
    file_limits: FileLimits = FileLimits()
    resource_limits: ResourceLimits = ResourceLimits()
    confirmation_gates: ConfirmationGates = ConfirmationGates()


class PolicyConfig(BaseModel):
    """Top-level security policy loaded from policy.yaml."""

    policy: PolicyBlock

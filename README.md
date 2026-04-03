# OpenClaw Remote Broker MCP

A single-user remote execution gateway that exposes command, file, process, and system tools over the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). Built with Python, FastMCP, and defense-in-depth security.

The broker lets an AI agent operate on a remote machine without requiring any client-side agent installation — acting as a secure execution boundary between the agent and the host system.

## Features

- **MCP-native** — Exposes 9 tools over Streamable HTTP transport (the modern MCP standard)
- **Whitelist-only commands** — Only explicitly allowed binaries can run; no arbitrary shell access
- **Sandboxed execution** — cgroups v2 resource limits + unprivileged OS user for every subprocess
- **Path validation** — All file operations are canonicalized and restricted to workspace roots
- **Session isolation** — Each session gets its own working directory (defaults to user's home), environment, and process group
- **Full audit logging** — Every tool call is logged with structured JSON (timestamp, client, args, exit code, duration)
- **No shell interpretation** — Commands run as argv arrays; shell metacharacters are disallowed

## Requirements

- **Python 3.13+**
- **Linux** with cgroups v2 (for sandboxing; optional — degrades gracefully)
- A dedicated unprivileged OS user for sandboxed execution (default: `oc-runner`)

### System packages

```bash
# Debian/Ubuntu
sudo apt install libmagic1 cgroup-tools

# Fedora/RHEL
sudo dnf install file-libs libcgroup-tools
```

## Installation

```bash
git clone <repo-url> oc-broker
cd oc-broker

# Install with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

## Configuration

Two YAML files in `config/` control the broker:

### `config/server.yaml` — Server settings

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  logging:
    audit_log: "log/audit.log"
    error_log: "log/audit-errors.log"
  sandbox:
    unprivileged_user: ""       # Empty = no privilege dropping
    cgroup_base: "data/cgroup"
    enable_cgroups: false
```

> All paths are relative to the project root. No root privileges required for default config.

### `config/policy.yaml` — Security policy

```yaml
policy:
  allowed_commands:
    git:
      executable: "/usr/bin/git"
      max_args: 20
      allowed_prefixes: ["status", "log", "diff", "pull", "fetch"]
      requires_confirmation: false
    ls:
      executable: "/bin/ls"
      max_args: 10
      requires_confirmation: false
  allowed_paths:
    - "~//**"                    # User's home directory (default session working dir)
    - "/home/**"                 # All user home directories
    - "/tmp/**"                  # Temporary files
  blocked_paths:
    - "**/.ssh/**"
    - "**/.gnupg/**"
    - "**/.aws/**"
    - "**/.env"
  resource_limits:
    memory_max: "536870912"     # 512 MB
    pids_max: 32
```

See `config/server.yaml` and `config/policy.yaml` for all available options.

## Quick Start

### 1. Start the broker (no setup needed)

```bash
uv sync
uv run python main.py
```

The broker starts on `http://127.0.0.1:8080` with plain HTTP. No root, no sandbox user required.

### 2. Connect from an MCP client

The broker exposes tools over Streamable HTTP at `http://<host>:<port>/mcp`. Any MCP-compatible client can connect.

## Available Tools

| Tool | Description |
|------|-------------|
| `create_session` | Create a sandboxed execution session (defaults to user's home directory) |
| `kill_session` | Terminate a session and clean up all its processes |
| `execute_command` | Run a whitelisted command as an argv array with timeout |
| `read_file` | Read a file from the session workspace |
| `write_file` | Write or append content to a file in the workspace |
| `list_directory` | List files and directories in the workspace |
| `download_file` | Download a file in chunks (base64, with SHA-256 verification) |
| `upload_file` | Upload a file in chunks (base64, atomic write on completion) |
| `get_system_info` | Get CPU, memory, and disk usage |
| `get_process_list` | List running processes (optionally session-scoped) |
| `kill_process` | Kill a process within a session |

### Example: Execute a command

```json
{
  "name": "execute_command",
  "arguments": {
    "session_id": "my-session",
    "argv": ["git", "status"],
    "timeout_seconds": 30
  }
}
```

**Response:**
```json
{
  "success": true,
  "exit_code": 0,
  "stdout": "On branch main\nnothing to commit",
  "stderr": "",
  "duration_ms": 120,
  "pid": 12345
}
```

### Example: Read a file

```json
{
  "name": "read_file",
  "arguments": {
    "session_id": "my-session",
    "path": "src/main.py"
  }
}
```

### Example: Download a large file (chunked)

```json
// First chunk
{
  "name": "download_file",
  "arguments": {
    "session_id": "my-session",
    "path": "build/output.jar",
    "chunk_size": 1048576,
    "offset": 0
  }
}

// Response includes transfer_id, chunk_data (base64), is_complete
// Repeat with offset += chunk_size until is_complete=true
// Final chunk includes sha256 hash for verification
```

### Example: Upload a file (chunked)

```json
// First chunk
{
  "name": "upload_file",
  "arguments": {
    "session_id": "my-session",
    "path": "src/new_module.py",
    "chunk_data": "<base64-encoded-content>",
    "chunk_offset": 0,
    "is_last": true
  }
}

// For multi-chunk: omit is_last, save transfer_id from response
// Final chunk: set is_last=true, include transfer_id and correct chunk_offset
// Response includes sha256 hash when complete
```

### Example: Confirmation gate

Commands marked with `requires_confirmation: true` in `policy.yaml` (like `python3`) require explicit acknowledgment:

```json
{
  "name": "execute_command",
  "arguments": {
    "session_id": "my-session",
    "argv": ["python3", "train.py"],
    "confirm": true
  }
}
```

Without `confirm: true`, the broker returns a `POLICY_CONFIRMATION_REQUIRED` error.

## Security Model

```
Client (AI Agent)
    │
    ▼
┌───────────────────────────────────────┐
│  Policy Enforcement                  │
│  → Session exists and is active?     │
│  → Path within workspace roots?      │
│  → Command in whitelist?             │
│  → Confirmation gate passed?         │
├───────────────────────────────────────┤
│  Sandboxed Execution                 │
│  → cgroups v2 resource limits        │
│  → Unprivileged OS user              │
│  → argv-style (no shell)             │
│  → Process group supervision         │
├───────────────────────────────────────┤
│  Audit Log                           │
│  → Every tool call logged as JSON    │
└───────────────────────────────────────┘
```

### What the broker does NOT allow

- Arbitrary shell commands or scripts
- Shell pipes, redirects, or command substitution
- Running as root
- Accessing paths outside configured workspace roots
- Commands not in the whitelist

## Audit Logs

Every tool invocation is logged as a JSON line. There are two log files:

### `audit.log` — All events

Every operation (success and failure) is recorded:

```json
{"timestamp": "2026-04-02T18:30:00Z", "event_type": "COMMAND_COMPLETED", "session_id": "abc-123", "tool_name": "execute_command", "exit_code": 0, "duration_ms": 450}
```

### `audit-errors.log` — Errors only

Failed operations are also written to a dedicated error log for fast triage. Each entry includes `error_code`, the error message, and (for exceptions) a full traceback:

```json
{"timestamp": "2026-04-02T18:30:01Z", "event_type": "COMMAND_FAILED", "session_id": "abc-123", "tool_name": "execute_command", "error": "Command 'curl' is not in the allowed whitelist", "error_code": "POLICY_001", "arguments": {"argv": ["curl", "example.com"]}}
```

Log paths are configured in `server.yaml` → `server.logging`:

```yaml
logging:
  audit_log: "log/audit.log"
  error_log: "log/audit-errors.log"
```

If `error_log` is omitted, it defaults to `<audit_log>-errors.log`.

## CLI Reference

```
uv run python main.py [OPTIONS]

Options:
  --config-dir PATH   Path to configuration directory (default: config)
  --host ADDRESS      Override server bind address
  --port PORT         Override server port
```

## Project Structure

```
oc-broker/
├── main.py                 # FastMCP server + tool registration
├── config/
│   ├── server.yaml         # Server configuration
│   ├── policy.yaml         # Command whitelist + path rules
│   ├── models.py           # Pydantic config models
│   └── loader.py           # YAML config loading
├── security/
│   ├── sanitizer.py        # Path + command validation
│   └── sandbox.py          # cgroups v2 + privilege dropping
├── tools/
│   ├── base.py             # Shared result models + error types
│   ├── command.py          # execute_command implementation
│   ├── filesystem.py       # read/write/list operations
│   └── system.py           # system info + process management
├── session/
│   └── manager.py          # Session lifecycle + cleanup
├── audit/
│   └── logger.py           # Structured audit logging
└── tests/                  # Test suite
```

## License

See [LICENSE](LICENSE) for details.

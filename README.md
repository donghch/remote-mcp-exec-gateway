# OpenClaw Remote Broker MCP

A single-user remote execution gateway that exposes command, file, process, and system tools over the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). Built with Python, FastMCP, and defense-in-depth security.

The broker lets an AI agent operate on a remote machine without requiring any client-side agent installation — acting as a secure execution boundary between the agent and the host system.

## Features

- **MCP-native** — Exposes 9 tools over Streamable HTTP transport (the modern MCP standard)
- **Whitelist-only commands** — Only explicitly allowed binaries can run; no arbitrary shell access
- **mTLS authentication** — Mutual TLS 1.3 ensures only trusted clients connect
- **Sandboxed execution** — cgroups v2 resource limits + unprivileged OS user for every subprocess
- **Path validation** — All file operations are canonicalized and restricted to workspace roots
- **Session isolation** — Each session gets its own working directory, environment, and process group
- **Full audit logging** — Every tool call is logged with structured JSON (timestamp, client, args, exit code, duration)
- **No shell interpretation** — Commands run as argv arrays; shell metacharacters are disallowed

## Requirements

- **Python 3.13+**
- **Linux** with cgroups v2 (for sandboxing; optional — degrades gracefully)
- A dedicated unprivileged OS user for sandboxed execution (default: `oc-runner`)
- TLS certificates for mTLS (server cert, server key, CA cert)

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
  host: "0.0.0.0"
  port: 8443
  tls:
    cert_path: "/etc/oc-broker/server.crt"
    key_path: "/etc/oc-broker/server.key"
    ca_cert_path: "/etc/oc-broker/ca.crt"
    min_version: "TLSv1.3"
  sessions:
    max_session_age: 1800       # 30 minutes inactivity timeout
    max_concurrent: 10
  sandbox:
    unprivileged_user: "oc-runner"
    enable_cgroups: true
```

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
    - "/home/oc-runner/workspace/**"
  blocked_paths:
    - "**/.ssh/**"
    - "**/.env"
  resource_limits:
    memory_max: "536870912"     # 512 MB
    pids_max: 32
```

See `config/server.yaml` and `config/policy.yaml` for all available options.

## Quick Start

### 1. Generate TLS certificates

```bash
mkdir -p /etc/oc-broker

# Generate CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout /etc/oc-broker/ca.key -out /etc/oc-broker/ca.crt \
  -subj "/CN=OC-Broker CA"

# Generate server cert
openssl req -newkey rsa:4096 -nodes \
  -keyout /etc/oc-broker/server.key -out /etc/oc-broker/server.csr \
  -subj "/CN=oc-broker-server"
openssl x509 -req -days 365 \
  -in /etc/oc-broker/server.csr -CA /etc/oc-broker/ca.crt \
  -CAkey /etc/oc-broker/ca.key -CAcreateserial \
  -out /etc/oc-broker/server.crt

# Generate client cert
openssl req -newkey rsa:4096 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=openclaw-client"
openssl x509 -req -days 365 \
  -in client.csr -CA /etc/oc-broker/ca.crt \
  -CAkey /etc/oc-broker/ca.key -CAcreateserial \
  -out client.crt
```

### 2. Create the sandbox user

```bash
sudo useradd -r -m -s /bin/bash oc-runner
```

### 3. Start the broker

```bash
uv run python main.py --config-dir config --host 0.0.0.0 --port 8443
```

### 4. Connect from an MCP client

The broker exposes tools over Streamable HTTP at `https://<host>:8443/mcp`. Any MCP-compatible client can connect using mTLS with the client certificate generated above.

## Available Tools

| Tool | Description |
|------|-------------|
| `create_session` | Create a sandboxed execution session with a working directory |
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
    ▼  mTLS (TLS 1.3, client cert required)
┌───────────────────────────────────────┐
│  Auth Middleware                      │
│  → Validate client cert against CA   │
│  → Extract client identity           │
├───────────────────────────────────────┤
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

Every tool invocation is logged as a JSON line to the configured audit log:

```json
{"timestamp": "2026-04-02T18:30:00Z", "event_type": "COMMAND_COMPLETED", "session_id": "abc-123", "tool_name": "execute_command", "exit_code": 0, "duration_ms": 450}
```

Log location is configured in `server.yaml` → `server.logging.audit_log`.

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
│   ├── auth.py             # mTLS authentication
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

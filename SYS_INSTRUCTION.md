# OpenClaw Remote Broker MCP — System Instructions

## Overview

The **OpenClaw Remote Broker MCP** is a secure remote execution gateway that exposes command execution, file system operations, and system management tools over the Model Context Protocol (MCP). It enables AI agents to operate on a remote machine without requiring client-side installation.

**Key Features:**
- Session-based execution with isolated contexts
- Whitelist/blacklist command policy enforcement
- Path sanitization and workspace boundary enforcement
- Structured audit logging for all operations
- cgroups sandboxing

---

## Basic Workflow

```
1. Create a session        → create_session()
2. Execute commands        → execute_command()
3. Read/write files        → read_file(), write_file()
4. List directories        → list_directory()
5. Kill session when done  → kill_session()
```

---

## Available Tools

### Session Management

#### `create_session`
Create a new execution session with sandboxed context.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `id` | string | No | auto-generated | Custom session ID |
| `working_dir` | string | No | user's home | Initial working directory |
| `environment` | object | No | {} | Environment variables |

**Example:**
```json
{
  "id": "my-session-001",
  "working_dir": "/home/user/project",
  "environment": {
    "JAVA_HOME": "/usr/lib/jvm/java-17",
    "NODE_ENV": "development"
  }
}
```

**Response:**
```json
{
  "success": true,
  "session_id": "my-session-001",
  "working_dir": "/home/user/project",
  "created_at": "2026-04-02T10:30:00"
}
```

---

#### `kill_session`
Terminate a session and clean up all its processes.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | — | Session to terminate |
| `force` | boolean | No | false | Use SIGKILL instead of SIGTERM |

**Example:**
```json
{
  "session_id": "my-session-001",
  "force": false
}
```

---

### Command Execution

#### `execute_command`
Execute a whitelisted command within a session.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | — | Session to execute within |
| `argv` | array | Yes | — | Command as array (no shell) |
| `timeout_seconds` | integer | No | 30 | Max execution time (max 300) |
| `stdin_input` | string | No | null | Stdin content to pipe |
| `confirm` | boolean | No | false | Pass confirmation gate |

**Example:**
```json
{
  "session_id": "my-session-001",
  "argv": ["git", "status"],
  "timeout_seconds": 60
}
```

**Response:**
```json
{
  "success": true,
  "exit_code": 0,
  "stdout": "On branch main\nnothing to commit, working tree clean",
  "stderr": "",
  "duration_ms": 45
}
```

**Important Notes:**
- Commands are executed as **argv arrays**, not shell strings
- Shell metacharacters (`|`, `&&`, `>`, etc.) are **not allowed**
- Commands must be in the policy allowlist or not in the blacklist

---

### File Operations

#### `read_file`
Read a file from the session workspace.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | — | Active session |
| `path` | string | Yes | — | File path (absolute or relative) |
| `offset` | integer | No | 0 | Byte offset to start |
| `limit` | integer | No | null | Max bytes to read |

**Example:**
```json
{
  "session_id": "my-session-001",
  "path": "src/main.py",
  "offset": 0,
  "limit": 4096
}
```

**Response:**
```json
{
  "success": true,
  "content": "import sys\n...",
  "size_bytes": 1024,
  "mime_type": "text/x-python"
}
```

---

#### `write_file`
Write content to a file in the session workspace.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | — | Active session |
| `path` | string | Yes | — | File path |
| `content` | string | Yes | — | Text content to write |
| `mode` | string | No | "overwrite" | "overwrite" or "append" |

**Example:**
```json
{
  "session_id": "my-session-001",
  "path": "output/result.txt",
  "content": "Analysis complete.",
  "mode": "overwrite"
}
```

---

#### `list_directory`
List contents of a directory.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | — | Active session |
| `path` | string | No | "." | Directory path |
| `include_hidden` | boolean | No | false | Include hidden files |

**Example:**
```json
{
  "session_id": "my-session-001",
  "path": ".",
  "include_hidden": false
}
```

**Response:**
```json
{
  "success": true,
  "entries": [
    {"name": "src", "type": "directory", "size": null},
    {"name": "README.md", "type": "file", "size": 2048},
    {"name": "main.py", "type": "file", "size": 512}
  ]
}
```

---

#### `download_file`
Download a file in chunks (for large files).

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | — | Active session |
| `path` | string | Yes | — | File to download |
| `chunk_size` | integer | No | 1048576 | Bytes per chunk (1MB) |
| `offset` | integer | No | 0 | Byte offset |

**Usage Pattern:**
```javascript
// Call repeatedly until is_complete = true
let offset = 0;
let chunks = [];
let result;

do {
  result = await download_file({ session_id, path, offset });
  chunks.push(result.chunk_data);
  offset += result.chunk_size;
} while (!result.is_complete);

// Verify integrity
const fullContent = base64Decode(chunks.join(''));
assert(sha256(fullContent) === result.sha256_hash);
```

---

#### `upload_file`
Upload a file in chunks.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | — | Active session |
| `path` | string | Yes | — | Destination path |
| `chunk_data` | string | Yes | — | Base64-encoded data |
| `transfer_id` | string | No | "" | Transfer ID (from first response) |
| `chunk_offset` | integer | No | 0 | Byte offset of this chunk |
| `is_last` | boolean | No | false | Final chunk flag |

**Usage Pattern:**
```javascript
const data = base64Encode(fileContent);
const chunkSize = 1024 * 1024; // 1MB chunks

for (let offset = 0; offset < data.length; offset += chunkSize) {
  const chunk = data.slice(offset, offset + chunkSize);
  const isLast = (offset + chunkSize) >= data.length;
  
  const result = await upload_file({
    session_id,
    path: "uploads/file.bin",
    chunk_data: chunk,
    transfer_id: result?.transfer_id || "",
    chunk_offset: offset,
    is_last: isLast
  });
}
```

---

### System Tools

#### `get_system_info`
Get host system information (no session required).

**Response:**
```json
{
  "cpu_percent": 25.3,
  "memory": {
    "total": 17179869184,
    "available": 8589934592,
    "percent": 50.0
  },
  "disks": [
    {
      "device": "/dev/sda1",
      "mountpoint": "/",
      "total": 536870912000,
      "used": 214748364800,
      "percent": 40.0
    }
  ]
}
```

---

#### `get_process_list`
List running processes, optionally scoped to a session.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | No | null | Filter by session |

---

#### `kill_process`
Kill a process within a session.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | Yes | — | Session the process belongs to |
| `pid` | integer | Yes | — | Process ID to kill |
| `signal` | integer | No | 15 | Signal number (15=SIGTERM, 9=SIGKILL) |

---

## Security Policies

### Command Policies

The broker uses a **blacklist model** — all commands are allowed except those explicitly banned.

#### Banned Commands (cannot execute)
| Command | Reason |
|---------|--------|
| `rm`, `rmdir` | Use file tools instead |
| `dd`, `mkfs`, `fdisk` | Destructive disk operations |
| `shutdown`, `reboot` | System control |
| `kill`, `pkill`, `killall` | Use `kill_process` tool |
| `chmod`, `chown` | Permission changes |
| `sudo`, `su` | Privilege escalation |

#### Confirmation Required (need `confirm: true`)
| Command | Reason |
|---------|--------|
| `python`, `python3` | Arbitrary code execution |
| `pip`, `pip3` | Package installation |
| `curl`, `wget` | Network downloads |
| `ssh`, `scp`, `rsync` | Remote access |

**Example with confirmation:**
```json
{
  "session_id": "my-session-001",
  "argv": ["pip", "install", "requests"],
  "confirm": true
}
```

#### Command Overrides
Some commands have restricted argument patterns:

```yaml
git:
  max_args: 20
  allowed_prefixes:
    - "status"
    - "log"
    - "diff"
    - "clone"
    - "pull"
    - "add"
    - "commit"
```

---

### Path Restrictions

#### Allowed Paths
- `~/` and all subdirectories (user's home)
- `/home/**` (all user homes)
- `/tmp/**` (temporary files)

#### Blocked Paths
- `**/.ssh/**` — SSH keys
- `**/.gnupg/**` — GPG keys
- `**/.aws/**` — AWS credentials
- `**/.env` — Environment files

#### File Limits
| Limit | Value |
|-------|-------|
| Max read size | 10 MB |
| Max write size | 50 MB |
| Blocked extensions | `.exe`, `.dll`, `.so` |

---

## Configuration

### Server Configuration (`config/server.yaml`)

```yaml
server:
  host: "127.0.0.1"
  port: 8080

  logging:
    level: "INFO"           # DEBUG, INFO, WARNING, ERROR
    format: "json"          # json or console
    audit_log: "log/audit.log"
    error_log: "log/audit-errors.log"

  sessions:
    max_session_age: 1800   # 30 minutes
    max_concurrent: 10
    cleanup_interval: 60    # seconds

  timeouts:
    command_default: 30     # seconds
    command_max: 300        # max allowed

  sandbox:
    unprivileged_user: ""   # empty = no privilege dropping
    enable_cgroups: false   # requires root
```

### Policy Configuration (`config/policy.yaml`)

See `config/policy.yaml` for full policy configuration including:
- `banned_commands` — Commands that cannot execute
- `confirmation_required` — Commands needing explicit consent
- `command_overrides` — Per-command restrictions
- `allowed_paths` / `blocked_paths` — Path restrictions
- `file_limits` — Size limits and blocked extensions
- `resource_limits` — cgroups limits (CPU, memory, PIDs)

---

## Error Handling

All tools return a consistent error structure:

```json
{
  "success": false,
  "error_code": "COMMAND_NOT_ALLOWED",
  "error_message": "Command 'rm' is banned: Destructive file deletion"
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `SESSION_001` | Session not found |
| `SESSION_002` | Session expired |
| `SESSION_003` | Max sessions reached |
| `SESSION_004` | Session creation failed |
| `COMMAND_001` | Command not allowed |
| `COMMAND_002` | Command timed out |
| `COMMAND_003` | Confirmation required |
| `PATH_001` | Path outside workspace |
| `PATH_002` | Path blocked by policy |
| `FILE_001` | File not found |
| `FILE_002` | File too large |
| `FILE_003` | Blocked file extension |

---

## Complete Example Workflow

```javascript
// 1. Create a session
const session = await create_session({
  working_dir: "/home/user/project"
});
// → { session_id: "abc123", ... }

// 2. List files
const files = await list_directory({
  session_id: "abc123",
  path: "."
});

// 3. Read a file
const readme = await read_file({
  session_id: "abc123",
  path: "README.md"
});

// 4. Execute a command
const result = await execute_command({
  session_id: "abc123",
  argv: ["git", "status"],
  timeout_seconds: 30
});

// 5. Write a file
await write_file({
  session_id: "abc123",
  path: "notes.txt",
  content: "Task completed successfully."
});

// 6. Get system info
const sysinfo = await get_system_info();

// 7. Clean up
await kill_session({ session_id: "abc123" });
```

---

## Audit Logging

All operations are logged to `log/audit.log` in JSON format:

```json
{
  "timestamp": "2026-04-02T10:30:00.123Z",
  "event_type": "COMMAND_COMPLETED",
  "session_id": "abc123",
  "tool_name": "execute_command",
  "arguments": {"argv": ["git", "status"]},
  "exit_code": 0,
  "duration_ms": 45
}
```

### Event Types
- `SERVER_START`, `SERVER_STOP`
- `SESSION_CREATED`, `SESSION_KILLED`, `SESSION_EXPIRED`
- `COMMAND_STARTED`, `COMMAND_COMPLETED`, `COMMAND_FAILED`
- `FILE_READ`, `FILE_WRITE`, `FILE_LIST`
- `FILE_UPLOAD`, `FILE_DOWNLOAD`
- `PROCESS_KILLED`
- `ERROR` — General errors

---

## Best Practices

1. **Always create a session first** — All tools (except `get_system_info`) require a session
2. **Use argv arrays** — Never pass shell strings with pipes or redirects
3. **Handle chunked transfers** — For files > 1MB, use `download_file`/`upload_file`
4. **Set appropriate timeouts** — Default is 30s, max is 300s
5. **Confirm dangerous commands** — Set `confirm: true` for pip, curl, etc.
6. **Clean up sessions** — Call `kill_session` when done to free resources
7. **Check error codes** — Use `error_code` for programmatic error handling

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Session not found" | Create a session first with `create_session()` |
| "Command not allowed" | Check `config/policy.yaml` for banned commands |
| "Path outside workspace" | Ensure path is within allowed paths |
| "Confirmation required" | Add `confirm: true` to the request |
| "Timeout exceeded" | Increase `timeout_seconds` (max 300) |
| "File too large" | Check `file_limits` in policy config |

---

*Version: 1.0 | Last Updated: 2026-04-02*

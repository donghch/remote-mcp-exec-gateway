<!-- Context: project-intelligence/technical | Priority: critical | Version: 2.0 | Updated: 2026-04-02 -->

# Technical Domain

**Purpose**: Tech stack, architecture, and security patterns for OpenClaw Remote Broker MCP.
**Last Updated**: 2026-04-02

## Quick Reference
**Update Triggers**: Tech stack changes | New MCP tools | Security policy changes
**Audience**: Developers, AI agents

## Primary Stack
| Layer | Technology | Version | Rationale |
|-------|-----------|---------|-----------|
| Language | Python | 3.x | Async support, stdlib subprocess/pathlib |
| Framework | FastAPI | latest | HTTP/SSE transport for MCP |
| Protocol | MCP (Model Context Protocol) | latest | Standard AI agent ↔ tool communication |
| Logging | structlog | latest | Structured, machine-parseable logs |
| Auth | mTLS (mutual TLS) | TLS 1.3 | Client + server certificate verification |

## Architecture
```
Type: Single-user agent-based gateway
Pattern: Transport → Security Guard → Executor → Sandbox
Components:
  1. MCP Transport Layer  - HTTP/SSE, request parsing, response streaming
  2. Security Guard       - Auth, policy enforcement, replay protection
  3. Command Executor     - Safe process spawning (shell=False, argv only)
  4. Session Manager      - Session-scoped execution, process group tracking
  5. File Service         - Read/write/list within allowed workspace roots
  6. Audit Logger         - All tool calls logged with metadata
  7. Sandbox Backend      - Privilege separation, cgroups v2, resource limits
```

## Project Structure
```
mcp-broker/
├── main.py                  # Entry point
├── config/
│   ├── policy.yaml          # Command allowlist, path restrictions
│   └── server.yaml          # TLS, timeouts, resource limits
├── security/
│   ├── auth.py              # mTLS authentication
│   ├── sanitizer.py         # Input validation, path canonicalization
│   └── sandbox.py           # Privilege separation, cgroups
├── tools/
│   ├── command.py           # execute_command (argv-style, no shell)
│   ├── filesystem.py        # read_file, write_file, list_directory
│   └── system.py            # get_system_info, get_process_list, kill_process
├── session/
│   └── manager.py           # Session lifecycle, process group tracking
├── audit/
│   └── logger.py            # Structured audit logging with redaction
└── tests/
```

## MCP Tools
| Tool | Purpose | Key Constraint |
|------|---------|----------------|
| `execute_command` | Run commands on remote machine | argv only, no shell=True |
| `read_file` | Read file from workspace | Path must be within allowed roots |
| `write_file` | Write file to workspace | Canonicalized paths only |
| `list_directory` | List directory contents | Allowed roots only |
| `create_session` | Create execution context | Unique ID, validated working_dir |
| `kill_session` | Terminate session + all processes | Full process group cleanup |
| `get_system_info` | CPU/memory/disk usage | Read-only |
| `download_file` | Stream file to client | Size limits enforced |
| `upload_file` | Receive file from client | Workspace only |

## Naming Conventions
| Type | Convention | Example |
|------|-----------|---------|
| Files | snake_case | `command.py`, `sanitizer.py` |
| Dirs | snake_case | `security/`, `tools/`, `session/` |
| Functions | snake_case | `execute_command`, `validate_path` |
| Classes | PascalCase | `SecurityGuard`, `SessionManager` |
| Config | snake_case | `policy.yaml`, `server.yaml` |

## Code Standards
- **No shell interpretation**: Always `shell=False`, argv-style process invocation
- **Path canonicalization**: All paths resolved to absolute, checked against allowed roots
- **Structured logging**: Use structlog for all log output
- **Policy-based**: Commands must match whitelist in `policy.yaml`
- **Fail closed**: Reject on any validation failure, never assume safe
- **Type hints**: Use Python type hints on all public functions

## Security Requirements
- **mTLS required**: Both client and server present certificates
- **Command whitelist only**: No arbitrary commands, no pipelines, no shell chaining
- **Dedicated unprivileged user**: Never run as root
- **cgroups v2**: CPU, memory, process, timeout limits enforced
- **Input sanitization**: Reject shell injection, path traversal, command substitution
- **Full audit logging**: Every tool call logged with timestamp, session, args, exit code
- **Redaction**: Never log secrets, tokens, credentials, or large file contents
- **Confirmation gate**: Destructive ops (recursive delete, mass overwrite) require approval
- **TLS 1.3 minimum**: All external communication encrypted

## 📂 Codebase References
**Design Spec**: Notion — [OpenClaw Remote Broker MCP](https://www.notion.so/3375e7062f4281fc9b86dc3930fb0cd1)
**Config**: `config/policy.yaml`, `config/server.yaml` (to be created)
**Entry Point**: `main.py` (to be created)

## Related Files
- `business-domain.md` — Why this broker exists
- `business-tech-bridge.md` — Business needs → technical mapping
- `decisions-log.md` — Architecture decision history

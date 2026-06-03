# Demo Unsafe MCP Report

This report is generated from the intentionally unsafe example fixture. It demonstrates the review artifact a maintainer can attach to an issue, pull request, or release note.

```bash
mcp-riskmap scan examples/unsafe-mcp-server --format markdown
```

# MCP Riskmap Report

- Root: `examples/unsafe-mcp-server`
- Findings: 13
- High or above: 7

| Severity | Rule | Location | Message |
| --- | --- | --- | --- |
| low | `REPO-MISSING-AGENTS` | `.:1` | Repository is missing AGENTS.md |
| low | `REPO-MISSING-LICENSE` | `.:1` | Repository is missing LICENSE |
| low | `REPO-MISSING-SECURITY` | `.:1` | Repository is missing SECURITY.md |
| high | `MCP-CONFIG-SHELL` | `mcp.json:4` | MCP server 'unsafe-demo' starts through a shell-capable command. |
| critical | `MCP-CONFIG-REMOTE-INSTALL` | `mcp.json:5` | MCP server 'unsafe-demo' downloads and executes remote content. |
| medium | `MCP-CONFIG-SECRET-ENV` | `mcp.json:7` | MCP server 'unsafe-demo' passes secret-like environment keys: OPENAI_API_KEY. |
| medium | `MCP-CONFIG-BROAD-ENV` | `mcp.json:17` | MCP server 'broad-env-demo' passes broad environment context: APPDATA, HOME, PATH, USERPROFILE. |
| medium | `MCP-CONFIG-NPX-LATEST` | `mcp.json:20` | MCP server 'npx-demo' runs npx with automatic yes. |
| high | `JS-CHILD-PROCESS-EXEC` | `server.js:4` | A JavaScript tool handler can pass input through a shell. |
| high | `JS-SPAWN-SHELL` | `server.js:8` | A JavaScript tool handler enables shell execution. |
| high | `PY-SHELL-TRUE` | `server.py:6` | A Python tool handler can pass input through a shell. |
| high | `PY-EVAL-EXEC` | `server.py:10` | A Python tool handler uses eval or exec. |
| high | `PY-OS-SYSTEM` | `server.py:14` | A Python tool handler invokes a command through the system shell. |

## Remediation

- `REPO-MISSING-AGENTS` at `.:1`: Add AGENTS.md with build, test, review, and security guidance for coding agents.
- `REPO-MISSING-LICENSE` at `.:1`: Add an OSI-approved license such as MIT or Apache-2.0.
- `REPO-MISSING-SECURITY` at `.:1`: Add SECURITY.md with vulnerability reporting and supported version guidance.
- `MCP-CONFIG-SHELL` at `mcp.json:4`: Pin the server executable directly and avoid cmd, powershell, bash, or sh wrappers for untrusted configs.
- `MCP-CONFIG-REMOTE-INSTALL` at `mcp.json:5`: Replace remote install pipelines with pinned packages, checksums, or reviewed local scripts.
- `MCP-CONFIG-SECRET-ENV` at `mcp.json:7`: Pass only the minimum required environment variables and document why each secret is needed.
- `MCP-CONFIG-BROAD-ENV` at `mcp.json:17`: Pass only the specific environment variables the server requires and document why each one is needed.
- `MCP-CONFIG-NPX-LATEST` at `mcp.json:20`: Pin package versions and review the resolved package before using npx -y in shared configs.
- `JS-CHILD-PROCESS-EXEC` at `server.js:4`: Use execFile or spawn with an argument array and validate allowed commands.
- `JS-SPAWN-SHELL` at `server.js:8`: Disable shell mode and pass command arguments as an array.
- `PY-SHELL-TRUE` at `server.py:6`: Use subprocess with an argument list and validate allowed commands or paths before execution.
- `PY-EVAL-EXEC` at `server.py:10`: Replace dynamic evaluation with parsed data structures and explicit dispatch tables.
- `PY-OS-SYSTEM` at `server.py:14`: Replace os.system with subprocess argument lists and explicit allowlists.

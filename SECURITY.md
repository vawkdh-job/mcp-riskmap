# Security Policy

## Reporting a vulnerability

Please open a private security advisory if the repository host supports it. If not, open a minimal public issue that says a security report is available and avoid posting exploit details.

Include:

- Affected version or commit
- Rule or command involved
- Minimal reproduction
- Expected behavior
- Actual behavior

## Supported versions

The `main` branch and latest tagged release receive security fixes.

## Scanner safety

`mcp-riskmap` is designed not to execute scanned MCP servers. Please report any behavior that starts external commands, follows remote install scripts, or sends scanned content to a network service.

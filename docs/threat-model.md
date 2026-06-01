# Threat Model

`mcp-riskmap` reviews MCP and agent-tool repositories before a maintainer runs or shares them.

## Assets

- Developer machines
- Repository secrets and environment variables
- Local files reachable by MCP tools
- Pull request review workflows
- GitHub Code Scanning output

## Trust boundaries

- Scanned repositories are untrusted input.
- MCP config files may contain commands that should not be executed during review.
- Tool descriptions may contain natural-language instructions intended for models rather than humans.

## Design choices

- The scanner reads files and does not start MCP servers.
- The scanner does not send scanned content to external services.
- Findings include remediation text so maintainers can make explicit risk decisions.
- Secret-like evidence is redacted in structured output before JSON or SARIF is written.
- SARIF output is intended for GitHub Code Scanning and includes rule help links, severity metadata, and stable partial fingerprints.

## Out of scope

- Runtime sandboxing
- Dynamic MCP protocol interaction
- Malware classification
- Secret scanning with high-entropy detection beyond key-name based redaction
- Full taint analysis

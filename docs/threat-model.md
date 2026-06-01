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
- SARIF output is intended for GitHub Code Scanning and should not include secret values beyond minimal evidence snippets.

## Out of scope

- Runtime sandboxing
- Dynamic MCP protocol interaction
- Malware classification
- Secret scanning with high-entropy detection
- Full taint analysis

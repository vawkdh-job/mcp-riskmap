# Roadmap

This roadmap is intentionally issue-sized so contributors can pick up small improvements without changing the scanner architecture.

## v0.2.0

- Add inline suppression comments for reviewed findings.
- Add unsafe filesystem write and path traversal candidate rules.
- Add support for more MCP client config locations.
- Add CI examples for consuming `mcp-riskmap` from other repositories.

## v0.3.0

- Add severity profiles for local development, CI, and release blocking.
- Add a packaged GitHub Action wrapper.
- Add SARIF baseline guidance for maintainers who want to ratchet down existing findings.

## Later

- Add Semgrep-compatible pattern export.
- Add optional high-entropy secret checks.
- Add richer language-aware parsing where it materially reduces false positives.

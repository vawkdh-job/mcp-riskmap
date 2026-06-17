# Roadmap

This roadmap is intentionally issue-sized so contributors can pick up small improvements without changing the scanner architecture.

## Recently completed

- Add inline suppression comments for reviewed findings.
- Add path excludes for fixture directories and intentionally unsafe examples.
- Add a packaged GitHub Action wrapper.
- Add a repository self-scan workflow that uploads SARIF.
- Add unsafe filesystem path input candidate rules for Python and JavaScript.
- Add full environment passthrough rules for Python and JavaScript child processes.
- Add support for additional MCP client config names such as `claude.json` and `mcp_config.json`.
- Add severity profiles for local, audit, CI, and release use.
- Add baseline creation and baseline-filtered scans for gradual adoption.
- Add CI examples for consuming `mcp-riskmap` from other repositories.
- Add baseline ratchet documentation for repositories with existing findings.

## v0.2.0

- Add release notes and verification steps for the profile and baseline workflow.
- Refine filesystem path rules with lower-false-positive parsing where real MCP examples show gaps.

## v0.3.0

- Refine filesystem path rules with lower-false-positive parsing where real MCP examples show gaps.
- Improve tool metadata checks for MCP prompt-injection and tool-poisoning patterns.

## Later

- Add Semgrep-compatible pattern export.
- Add optional high-entropy secret checks.
- Add richer language-aware parsing where it materially reduces false positives.

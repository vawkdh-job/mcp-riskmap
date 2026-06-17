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
- Add baseline ratchet audit output for active, stale, and new findings.
- Reduce filesystem path-input false positives for path construction without file access.
- Add an initial tool-selection poisoning pattern for JSON tool metadata.

## v0.3.0

- Refine filesystem path rules with richer language-aware parsing where real MCP examples show gaps.
- Broaden MCP prompt-injection and tool-poisoning metadata checks with examples from real tool descriptors.

## Later

- Add Semgrep-compatible pattern export.
- Add optional high-entropy secret checks.
- Add richer language-aware parsing where it materially reduces false positives.

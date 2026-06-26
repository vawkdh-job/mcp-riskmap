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

- Detect multiline Python and JavaScript shell-execution patterns. See [#28](https://github.com/vawkdh-job/mcp-riskmap/issues/28).
- Reuse tool-selection poisoning detection in source analyzers. See [#29](https://github.com/vawkdh-job/mcp-riskmap/issues/29).
- Add repo-hygiene controls for subdirectory and demo scans. See [#31](https://github.com/vawkdh-job/mcp-riskmap/issues/31).

## Later

- Make baseline identity less sensitive to line-number drift. See [#30](https://github.com/vawkdh-job/mcp-riskmap/issues/30).
- Add Semgrep-compatible pattern export. See [#32](https://github.com/vawkdh-job/mcp-riskmap/issues/32).
- Add optional high-entropy secret checks.
- Add richer language-aware parsing where it materially reduces false positives.

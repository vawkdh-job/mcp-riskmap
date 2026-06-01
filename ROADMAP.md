# Roadmap

This roadmap is intentionally issue-sized so contributors can pick up small improvements without changing the scanner architecture.

## v0.2.0

- Add inline suppression comments for reviewed findings.
- Add unsafe filesystem write and path traversal candidate rules.
- Add support for more MCP client config locations.
- Add safe and unsafe examples for every rule family.

## v0.3.0

- Add severity profiles for local development, CI, and release blocking.
- Add SARIF rule help links that point to `docs/rules.md` anchors.
- Add a packaged GitHub Action wrapper.

## Later

- Add Semgrep-compatible pattern export.
- Add optional high-entropy secret checks.
- Add richer language-aware parsing where it materially reduces false positives.

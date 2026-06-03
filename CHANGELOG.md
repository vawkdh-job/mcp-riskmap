# Changelog

## Unreleased

## v0.1.5 - 2026-06-03

### Added

- Detect MCP config `env` blocks that pass broad local environment context, including whole-environment references and bundled host-context keys.
- Add broad environment examples and remediation notes to the unsafe fixture and rule documentation.

## v0.1.4 - 2026-06-03

### Fixed

- Register filesystem path-input and environment-passthrough rule metadata for SARIF/Code Scanning output.
- Refresh packaged action and Code Scanning examples to use Node 24-based GitHub Actions.
- Mark the safe file-read example's reviewed path-input finding with a rule-specific suppression.

## v0.1.3 - 2026-06-03

### Added

- Python and JavaScript rules for filesystem operations that appear to use user-controlled path input.
- Python and JavaScript rules for full process environment passthrough into child processes.
- Additional MCP config filename support for `claude.json` and `mcp_config.json`.
- PyPI-first install guidance and updated maintainer release checklist notes.

## v0.1.2 - 2026-06-01

### Added

- Inline `mcp-riskmap: ignore RULE-ID` suppressions for reviewed findings.
- `--exclude` support for fixture directories, generated output, and intentionally unsafe examples.
- Composite GitHub Action wrapper plus repository self-scan workflow with SARIF upload.
- Codex for OSS application notes documenting maintainer workflow fit and API credit use.

### Fixed

- Repository hygiene rule docs now match the implemented low severity.

## v0.1.1 - 2026-06-01

### Added

- SARIF rule help links, rule metadata, and partial fingerprints for GitHub Code Scanning.
- Rule documentation with unsafe examples, safer patterns, and review notes for each rule.
- CI matrix for Python 3.10, 3.11, and 3.12 plus package build validation.

### Changed

- JSON and SARIF evidence now redact secret-like values before writing reports.
- Missing or invalid scan targets now return a CLI input error instead of scanning the current working directory.

## v0.1.0 - 2026-06-01

Initial public MVP release.

### Added

- Static MCP config checks for shell wrappers, remote install pipelines, secret-like environment variables, and non-interactive `npx -y` usage.
- Python checks for `subprocess(..., shell=True)`, `os.system`, `eval`, and `exec`.
- JavaScript and TypeScript checks for `child_process.exec` and `spawn(..., { shell: true })`.
- Prompt-injection-like text checks for tool descriptions and nearby source strings.
- Repository hygiene checks for `AGENTS.md`, `SECURITY.md`, and `LICENSE`.
- Table, JSON, Markdown, and SARIF output.
- `--fail-on` support for CI gating.
- Unsafe example repository for scanner demos.
- Unit tests and GitHub Actions CI.

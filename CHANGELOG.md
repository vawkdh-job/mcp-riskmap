# Changelog

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

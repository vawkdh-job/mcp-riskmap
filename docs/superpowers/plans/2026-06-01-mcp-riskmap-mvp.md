# MCP Riskmap MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local-first static auditor that reports risky MCP and agent-tool repository patterns without executing untrusted servers.

**Architecture:** The CLI walks a target directory, runs small analyzers over configuration and source files, normalizes findings into one dataclass, and renders table, JSON, Markdown, or SARIF output. The implementation uses only the Python standard library so it is easy to install, audit, and run on Windows.

**Tech Stack:** Python 3.10+, argparse, pathlib, json, unittest, pyproject entry point.

---

### Task 1: Core Finding Model and Scanner

**Files:**
- Create: `src/mcp_riskmap/models.py`
- Create: `src/mcp_riskmap/scanner.py`
- Test: `tests/test_scanner.py`

- [ ] Write tests that create unsafe MCP config, Python, and JavaScript files and assert high-confidence findings are returned.
- [ ] Run `python -m unittest tests.test_scanner -v` and confirm failures from missing package modules.
- [ ] Implement `Finding`, `Rule`, `ScanResult`, and `scan_path()`.
- [ ] Run the scanner tests and confirm they pass.

### Task 2: Analyzers

**Files:**
- Create: `src/mcp_riskmap/analyzers/config.py`
- Create: `src/mcp_riskmap/analyzers/python_source.py`
- Create: `src/mcp_riskmap/analyzers/js_source.py`
- Create: `src/mcp_riskmap/analyzers/repo_hygiene.py`
- Create: `src/mcp_riskmap/rules/registry.py`

- [ ] Implement regex-based checks for MCP config command risk, Python shell/eval risk, JS child-process risk, tool-description injection strings, and missing OSS hygiene files.
- [ ] Keep rules conservative and explain each finding with remediation text.

### Task 3: Reporters and CLI

**Files:**
- Create: `src/mcp_riskmap/reporters/json_reporter.py`
- Create: `src/mcp_riskmap/reporters/markdown.py`
- Create: `src/mcp_riskmap/reporters/sarif.py`
- Create: `src/mcp_riskmap/reporters/table.py`
- Create: `src/mcp_riskmap/cli.py`
- Test: `tests/test_reporters.py`

- [ ] Write tests for JSON and SARIF output structure.
- [ ] Implement reporters.
- [ ] Implement `mcp-riskmap scan PATH --format table|json|markdown|sarif --output FILE --fail-on high`.

### Task 4: OSS Project Materials

**Files:**
- Create: `README.md`
- Create: `LICENSE`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`
- Create: `AGENTS.md`
- Create: `.github/workflows/ci.yml`
- Create: `docs/threat-model.md`
- Create: `docs/rules.md`
- Create: `docs/github-code-scanning.md`
- Create: `examples/unsafe-mcp-server/*`
- Create: `pyproject.toml`

- [ ] Document the project goal, non-execution safety stance, install commands, examples, and OpenAI Codex for OSS fit.
- [ ] Add CI that runs `python -m unittest discover -s tests -v`.
- [ ] Add a GitHub Code Scanning SARIF example workflow snippet in docs.

### Task 5: Verification

- [ ] Run `python -m unittest discover -s tests -v`.
- [ ] Run `python -m mcp_riskmap.cli scan examples/unsafe-mcp-server --format json`.
- [ ] Run `python -m mcp_riskmap.cli scan examples/unsafe-mcp-server --format sarif --output results.sarif`.
- [ ] Run `git status --short`.

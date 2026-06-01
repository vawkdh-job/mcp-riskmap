# Codex for OSS Application Notes

This page summarizes why `mcp-riskmap` fits maintainer automation and security workflows.

## Project role

`mcp-riskmap` is a local-first static auditor for MCP and agent-tool repositories. It is meant to run before a maintainer starts an untrusted MCP server from a pull request, issue reproduction, or community example.

The project targets a practical gap in the MCP ecosystem:

- MCP configs can start shells, install packages, or pass secrets into local tools.
- Agent-tool source often contains command execution, dynamic evaluation, filesystem access, or prompt-injection-like tool text.
- Maintainers need review artifacts that work in local terminals, pull requests, and GitHub Code Scanning.

## Maintainer workflow

The intended workflow is:

1. Run `mcp-riskmap scan .` locally before reviewing a new MCP server.
2. Add reviewed suppressions with `mcp-riskmap: ignore RULE-ID` when a finding is understood and accepted.
3. Run the GitHub Action on pull requests and upload SARIF to Code Scanning.
4. Use issue templates and rule requests to triage false positives and new MCP risk patterns.
5. Cut small releases with changelog entries and regression tests for every rule change.

## Current readiness

- Static scanner with MCP config, Python, JavaScript, TypeScript, repository hygiene, and prompt-injection-like text checks.
- Table, JSON, Markdown, and SARIF reports.
- Secret-like evidence redaction for structured reports.
- GitHub Action wrapper in `action.yml`.
- CI matrix for Python 3.10, 3.11, and 3.12 plus package build validation.
- Security policy, contribution guide, AGENTS.md, issue templates, changelog, roadmap, and tagged releases.
- Demo review artifact for an intentionally unsafe MCP fixture: [demo-unsafe-report.md](demo-unsafe-report.md).

## Codex and API credit use

Codex/API credits would be used for maintainer work on this repository:

- design new rules from real MCP review cases;
- generate and review regression fixtures;
- triage false positives and issue reports;
- draft documentation and release notes;
- review pull requests before merge;
- improve SARIF output for GitHub Code Scanning.

AI-generated changes must be reviewed by a maintainer before merge. The project should not use Codex Security or API credits to scan repositories without permission from their owners or maintainers.

## Honest status

This is an early public project. The strongest current signal is not broad adoption yet, but a focused fit with MCP security, maintainer automation, SARIF-based review, and Codex-supported OSS maintenance workflows.

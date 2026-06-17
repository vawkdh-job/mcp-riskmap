# mcp-riskmap

[![CI](https://github.com/vawkdh-job/mcp-riskmap/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vawkdh-job/mcp-riskmap/actions/workflows/ci.yml)
[![mcp-riskmap](https://github.com/vawkdh-job/mcp-riskmap/actions/workflows/mcp-riskmap.yml/badge.svg?branch=main)](https://github.com/vawkdh-job/mcp-riskmap/actions/workflows/mcp-riskmap.yml)
[![Release](https://img.shields.io/github/v/release/vawkdh-job/mcp-riskmap)](https://github.com/vawkdh-job/mcp-riskmap/releases)
[![PyPI](https://img.shields.io/pypi/v/mcp-riskmap)](https://pypi.org/project/mcp-riskmap/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`mcp-riskmap` is a local-first static auditor for MCP and agent-tool repositories. It looks for risky MCP configuration, shell-enabled tool handlers, prompt-injection-like tool descriptions, and missing maintainer guidance without starting untrusted MCP servers.

This project is intentionally small and conservative. It is designed for maintainers who want a quick review signal in local development, pull requests, and GitHub Code Scanning.

## Why this exists

MCP servers often expose tools that can touch files, shells, networks, credentials, or local developer state. Reference servers and community examples are useful, but each maintainer still needs a threat model and basic safeguards before sharing configs or accepting tool changes.

`mcp-riskmap` focuses on static signals that are cheap to review:

- MCP config that starts through `cmd`, `powershell`, `bash`, or `sh`
- Remote install pipelines such as `curl ... | sh` or `curl ... | iex`
- Secret-like environment variables passed into MCP servers
- Full process environment passthrough into Python or JavaScript child processes
- Python `subprocess(..., shell=True)`, `os.system`, `eval`, and `exec`
- JavaScript `child_process.exec` and `spawn(..., { shell: true })`
- Python and JavaScript filesystem access that appears to use user-controlled path input
- Tool text that looks like model-control prompt injection
- JSON tool metadata that looks like prompt-injection or tool-poisoning text
- Missing `AGENTS.md`, `SECURITY.md`, or `LICENSE`

## Install

From PyPI:

```bash
python -m pip install --upgrade mcp-riskmap
```

From a checkout:

```bash
python -m pip install -e .
```

From GitHub:

```bash
python -m pip install "git+https://github.com/vawkdh-job/mcp-riskmap.git@v0.2.0"
```

For development without installing:

```bash
$env:PYTHONPATH = "src"
python -m mcp_riskmap.cli scan examples/unsafe-mcp-server
python -m mcp_riskmap.cli --version
```

## Usage

```bash
mcp-riskmap scan .
mcp-riskmap scan . --format json
mcp-riskmap scan . --format markdown --output report.md
mcp-riskmap scan . --format sarif --output results.sarif --fail-on high
mcp-riskmap scan . --exclude "examples/**" --exclude "tests/**"
mcp-riskmap scan . --profile ci
mcp-riskmap baseline . --output mcp-riskmap-baseline.json
mcp-riskmap scan . --baseline mcp-riskmap-baseline.json --profile ci
```

`--fail-on high` returns exit code `1` when at least one finding is high or critical.

Use `--exclude` for reviewed fixture directories, generated output, or intentionally unsafe examples that should not block CI.

Use `--profile` for common fail policies:

- `local`: report findings without failing.
- `audit`: report findings without failing, intended for review artifacts.
- `ci`: fail on high or critical findings.
- `release`: fail on medium, high, or critical findings.

`--fail-on` overrides the selected profile.

Use `baseline` when adopting `mcp-riskmap` in a repository that already has reviewed findings. The baseline records current findings, and `scan --baseline` reports only findings that are not already in the baseline.

See [docs/baseline-ratchet.md](docs/baseline-ratchet.md) for the recommended baseline workflow.

## Examples

- `examples/unsafe-mcp-server/` contains intentionally risky MCP config and tool-handler patterns for scanner demonstrations.
- `examples/safe-mcp-server/` contains a safer file-read pattern using a resolved base directory boundary check.
- `docs/rules.md` contains unsafe examples, safer patterns, and review notes for each rule.

## Example output

```text
SEVERITY  RULE                       LOCATION      MESSAGE
--------  -------------------------  ------------  ------------------------------------------------
CRITICAL  MCP-CONFIG-REMOTE-INSTALL  mcp.json:5    MCP server 'unsafe-demo' downloads and executes...
HIGH      PY-SHELL-TRUE              server.py:6   A Python tool handler can pass input through a shell.
HIGH      JS-CHILD-PROCESS-EXEC      server.js:4   A JavaScript tool handler can pass input through a shell.
```

## Output formats

- `table`: compact terminal output
- `json`: automation-friendly structured output
- `markdown`: issue and release-note friendly report
- `sarif`: GitHub Code Scanning compatible output

Structured outputs redact secret-like evidence values before writing JSON or SARIF.

## Reviewed suppressions

If a maintainer reviews a finding and accepts the risk, add a narrow suppression on the same line or the previous line:

```python
# mcp-riskmap: ignore PY-SHELL-TRUE
subprocess.run(command, shell=True)
```

Use rule-specific suppressions where possible. `mcp-riskmap: ignore` suppresses all rules on the next line and should be reserved for generated or documented fixture code.

## GitHub Action

This repository includes a composite GitHub Action:

```yaml
name: mcp-riskmap

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v6
      - uses: vawkdh-job/mcp-riskmap@v0.1.5
        with:
          path: .
          format: sarif
          output: mcp-riskmap.sarif
          fail-on: high
          exclude: |
            examples/**
            tests/**
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcp-riskmap.sarif
```

Additional copy-paste workflows are available in [docs/ci-examples](docs/ci-examples/).

## Safety stance

`mcp-riskmap` does not execute MCP servers. It reads files and reports static findings. That means it will miss runtime-only behavior, but it is safer for quick review of unknown configs and pull requests.

## Why static only?

Some MCP scanners inspect live tool descriptions by starting configured servers. That can be useful, but it is risky when a reviewer is looking at an unknown repository or pull request. `mcp-riskmap` is meant to run earlier in the review flow: it reads files, flags obvious risk, and produces review artifacts without executing commands from the target project.

## Compared with dynamic scanners

`mcp-riskmap` is not a replacement for dynamic MCP inspection. It is a first-pass guardrail for maintainers who need quick review signals in CI and code review.

| Area | mcp-riskmap | Dynamic scanners |
| --- | --- | --- |
| Starts scanned MCP servers | No | Often yes |
| Safe for unknown PRs | Designed for this | Depends on sandboxing |
| CI/SARIF friendly | Yes | Depends on tool |
| Runtime behavior coverage | Limited | Better |
| Static source/config review | Primary focus | Varies |

## Current limitations

- Rules are conservative regex/static checks, not full taint analysis.
- The scanner does not inspect live MCP tool responses.
- Secret detection is key-name based and does not do high-entropy scanning.
- JavaScript and Python analyzers focus on common high-risk patterns first.

## Roadmap

- Add CI examples for consuming `mcp-riskmap` from other repositories.
- Add rule severity profiles.
- Improve tool metadata checks for MCP prompt-injection and tool-poisoning patterns.
- Add Semgrep-compatible pattern export.

See [ROADMAP.md](ROADMAP.md) for issue-sized milestones.

## OpenAI Codex for OSS fit

This project is intended to be maintained as an open-source security and maintainer automation tool. It includes tests, CI, SARIF output, GitHub Code Scanning support, a published PyPI package, examples, security docs, contribution guidance, AGENTS.md, protected-main workflow notes, and tagged releases.

Codex/API credits would be useful for reviewing rule changes, generating regression tests, triaging issues, improving documentation, and producing release notes. AI output should be reviewed by maintainers before merge.

See [docs/codex-for-oss.md](docs/codex-for-oss.md) for application-specific maintainer workflow notes.

# mcp-riskmap

`mcp-riskmap` is a local-first static auditor for MCP and agent-tool repositories. It looks for risky MCP configuration, shell-enabled tool handlers, prompt-injection-like tool descriptions, and missing maintainer guidance without starting untrusted MCP servers.

This project is intentionally small and conservative. It is designed for maintainers who want a quick review signal in local development, pull requests, and GitHub Code Scanning.

## Why this exists

MCP servers often expose tools that can touch files, shells, networks, credentials, or local developer state. Reference servers and community examples are useful, but each maintainer still needs a threat model and basic safeguards before sharing configs or accepting tool changes.

`mcp-riskmap` focuses on static signals that are cheap to review:

- MCP config that starts through `cmd`, `powershell`, `bash`, or `sh`
- Remote install pipelines such as `curl ... | sh` or `curl ... | iex`
- Secret-like environment variables passed into MCP servers
- Python `subprocess(..., shell=True)`, `os.system`, `eval`, and `exec`
- JavaScript `child_process.exec` and `spawn(..., { shell: true })`
- Tool text that looks like model-control prompt injection
- Missing `AGENTS.md`, `SECURITY.md`, or `LICENSE`

## Install

From a checkout:

```bash
python -m pip install -e .
```

For development without installing:

```bash
$env:PYTHONPATH = "src"
python -m mcp_riskmap.cli scan examples/unsafe-mcp-server
```

## Usage

```bash
mcp-riskmap scan .
mcp-riskmap scan . --format json
mcp-riskmap scan . --format markdown --output report.md
mcp-riskmap scan . --format sarif --output results.sarif --fail-on high
```

`--fail-on high` returns exit code `1` when at least one finding is high or critical.

## Output formats

- `table`: compact terminal output
- `json`: automation-friendly structured output
- `markdown`: issue and release-note friendly report
- `sarif`: GitHub Code Scanning compatible output

## Safety stance

`mcp-riskmap` does not execute MCP servers. It reads files and reports static findings. That means it will miss runtime-only behavior, but it is safer for quick review of unknown configs and pull requests.

## Roadmap

- Add more MCP client config locations
- Add rule suppression with inline comments
- Add rule severity profiles
- Add Semgrep-compatible pattern export
- Add GitHub Action packaging after the first tagged release

## OpenAI Codex for OSS fit

This project is intended to be maintained as an open-source security and maintainer automation tool. Codex/API credits would be useful for reviewing rule changes, generating regression tests, triaging issues, improving documentation, and producing release notes. AI output should be reviewed by maintainers before merge.

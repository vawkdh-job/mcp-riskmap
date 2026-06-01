# Agent Instructions

## Build and test

Use Python 3.10 or newer.

```bash
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Run the CLI locally:

```bash
$env:PYTHONPATH = "src"
python -m mcp_riskmap.cli scan examples/unsafe-mcp-server --format table
```

## Review rules

- Do not add runtime execution of scanned MCP servers.
- Keep findings conservative and actionable.
- Every rule needs remediation text.
- Every behavior change needs a test.
- Prefer standard-library code unless a dependency removes meaningful risk or complexity.

## Security review focus

Check shell execution, path traversal, secret handling, network calls, SARIF correctness, and false-positive risk.

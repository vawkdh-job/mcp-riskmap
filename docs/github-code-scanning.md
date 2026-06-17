# GitHub Code Scanning

`mcp-riskmap` can write SARIF so maintainers can upload findings to GitHub Code Scanning.

Example workflow using the packaged action:

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
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: vawkdh-job/mcp-riskmap@v0.1.1
        with:
          path: .
          format: sarif
          output: results.sarif
          fail-on: high
          exclude: |
            examples/**
            tests/**
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

Use `--exclude` or the action's `exclude` input for reviewed fixture directories, generated output, or intentionally unsafe examples.

For direct CLI use in CI, use a profile instead of repeating a fail threshold:

```yaml
- run: python -m pip install --upgrade mcp-riskmap
- run: mcp-riskmap scan . --profile ci --format sarif --output results.sarif --exclude "examples/**" --exclude "tests/**"
```

For repositories that already have reviewed findings, create a baseline once and check only new findings:

```bash
mcp-riskmap baseline . --output mcp-riskmap-baseline.json --exclude "examples/**" --exclude "tests/**"
mcp-riskmap scan . --baseline mcp-riskmap-baseline.json --profile ci
```

Commit the baseline only after the current findings have been reviewed. Remove baseline entries as the underlying risks are fixed.

See [baseline-ratchet.md](baseline-ratchet.md) for the review workflow and [ci-examples](ci-examples/) for copy-paste workflow files.

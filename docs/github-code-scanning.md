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

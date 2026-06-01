# GitHub Code Scanning

`mcp-riskmap` can write SARIF so maintainers can upload findings to GitHub Code Scanning.

Example workflow:

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
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -e .
      - run: mcp-riskmap scan . --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Save the workflow as `.github/workflows/mcp-riskmap.yml` after publishing the repository.

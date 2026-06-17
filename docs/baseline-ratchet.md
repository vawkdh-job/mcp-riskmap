# Baseline Ratchet

Use a baseline when a repository has existing reviewed findings but maintainers want CI to block new high-risk changes.

## Create the baseline

Review current findings first, then write the baseline:

```bash
mcp-riskmap baseline . --output mcp-riskmap-baseline.json --exclude "examples/**" --exclude "tests/**"
```

Commit `mcp-riskmap-baseline.json` only after the listed findings are accepted as known work.

## Check only new findings

Use the baseline during CI or local review:

```bash
mcp-riskmap scan . --baseline mcp-riskmap-baseline.json --profile ci
```

The scan reports findings that are not present in the baseline. With `--profile ci`, high and critical findings return exit code `1`.

## Ratchet down risk

When a known finding is fixed, remove its entry from `mcp-riskmap-baseline.json` and keep the code change in the same pull request. The baseline should shrink over time.

Do not add new entries to avoid fixing new findings unless a maintainer has reviewed and accepted the risk.

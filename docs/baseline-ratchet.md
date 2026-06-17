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

## Audit baseline drift

Check whether the baseline is shrinking or hiding newly introduced findings:

```bash
mcp-riskmap baseline-check . --baseline mcp-riskmap-baseline.json --exclude "examples/**" --exclude "tests/**"
```

The command reports:

- `active`: baseline entries that still match current findings.
- `stale`: baseline entries that no longer match current findings.
- `new`: current findings that are not in the baseline.

Use `--format json` when another script needs the counts or `new_findings` list. The command returns exit code `1` when any new finding is present, and returns `0` when the only drift is stale baseline entries.

## Ratchet down risk

When a known finding is fixed, remove its entry from `mcp-riskmap-baseline.json` and keep the code change in the same pull request. The baseline should shrink over time.

Do not add new entries to avoid fixing new findings unless a maintainer has reviewed and accepted the risk.

# Maintainer Release Checklist

This checklist covers the account-level release tasks that cannot be completed from a pull request alone.

## PyPI trusted publishing

`mcp-riskmap` uses a GitHub Actions workflow for PyPI publishing. The workflow does not store a PyPI API token. Instead, PyPI should trust GitHub's OpenID Connect identity for this repository.

### One-time PyPI setup

1. Create or sign in to a PyPI account.
2. Verify the account email address.
3. Enable two-factor authentication on the PyPI account.
4. In PyPI, add a pending trusted publisher with these values:

| Field | Value |
| --- | --- |
| PyPI project name | `mcp-riskmap` |
| Owner | `vawkdh-job` |
| Repository name | `mcp-riskmap` |
| Workflow filename | `publish-pypi.yml` |
| Environment name | `pypi` |

5. In GitHub, create the repository environment `pypi` under Settings -> Environments.
6. If desired, require manual approval on the `pypi` environment before publishing.

### First publish

After the trusted publisher is configured and this workflow is on `main`, run the workflow manually:

1. Open Actions -> `publish-pypi`.
2. Select `Run workflow` on `main`.
3. Confirm that the package uploads to https://pypi.org/project/mcp-riskmap/.
4. Verify installation:

```bash
python -m pip install --upgrade mcp-riskmap
mcp-riskmap --version
```

### Future releases

For future releases, update the version in `pyproject.toml` and `src/mcp_riskmap/__init__.py`, merge the release PR, and publish a GitHub release. The `publish-pypi` workflow runs when a non-prerelease GitHub release is published.

## Branch protection

Enable branch protection on `main` so maintainer workflow evidence is stronger and accidental direct pushes are blocked.

Recommended settings:

- Require a pull request before merging.
- Require status checks before merging.
- Require branches to be up to date before merging.
- Required checks:
  - `ci`
  - `mcp-riskmap`
- Block force pushes.
- Block deletions.

GitHub UI path:

1. Open Settings -> Branches.
2. Add a branch protection rule for `main`.
3. Enable the settings above.

GitHub CLI/API option, after `gh auth login` with repository admin rights:

```bash
gh api --method PUT repos/vawkdh-job/mcp-riskmap/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -f required_pull_request_reviews='{}' \
  -F enforce_admins=true \
  -f restrictions=null \
  -f required_status_checks='{"strict":true,"contexts":["ci","mcp-riskmap"]}'
```

Then verify:

```bash
gh api repos/vawkdh-job/mcp-riskmap/branches/main --jq '{name, protected}'
```

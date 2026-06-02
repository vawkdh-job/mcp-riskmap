# Maintainer Release Checklist

This checklist covers recurring release tasks and the account-level settings that protect the release path.

## Current setup

`mcp-riskmap` is published through GitHub Actions and PyPI trusted publishing. The workflow does not store a PyPI API token. PyPI trusts GitHub's OpenID Connect identity for this repository.

| Area | Current value |
| --- | --- |
| PyPI project | `mcp-riskmap` |
| GitHub owner | `vawkdh-job` |
| GitHub repository | `mcp-riskmap` |
| Publish workflow | `.github/workflows/publish-pypi.yml` |
| PyPI environment | `pypi` |
| Package page | https://pypi.org/project/mcp-riskmap/ |

The `main` branch is protected. Required checks should match the jobs that run on pull requests:

- `scan`
- `package`
- `test py3.10`
- `test py3.11`
- `test py3.12`

On the GitHub branch protection page, leave `Allow force pushes` and `Allow deletions` unchecked.

## Future release flow

1. Update the version in `pyproject.toml`.
2. Update the version in `src/mcp_riskmap/__init__.py`.
3. Add release notes under `CHANGELOG.md`.
4. Open a pull request and wait for all required checks.
5. Merge to `main`.
6. Create a non-prerelease GitHub release for the same version tag.
7. Confirm that the `publish-pypi` workflow completed successfully.
8. Verify installation from a clean environment:

```bash
python -m pip install --upgrade mcp-riskmap
mcp-riskmap --version
```

## PyPI trusted publisher recovery

If the PyPI project or trusted publisher configuration is recreated, use these values:

| Field | Value |
| --- | --- |
| PyPI project name | `mcp-riskmap` |
| Owner | `vawkdh-job` |
| Repository name | `mcp-riskmap` |
| Workflow filename | `publish-pypi.yml` |
| Environment name | `pypi` |

In GitHub, keep the repository environment `pypi` under Settings -> Environments. Requiring manual approval on the environment is acceptable for release control.

## Branch protection recovery

If branch protection is recreated, use these settings for `main`:

- Require a pull request before merging.
- Require status checks before merging.
- Require branches to be up to date before merging.
- Require the five checks listed in Current setup.
- Do not allow force pushes.
- Do not allow deletions.

GitHub CLI/API option, after `gh auth login` with repository admin rights:

```bash
gh api --method PUT repos/vawkdh-job/mcp-riskmap/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -f required_pull_request_reviews='{}' \
  -F enforce_admins=true \
  -f restrictions=null \
  -f required_status_checks='{"strict":true,"contexts":["scan","package","test py3.10","test py3.11","test py3.12"]}'
```

Then verify:

```bash
gh api repos/vawkdh-job/mcp-riskmap/branches/main --jq '{name, protected}'
```

# Contributing

Thanks for improving `mcp-riskmap`.

## Development setup

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Run tests:

```bash
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

## Rule changes

Every new rule should include:

- A stable rule id
- A short title
- Severity
- Message
- Remediation text
- At least one test that fails before the rule is implemented
- A safe example and an unsafe example when practical

Prefer conservative findings over noisy guesses.

If a test fixture intentionally contains unsafe code, either place it under an excluded fixture path in CI or add a narrow `mcp-riskmap: ignore RULE-ID` suppression with a clear reason nearby.

## Pull requests

Keep pull requests focused. Include a short explanation of the risk being detected and why static analysis is enough for the first version.

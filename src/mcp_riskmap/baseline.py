from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_riskmap.models import Finding, ScanResult

BASELINE_VERSION = 1


class BaselineError(ValueError):
    pass


def finding_key(finding: Finding) -> str:
    return "|".join([finding.rule_id, finding.path, str(finding.line), finding.message])


def render_baseline(result: ScanResult) -> str:
    findings = [
        {
            "key": finding_key(finding),
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "message": finding.message,
        }
        for finding in result.findings
    ]
    return json.dumps(
        {
            "version": BASELINE_VERSION,
            "root": str(result.root),
            "summary": {"findings": len(findings)},
            "findings": findings,
        },
        indent=2,
        sort_keys=True,
    )


def load_baseline(path: str | Path) -> set[str]:
    baseline_path = Path(path)
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read baseline file: {baseline_path}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline file is not valid JSON: {baseline_path}") from exc

    findings = data.get("findings")
    if not isinstance(findings, list):
        raise BaselineError("baseline file must contain a findings array")

    keys: set[str] = set()
    for item in findings:
        key = _key_from_item(item)
        if key:
            keys.add(key)
    return keys


def filter_baselined_findings(result: ScanResult, baseline_keys: set[str]) -> ScanResult:
    return ScanResult(
        root=result.root,
        findings=[finding for finding in result.findings if finding_key(finding) not in baseline_keys],
    )


def _key_from_item(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    key = item.get("key")
    if isinstance(key, str) and key:
        return key

    rule_id = item.get("rule_id")
    path = item.get("path")
    line = item.get("line")
    message = item.get("message")
    if not isinstance(rule_id, str) or not isinstance(path, str) or not isinstance(message, str):
        return None
    return "|".join([rule_id, path, str(line or 1), message])

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_riskmap.models import Finding, ScanResult

BASELINE_VERSION = 1


class BaselineError(ValueError):
    pass


@dataclass(frozen=True)
class BaselineAudit:
    root: Path
    baseline_keys: set[str]
    current_keys: set[str]
    active_keys: set[str]
    stale_keys: set[str]
    new_findings: list[Finding]

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "summary": {
                "baseline": len(self.baseline_keys),
                "current": len(self.current_keys),
                "active": len(self.active_keys),
                "stale": len(self.stale_keys),
                "new": len(self.new_findings),
            },
            "active_keys": sorted(self.active_keys),
            "stale_keys": sorted(self.stale_keys),
            "new_findings": [finding.as_dict() for finding in self.new_findings],
        }


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


def audit_baseline(result: ScanResult, baseline_keys: set[str]) -> BaselineAudit:
    current_keys = {finding_key(finding) for finding in result.findings}
    return BaselineAudit(
        root=result.root,
        baseline_keys=baseline_keys,
        current_keys=current_keys,
        active_keys=baseline_keys & current_keys,
        stale_keys=baseline_keys - current_keys,
        new_findings=[finding for finding in result.findings if finding_key(finding) not in baseline_keys],
    )


def render_baseline_audit(audit: BaselineAudit, report_format: str) -> str:
    if report_format == "json":
        return json.dumps(audit.as_dict(), indent=2, sort_keys=True)

    rows = [
        ("baseline", len(audit.baseline_keys)),
        ("current", len(audit.current_keys)),
        ("active", len(audit.active_keys)),
        ("stale", len(audit.stale_keys)),
        ("new", len(audit.new_findings)),
    ]
    width = max(len(label) for label, _ in rows)
    return "\n".join(f"{label.upper():<{width}}  {count}" for label, count in rows)


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

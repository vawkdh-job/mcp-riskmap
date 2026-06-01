from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_riskmap.redaction import redact_text


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    message: str
    path: str
    line: int = 1
    remediation: str = ""
    evidence: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "remediation": self.remediation,
            "evidence": redact_text(self.evidence),
        }


@dataclass(frozen=True)
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)

    def count_at_or_above(self, severity: str) -> int:
        threshold = SEVERITY_ORDER[severity]
        return sum(1 for finding in self.findings if SEVERITY_ORDER[finding.severity] >= threshold)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "summary": {
                "findings": len(self.findings),
                "critical": self.count_at_or_above("critical"),
                "high_or_above": self.count_at_or_above("high"),
                "medium_or_above": self.count_at_or_above("medium"),
            },
            "findings": [finding.as_dict() for finding in self.findings],
        }

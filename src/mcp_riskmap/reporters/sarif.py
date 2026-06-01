from __future__ import annotations

import json

from mcp_riskmap.models import ScanResult


def render_sarif(result: ScanResult) -> str:
    rules = {}
    sarif_results = []
    for finding in result.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.remediation or finding.message},
            "defaultConfiguration": {"level": _level_for(finding.severity)},
        }
        sarif_results.append(
            {
                "ruleId": finding.rule_id,
                "level": _level_for(finding.severity),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": max(finding.line, 1)},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-riskmap",
                        "informationUri": "https://github.com/kdh/mcp-riskmap",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def _level_for(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"

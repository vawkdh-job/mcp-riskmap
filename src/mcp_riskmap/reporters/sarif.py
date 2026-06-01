from __future__ import annotations

import hashlib
import json

from mcp_riskmap.models import ScanResult
from mcp_riskmap.redaction import redact_text
from mcp_riskmap.rules.registry import RULES


def render_sarif(result: ScanResult) -> str:
    rules = {}
    sarif_results = []
    for finding in result.findings:
        metadata = RULES.metadata_for(finding.rule_id)
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.remediation or finding.message},
            "helpUri": metadata.help_uri,
            "help": {"text": metadata.description},
            "defaultConfiguration": {"level": _level_for(finding.severity)},
            "properties": {
                "precision": metadata.precision,
                "security-severity": metadata.security_severity,
                "tags": list(metadata.tags),
            },
        }
        fingerprint = _fingerprint_for(finding)
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
                "partialFingerprints": {
                    "primaryLocationLineHash": fingerprint,
                },
                "properties": {
                    "severity": finding.severity,
                    "evidence": redact_text(finding.evidence),
                    "remediation": finding.remediation,
                    "precision": metadata.precision,
                    "security-severity": metadata.security_severity,
                    "tags": list(metadata.tags),
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
                        "informationUri": "https://github.com/vawkdh-job/mcp-riskmap",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": "mcp-riskmap"},
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


def _fingerprint_for(finding) -> str:
    source = f"{finding.rule_id}\0{finding.path}\0{finding.line}\0{finding.message}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()[:32]

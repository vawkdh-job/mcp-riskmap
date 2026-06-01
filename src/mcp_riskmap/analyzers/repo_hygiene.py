from __future__ import annotations

from pathlib import Path

from mcp_riskmap.models import Finding


def analyze_repo_hygiene(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    checks = [
        ("AGENTS.md", "REPO-MISSING-AGENTS", "Repository is missing AGENTS.md", "Add AGENTS.md with build, test, review, and security guidance for coding agents."),
        ("SECURITY.md", "REPO-MISSING-SECURITY", "Repository is missing SECURITY.md", "Add SECURITY.md with vulnerability reporting and supported version guidance."),
        ("LICENSE", "REPO-MISSING-LICENSE", "Repository is missing LICENSE", "Add an OSI-approved license such as MIT or Apache-2.0."),
    ]
    for filename, rule_id, title, remediation in checks:
        if not (root / filename).exists() and not (root / f"{filename}.md").exists():
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity="low",
                    message=title,
                    path=".",
                    line=1,
                    remediation=remediation,
                    evidence=filename,
                )
            )
    return findings

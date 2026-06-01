from __future__ import annotations

from mcp_riskmap.models import ScanResult


def render_markdown(result: ScanResult) -> str:
    lines = [
        "# MCP Riskmap Report",
        "",
        f"- Root: `{result.root}`",
        f"- Findings: {len(result.findings)}",
        f"- High or above: {result.count_at_or_above('high')}",
        "",
    ]
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.extend(["| Severity | Rule | Location | Message |", "| --- | --- | --- | --- |"])
    for finding in result.findings:
        location = f"{finding.path}:{finding.line}"
        message = finding.message.replace("|", "\\|")
        lines.append(f"| {finding.severity} | `{finding.rule_id}` | `{location}` | {message} |")

    lines.extend(["", "## Remediation"])
    for finding in result.findings:
        lines.append(f"- `{finding.rule_id}` at `{finding.path}:{finding.line}`: {finding.remediation}")
    return "\n".join(lines)

from __future__ import annotations

from mcp_riskmap.models import ScanResult


def render_table(result: ScanResult) -> str:
    if not result.findings:
        return f"No findings for {result.root}"

    rows = [("SEVERITY", "RULE", "LOCATION", "MESSAGE")]
    for finding in result.findings:
        rows.append(
            (
                finding.severity.upper(),
                finding.rule_id,
                f"{finding.path}:{finding.line}",
                finding.message,
            )
        )

    widths = [min(max(len(row[index]) for row in rows), 48) for index in range(4)]
    rendered = []
    for index, row in enumerate(rows):
        rendered.append("  ".join(_fit(value, widths[col]) for col, value in enumerate(row)))
        if index == 0:
            rendered.append("  ".join("-" * width for width in widths))
    return "\n".join(rendered)


def _fit(value: str, width: int) -> str:
    if len(value) <= width:
        return value.ljust(width)
    return value[: max(width - 1, 1)] + "…"

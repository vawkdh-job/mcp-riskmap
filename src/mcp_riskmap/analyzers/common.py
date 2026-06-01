from __future__ import annotations

import re
from pathlib import Path

SUPPRESSION_RE = re.compile(r"mcp-riskmap:\s*ignore(?:\s+([A-Z0-9_, -]+))?", re.IGNORECASE)


def relative_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def is_suppressed(lines: list[str], line_index: int, rule_id: str) -> bool:
    comment_lines = [lines[line_index]]
    if line_index > 0:
        comment_lines.append(lines[line_index - 1])
    return any(_suppresses_rule(line, rule_id) for line in comment_lines)


def _suppresses_rule(line: str, rule_id: str) -> bool:
    match = SUPPRESSION_RE.search(line)
    if not match:
        return False
    raw_rules = match.group(1)
    if not raw_rules:
        return True
    rules = {rule.strip().upper() for rule in re.split(r"[,\s]+", raw_rules) if rule.strip()}
    return "ALL" in rules or rule_id.upper() in rules

from __future__ import annotations

from pathlib import Path

from mcp_riskmap.analyzers.config import analyze_config, is_candidate as is_config_candidate
from mcp_riskmap.analyzers.js_source import analyze_javascript
from mcp_riskmap.analyzers.python_source import analyze_python
from mcp_riskmap.analyzers.repo_hygiene import analyze_repo_hygiene
from mcp_riskmap.models import Finding, ScanResult

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules", "dist", "build"}
JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}


def scan_path(path: str | Path) -> ScanResult:
    root = Path(path).resolve()
    findings: list[Finding] = []

    for file_path in _iter_files(root):
        suffix = file_path.suffix.lower()
        if is_config_candidate(file_path):
            findings.extend(analyze_config(root, file_path))
        if suffix == ".py":
            findings.extend(analyze_python(root, file_path))
        elif suffix in JS_SUFFIXES:
            findings.extend(analyze_javascript(root, file_path))

    findings.extend(analyze_repo_hygiene(root))
    findings.sort(key=lambda finding: (finding.path, finding.line, finding.rule_id))
    return ScanResult(root=root, findings=findings)


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return

    for candidate in root.rglob("*"):
        if candidate.is_dir():
            continue
        if any(part in SKIP_DIRS for part in candidate.parts):
            continue
        yield candidate

from __future__ import annotations

from collections.abc import Sequence
from fnmatch import fnmatch
from pathlib import Path

from mcp_riskmap.analyzers.common import relative_path
from mcp_riskmap.analyzers.config import analyze_config, is_candidate as is_config_candidate
from mcp_riskmap.analyzers.js_source import analyze_javascript
from mcp_riskmap.analyzers.python_source import analyze_python
from mcp_riskmap.analyzers.repo_hygiene import analyze_repo_hygiene
from mcp_riskmap.models import Finding, ScanResult

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules", "dist", "build"}
JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}


class ScanInputError(ValueError):
    pass


def scan_path(path: str | Path, exclude_patterns: Sequence[str] | None = None) -> ScanResult:
    root = Path(path).resolve()
    if not root.exists():
        raise ScanInputError(f"scan target does not exist: {root}")
    if not root.is_file() and not root.is_dir():
        raise ScanInputError(f"scan target is not a file or directory: {root}")

    findings: list[Finding] = []
    excludes = tuple(_normalize_pattern(pattern) for pattern in (exclude_patterns or ()) if pattern)

    for file_path in _iter_files(root, excludes):
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


def _iter_files(root: Path, exclude_patterns: Sequence[str]):
    if root.is_file():
        if not _is_excluded(root, root, exclude_patterns):
            yield root
        return

    for candidate in root.rglob("*"):
        if candidate.is_dir():
            continue
        if any(part in SKIP_DIRS for part in candidate.parts):
            continue
        if _is_excluded(root, candidate, exclude_patterns):
            continue
        yield candidate


def _is_excluded(root: Path, candidate: Path, exclude_patterns: Sequence[str]) -> bool:
    if not exclude_patterns:
        return False
    rel = relative_path(root, candidate)
    return any(fnmatch(rel, pattern) or fnmatch(candidate.name, pattern) for pattern in exclude_patterns)


def _normalize_pattern(pattern: str) -> str:
    normalized = pattern.replace("\\", "/").strip()
    if normalized.endswith("/"):
        return f"{normalized}**"
    return normalized

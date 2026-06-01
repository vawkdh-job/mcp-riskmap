from __future__ import annotations

import re
from pathlib import Path

from mcp_riskmap.analyzers.common import is_suppressed, relative_path, read_text
from mcp_riskmap.models import Finding

SHELL_TRUE_RE = re.compile(r"subprocess\.(run|call|Popen|check_call|check_output)\s*\([^)]*shell\s*=\s*True")
EVAL_EXEC_RE = re.compile(r"\b(eval|exec)\s*\(")


def analyze_python(root: Path, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel = relative_path(root, path)
    lines = read_text(path).splitlines()
    for line_index, line in enumerate(lines):
        line_number = line_index + 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if SHELL_TRUE_RE.search(stripped) and not is_suppressed(lines, line_index, "PY-SHELL-TRUE"):
            findings.append(
                Finding(
                    rule_id="PY-SHELL-TRUE",
                    title="Python tool invokes subprocess with shell=True",
                    severity="high",
                    message="A Python tool handler can pass input through a shell.",
                    path=rel,
                    line=line_number,
                    remediation="Use subprocess with an argument list and validate allowed commands or paths before execution.",
                    evidence=stripped[:240],
                )
            )

        # mcp-riskmap: ignore PY-OS-SYSTEM
        if "os.system(" in stripped and not is_suppressed(lines, line_index, "PY-OS-SYSTEM"):
            findings.append(
                Finding(
                    rule_id="PY-OS-SYSTEM",
                    title="Python tool invokes os.system",
                    severity="high",
                    message="A Python tool handler invokes a command through the system shell.",
                    path=rel,
                    line=line_number,
                    remediation="Replace os.system with subprocess argument lists and explicit allowlists.",
                    evidence=stripped[:240],
                )
            )

        if EVAL_EXEC_RE.search(stripped) and not is_suppressed(lines, line_index, "PY-EVAL-EXEC"):
            findings.append(
                Finding(
                    rule_id="PY-EVAL-EXEC",
                    title="Python tool evaluates dynamic code",
                    severity="high",
                    message="A Python tool handler uses eval or exec.",
                    path=rel,
                    line=line_number,
                    remediation="Replace dynamic evaluation with parsed data structures and explicit dispatch tables.",
                    evidence=stripped[:240],
                )
            )

        # mcp-riskmap: ignore TOOL-DESCRIPTION-INJECTION
        if ("ignore previous" in stripped.lower() or "system prompt" in stripped.lower()) and not is_suppressed(lines, line_index, "TOOL-DESCRIPTION-INJECTION"):
            findings.append(
                Finding(
                    rule_id="TOOL-DESCRIPTION-INJECTION",
                    title="Tool text contains prompt-injection-like wording",
                    severity="medium",
                    message="Tool text includes phrases often used to override model instructions.",
                    path=rel,
                    line=line_number,
                    remediation="Keep tool descriptions factual and remove instructions that target the model control plane.",
                    evidence=stripped[:240],
                )
            )

    return findings

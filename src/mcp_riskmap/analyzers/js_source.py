from __future__ import annotations

from pathlib import Path

from mcp_riskmap.analyzers.common import is_suppressed, relative_path, read_text
from mcp_riskmap.models import Finding


def analyze_javascript(root: Path, path: Path) -> list[Finding]:
    text = read_text(path)
    rel = relative_path(root, path)
    child_process_context = "child_process" in text or "node:child_process" in text
    findings: list[Finding] = []

    lines = text.splitlines()
    for line_index, line in enumerate(lines):
        line_number = line_index + 1
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        # mcp-riskmap: ignore PY-EVAL-EXEC
        if child_process_context and ("exec(" in stripped or ".exec(" in stripped) and not is_suppressed(lines, line_index, "JS-CHILD-PROCESS-EXEC"):
            findings.append(
                Finding(
                    rule_id="JS-CHILD-PROCESS-EXEC",
                    title="JavaScript tool invokes child_process.exec",
                    severity="high",
                    message="A JavaScript tool handler can pass input through a shell.",
                    path=rel,
                    line=line_number,
                    remediation="Use execFile or spawn with an argument array and validate allowed commands.",
                    evidence=stripped[:240],
                )
            )

        if "spawn(" in stripped and "shell: true" in stripped and not is_suppressed(lines, line_index, "JS-SPAWN-SHELL"):
            findings.append(
                Finding(
                    rule_id="JS-SPAWN-SHELL",
                    title="JavaScript tool invokes spawn with shell enabled",
                    severity="high",
                    message="A JavaScript tool handler enables shell execution.",
                    path=rel,
                    line=line_number,
                    remediation="Disable shell mode and pass command arguments as an array.",
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

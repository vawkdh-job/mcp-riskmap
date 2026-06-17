from __future__ import annotations

import re
from pathlib import Path

from mcp_riskmap.analyzers.common import is_suppressed, relative_path, read_text
from mcp_riskmap.models import Finding

FILESYSTEM_OP_RE = re.compile(
    r"\bfs\.(readFile|readFileSync|writeFile|writeFileSync|rm|rmSync|unlink|unlinkSync|readdir|createReadStream|createWriteStream)\s*\("
    r"|\bsendFile\s*\("
)
USER_PATH_RE = re.compile(
    r"\b(req|request|params|query|body|arguments|toolInput|userInput|input|filename|fileName|file_path|filePath|upload|download|targetPath|sourcePath)\b",
    re.IGNORECASE,
)
PATH_TRAVERSAL_LITERAL_RE = re.compile(r"[\"'`][^\"'`]*\.\.[^\"'`]*[\"'`]")
ENV_PASSTHROUGH_RE = re.compile(r"(\benv\s*:\s*process\.env|\.\.\.\s*process\.env)")


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

        if _looks_like_user_controlled_filesystem_path(stripped) and not is_suppressed(lines, line_index, "JS-FILE-PATH-INPUT"):
            findings.append(
                Finding(
                    rule_id="JS-FILE-PATH-INPUT",
                    title="JavaScript tool uses user-controlled filesystem path input",
                    severity="medium",
                    message="A JavaScript tool appears to use user-controlled path input in a filesystem operation.",
                    path=rel,
                    line=line_number,
                    remediation="Resolve paths against an allowlisted base directory and reject paths that escape it before reading, writing, moving, or deleting files.",
                    evidence=stripped[:240],
                )
            )

        if ENV_PASSTHROUGH_RE.search(stripped) and not is_suppressed(lines, line_index, "JS-ENV-PASSTHROUGH"):
            findings.append(
                Finding(
                    rule_id="JS-ENV-PASSTHROUGH",
                    title="JavaScript tool passes the full process environment",
                    severity="medium",
                    message="A JavaScript tool appears to pass the full process environment into a child process.",
                    path=rel,
                    line=line_number,
                    remediation="Pass a minimal env object containing only the variables the child process requires.",
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


def _looks_like_user_controlled_filesystem_path(line: str) -> bool:
    if not FILESYSTEM_OP_RE.search(line):
        return False
    return bool(USER_PATH_RE.search(line) or PATH_TRAVERSAL_LITERAL_RE.search(line))

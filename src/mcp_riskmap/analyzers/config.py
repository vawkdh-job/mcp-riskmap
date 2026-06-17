from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_riskmap.analyzers.common import relative_path, read_text
from mcp_riskmap.models import Finding

CONFIG_NAMES = {
    "mcp.json",
    "mcp.config.json",
    "claude_desktop_config.json",
    "settings.json",
}

SECRET_KEY_RE = re.compile(r"(api[_-]?key|token|secret|password|credential)", re.IGNORECASE)


def is_candidate(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES or ".mcp" in path.name.lower()


def analyze_config(root: Path, path: Path) -> list[Finding]:
    text = read_text(path)
    if "mcpServers" not in text and "mcp_servers" not in text and "tools" not in text:
        return []

    findings: list[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return findings

    path_text = relative_path(root, path)
    for metadata_text in _tool_metadata_strings(data):
        if _looks_like_prompt_injection(metadata_text):
            findings.append(
                Finding(
                    rule_id="TOOL-DESCRIPTION-INJECTION",
                    title="Tool metadata contains prompt-injection-like wording",
                    severity="medium",
                    message="Tool metadata includes phrases often used to override model instructions.",
                    path=path_text,
                    line=_line_for(text, metadata_text),
                    remediation="Keep tool names, descriptions, and schemas factual; remove instructions that target the model control plane.",
                    evidence=metadata_text[:240],
                )
            )
            break

    servers = _server_entries(data)
    for server_name, server in servers:
        command = str(server.get("command", ""))
        args = [str(arg) for arg in server.get("args", [])]
        command_line = " ".join([command, *args]).lower()

        if _looks_like_shell_wrapper(command, args):
            findings.append(
                Finding(
                    rule_id="MCP-CONFIG-SHELL",
                    title="MCP server starts through a shell wrapper",
                    severity="high",
                    message=f"MCP server '{server_name}' starts through a shell-capable command.",
                    path=path_text,
                    line=_line_for(text, command),
                    remediation="Pin the server executable directly and avoid cmd, powershell, bash, or sh wrappers for untrusted configs.",
                    evidence=" ".join([command, *args])[:240],
                )
            )

        if "curl " in command_line and ("| sh" in command_line or "| iex" in command_line):
            findings.append(
                Finding(
                    rule_id="MCP-CONFIG-REMOTE-INSTALL",
                    title="MCP config pipes remote content into an interpreter",
                    severity="critical",
                    message=f"MCP server '{server_name}' downloads and executes remote content.",
                    path=path_text,
                    line=_line_for(text, "curl"),
                    remediation="Replace remote install pipelines with pinned packages, checksums, or reviewed local scripts.",
                    evidence=" ".join([command, *args])[:240],
                )
            )

        env = server.get("env")
        if isinstance(env, dict):
            secret_keys = sorted(key for key in env if SECRET_KEY_RE.search(str(key)))
            if secret_keys:
                findings.append(
                    Finding(
                        rule_id="MCP-CONFIG-SECRET-ENV",
                        title="MCP config passes secret-like environment variables",
                        severity="medium",
                        message=f"MCP server '{server_name}' passes secret-like environment keys: {', '.join(secret_keys)}.",
                        path=path_text,
                        line=_line_for(text, secret_keys[0]),
                        remediation="Pass only the minimum required environment variables and document why each secret is needed.",
                        evidence=", ".join(secret_keys),
                    )
                )

        if command.lower() == "npx" and any(arg == "-y" for arg in args):
            findings.append(
                Finding(
                    rule_id="MCP-CONFIG-NPX-LATEST",
                    title="MCP config allows non-interactive npx package execution",
                    severity="medium",
                    message=f"MCP server '{server_name}' runs npx with automatic yes.",
                    path=path_text,
                    line=_line_for(text, "npx"),
                    remediation="Pin package versions and review the resolved package before using npx -y in shared configs.",
                    evidence=" ".join([command, *args])[:240],
                )
            )

    return findings


def _server_entries(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    if not isinstance(servers, dict):
        return []
    return [(str(name), server) for name, server in servers.items() if isinstance(server, dict)]


def _looks_like_shell_wrapper(command: str, args: list[str]) -> bool:
    shell_commands = {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "bash", "sh"}
    if Path(command).name.lower() in shell_commands:
        return True
    shell_flags = {"/c", "-c", "-command", "/command"}
    return any(arg.lower() in shell_flags for arg in args)


def _tool_metadata_strings(value: Any) -> list[str]:
    strings: list[str] = []
    _collect_tool_metadata_strings(value, strings)
    return strings


def _collect_tool_metadata_strings(value: Any, strings: list[str]) -> None:
    metadata_keys = {"description", "title", "instructions", "prompt", "systemPrompt"}
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key in metadata_keys and isinstance(item, str):
                strings.append(item)
            else:
                _collect_tool_metadata_strings(item, strings)
    elif isinstance(value, list):
        for item in value:
            _collect_tool_metadata_strings(item, strings)


def _looks_like_prompt_injection(text: str) -> bool:
    lowered = text.lower()
    # mcp-riskmap: ignore TOOL-DESCRIPTION-INJECTION
    return "ignore previous" in lowered or "system prompt" in lowered


def _line_for(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle and needle in line:
            return index
    return 1

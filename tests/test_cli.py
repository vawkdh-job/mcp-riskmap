import json
import io
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mcp_riskmap import __version__
from mcp_riskmap.cli import main


class CliTests(unittest.TestCase):
    def test_version_flag_prints_package_version(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = main(["--version"])

        self.assertEqual(0, code)
        self.assertIn(__version__, stdout.getvalue())

    def test_version_flag_works_from_console_entrypoint(self):
        stdout = io.StringIO()

        with patch.object(sys, "argv", ["mcp-riskmap", "--version"]):
            with redirect_stdout(stdout):
                code = main()

        self.assertEqual(0, code)
        self.assertIn(__version__, stdout.getvalue())

    def test_scan_missing_path_returns_input_error(self):
        stderr = io.StringIO()
        missing_path = Path(tempfile.gettempdir()) / "mcp-riskmap-missing-target"

        with redirect_stderr(stderr):
            code = main(["scan", str(missing_path)])

        self.assertEqual(2, code)
        self.assertIn("does not exist", stderr.getvalue())

    def test_scan_exclude_option_omits_matching_paths(self):
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            live = root / "live"
            fixtures.mkdir()
            live.mkdir()
            unsafe_source = textwrap.dedent(
                """
                import subprocess
                subprocess.run(command, shell=True)
                """
            ).strip()
            (fixtures / "server.py").write_text(unsafe_source, encoding="utf-8")
            (live / "server.py").write_text(unsafe_source, encoding="utf-8")

            with redirect_stdout(stdout):
                code = main(["scan", str(root), "--format", "json", "--exclude", "fixtures/**"])

        data = json.loads(stdout.getvalue())
        finding_paths = {finding["path"] for finding in data["findings"]}
        self.assertEqual(0, code)
        self.assertNotIn("fixtures/server.py", finding_paths)
        self.assertIn("live/server.py", finding_paths)

    def test_scan_profile_ci_fails_on_high_findings(self):
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("import subprocess\nsubprocess.run(command, shell=True)\n", encoding="utf-8")

            with redirect_stdout(stdout):
                code = main(["scan", str(root), "--profile", "ci", "--format", "json"])

        data = json.loads(stdout.getvalue())
        self.assertEqual(1, code)
        self.assertIn("PY-SHELL-TRUE", {finding["rule_id"] for finding in data["findings"]})

    def test_scan_profile_local_does_not_fail_on_findings(self):
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("import subprocess\nsubprocess.run(command, shell=True)\n", encoding="utf-8")

            with redirect_stdout(stdout):
                code = main(["scan", str(root), "--profile", "local", "--format", "json"])

        self.assertEqual(0, code)

    def test_scan_baseline_filters_existing_findings_but_keeps_new_findings(self):
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_path = root / "mcp-riskmap-baseline.json"
            (root / "known.py").write_text("import subprocess\nsubprocess.run(command, shell=True)\n", encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                baseline_code = main(["baseline", str(root), "--output", str(baseline_path)])

            (root / "new.py").write_text("import subprocess\nsubprocess.run(command, shell=True)\n", encoding="utf-8")

            with redirect_stdout(stdout):
                scan_code = main(
                    [
                        "scan",
                        str(root),
                        "--baseline",
                        str(baseline_path),
                        "--format",
                        "json",
                        "--fail-on",
                        "high",
                    ]
                )

        data = json.loads(stdout.getvalue())
        self.assertEqual(0, baseline_code)
        self.assertEqual(1, scan_code)
        finding_paths = {finding["path"] for finding in data["findings"]}
        self.assertNotIn("known.py", finding_paths)
        self.assertIn("new.py", finding_paths)

    def test_baseline_check_reports_active_stale_and_new_findings(self):
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_path = root / "mcp-riskmap-baseline.json"
            for name in ("AGENTS.md", "SECURITY.md", "LICENSE"):
                (root / name).write_text("present\n", encoding="utf-8")
            unsafe_source = "import subprocess\nsubprocess.run(command, shell=True)\n"
            (root / "known.py").write_text(unsafe_source, encoding="utf-8")
            (root / "fixed.py").write_text(unsafe_source, encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                baseline_code = main(["baseline", str(root), "--output", str(baseline_path)])

            (root / "fixed.py").unlink()
            (root / "new.py").write_text(unsafe_source, encoding="utf-8")

            with redirect_stdout(stdout):
                check_code = main(["baseline-check", str(root), "--baseline", str(baseline_path), "--format", "json"])

        data = json.loads(stdout.getvalue())
        self.assertEqual(0, baseline_code)
        self.assertEqual(1, check_code)
        self.assertEqual(
            {
                "baseline": 2,
                "current": 2,
                "active": 1,
                "stale": 1,
                "new": 1,
            },
            data["summary"],
        )
        self.assertEqual(["new.py"], [finding["path"] for finding in data["new_findings"]])

    def test_baseline_check_allows_stale_baseline_without_new_findings(self):
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_path = root / "mcp-riskmap-baseline.json"
            for name in ("AGENTS.md", "SECURITY.md", "LICENSE"):
                (root / name).write_text("present\n", encoding="utf-8")
            unsafe_source = "import subprocess\nsubprocess.run(command, shell=True)\n"
            (root / "fixed.py").write_text(unsafe_source, encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                baseline_code = main(["baseline", str(root), "--output", str(baseline_path)])

            (root / "fixed.py").unlink()

            with redirect_stdout(stdout):
                check_code = main(["baseline-check", str(root), "--baseline", str(baseline_path), "--format", "json"])

        data = json.loads(stdout.getvalue())
        self.assertEqual(0, baseline_code)
        self.assertEqual(0, check_code)
        self.assertEqual(1, data["summary"]["stale"])
        self.assertEqual(0, data["summary"]["new"])


if __name__ == "__main__":
    unittest.main()

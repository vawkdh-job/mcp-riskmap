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


if __name__ == "__main__":
    unittest.main()

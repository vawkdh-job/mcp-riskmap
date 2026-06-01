import io
import unittest
from contextlib import redirect_stdout

from mcp_riskmap import __version__
from mcp_riskmap.cli import main


class CliTests(unittest.TestCase):
    def test_version_flag_prints_package_version(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = main(["--version"])

        self.assertEqual(0, code)
        self.assertIn(__version__, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path

from mcp_riskmap.models import Finding, ScanResult
from mcp_riskmap.reporters.json_reporter import render_json
from mcp_riskmap.reporters.markdown import render_markdown
from mcp_riskmap.reporters.sarif import render_sarif
from mcp_riskmap.reporters.table import render_table


class ReporterTests(unittest.TestCase):
    def test_render_json_contains_findings(self):
        result = _sample_result()

        data = json.loads(render_json(result))

        self.assertEqual(1, data["summary"]["findings"])
        self.assertEqual("PY-SHELL-TRUE", data["findings"][0]["rule_id"])

    def test_render_sarif_contains_required_schema_and_locations(self):
        result = _sample_result()

        data = json.loads(render_sarif(result))

        self.assertEqual("2.1.0", data["version"])
        driver = data["runs"][0]["tool"]["driver"]
        self.assertEqual("mcp-riskmap", driver["name"])
        self.assertEqual("https://github.com/vawkdh-job/mcp-riskmap", driver["informationUri"])
        self.assertEqual("PY-SHELL-TRUE", data["runs"][0]["results"][0]["ruleId"])
        self.assertEqual("server.py", data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])

    def test_markdown_and_table_render_human_readable_summary(self):
        result = _sample_result()

        self.assertIn("PY-SHELL-TRUE", render_markdown(result))
        self.assertIn("server.py", render_table(result))


def _sample_result() -> ScanResult:
    return ScanResult(
        root=Path(tempfile.gettempdir()),
        findings=[
            Finding(
                rule_id="PY-SHELL-TRUE",
                title="Python tool invokes subprocess with shell=True",
                severity="high",
                message="A Python tool handler can pass input through a shell.",
                path="server.py",
                line=7,
                remediation="Use subprocess with an argument list.",
                evidence="subprocess.run(command, shell=True)",
            )
        ],
    )


if __name__ == "__main__":
    unittest.main()

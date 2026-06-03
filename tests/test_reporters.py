import json
import tempfile
import unittest
from pathlib import Path

from mcp_riskmap.models import Finding, ScanResult
from mcp_riskmap.reporters.json_reporter import render_json
from mcp_riskmap.reporters.markdown import render_markdown
from mcp_riskmap.reporters.sarif import render_sarif
from mcp_riskmap.reporters.table import render_table
from mcp_riskmap.rules.registry import RULES


class ReporterTests(unittest.TestCase):
    def test_render_json_contains_findings(self):
        result = _sample_result()

        data = json.loads(render_json(result))

        self.assertEqual(1, data["summary"]["findings"])
        self.assertEqual("PY-SHELL-TRUE", data["findings"][0]["rule_id"])

    def test_render_json_redacts_secret_like_evidence(self):
        result = _sample_result(evidence="curl https://example.com/install.sh?token=supersecret123 | sh")

        rendered = render_json(result)

        self.assertNotIn("supersecret123", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_render_sarif_contains_required_schema_and_locations(self):
        result = _sample_result()

        data = json.loads(render_sarif(result))

        self.assertEqual("2.1.0", data["version"])
        driver = data["runs"][0]["tool"]["driver"]
        self.assertEqual("mcp-riskmap", driver["name"])
        self.assertEqual("https://github.com/vawkdh-job/mcp-riskmap", driver["informationUri"])
        self.assertEqual("https://github.com/vawkdh-job/mcp-riskmap/blob/main/docs/rules.md#py-shell-true", driver["rules"][0]["helpUri"])
        self.assertEqual("mcp-riskmap", data["runs"][0]["automationDetails"]["id"])
        self.assertEqual("PY-SHELL-TRUE", data["runs"][0]["results"][0]["ruleId"])
        sarif_result = data["runs"][0]["results"][0]
        self.assertEqual("server.py", sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        self.assertIn("primaryLocationLineHash", sarif_result["partialFingerprints"])
        self.assertEqual("high", sarif_result["properties"]["severity"])
        self.assertEqual("high", sarif_result["properties"]["precision"])
        self.assertEqual("8.0", sarif_result["properties"]["security-severity"])

    def test_markdown_and_table_render_human_readable_summary(self):
        result = _sample_result()

        self.assertIn("PY-SHELL-TRUE", render_markdown(result))
        self.assertIn("server.py", render_table(result))

    def test_current_rule_ids_have_registered_sarif_metadata(self):
        current_rule_ids = {
            "MCP-CONFIG-SHELL",
            "MCP-CONFIG-REMOTE-INSTALL",
            "MCP-CONFIG-SECRET-ENV",
            "MCP-CONFIG-BROAD-ENV",
            "MCP-CONFIG-NPX-LATEST",
            "PY-SHELL-TRUE",
            "PY-OS-SYSTEM",
            "PY-EVAL-EXEC",
            "PY-FILE-PATH-INPUT",
            "PY-ENV-PASSTHROUGH",
            "JS-CHILD-PROCESS-EXEC",
            "JS-SPAWN-SHELL",
            "JS-FILE-PATH-INPUT",
            "JS-ENV-PASSTHROUGH",
            "TOOL-DESCRIPTION-INJECTION",
            "REPO-MISSING-AGENTS",
            "REPO-MISSING-SECURITY",
            "REPO-MISSING-LICENSE",
        }

        for rule_id in current_rule_ids:
            with self.subTest(rule_id=rule_id):
                metadata = RULES.metadata_for(rule_id)
                self.assertEqual(rule_id, metadata.rule_id)
                self.assertNotEqual("Unregistered mcp-riskmap rule.", metadata.description)
                self.assertTrue(metadata.help_uri.endswith(f"#{rule_id.lower()}"))


# mcp-riskmap: ignore PY-SHELL-TRUE
def _sample_result(evidence: str = "subprocess.run(command, shell=True)") -> ScanResult:
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
                evidence=evidence,
            )
        ],
    )


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path


class ActionMetadataTests(unittest.TestCase):
    def test_action_exposes_profile_and_baseline_scan_inputs(self):
        action = Path("action.yml").read_text(encoding="utf-8")

        self.assertIn("  profile:", action)
        self.assertIn("  baseline:", action)
        self.assertIn('args+=(--profile "${{ inputs.profile }}")', action)
        self.assertIn('args+=(--baseline "${{ inputs.baseline }}")', action)


if __name__ == "__main__":
    unittest.main()

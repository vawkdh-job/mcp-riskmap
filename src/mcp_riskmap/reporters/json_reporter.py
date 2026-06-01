from __future__ import annotations

import json

from mcp_riskmap.models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.as_dict(), indent=2, sort_keys=True)

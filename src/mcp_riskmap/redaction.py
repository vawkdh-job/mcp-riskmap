from __future__ import annotations

import re

SECRET_VALUE_RE = re.compile(
    r"(?i)\b(token|api[_-]?key|secret|password|credential|authorization)\b"
    r"(\s*[:=]\s*|/)"
    r"([^\s&|,'\"]+)"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")


def redact_text(value: str) -> str:
    if not value:
        return value
    redacted = SECRET_VALUE_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", value)
    redacted = BEARER_RE.sub("Bearer [REDACTED]", redacted)
    return redacted

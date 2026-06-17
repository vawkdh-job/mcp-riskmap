from __future__ import annotations


PROFILE_FAIL_ON = {
    "local": None,
    "audit": None,
    "ci": "high",
    "release": "medium",
}


def fail_threshold(profile: str, explicit_fail_on: str | None) -> str | None:
    if explicit_fail_on:
        return explicit_fail_on
    return PROFILE_FAIL_ON[profile]

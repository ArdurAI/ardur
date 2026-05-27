"""Shared primitives for hook adapter and fixture modules.

Extracted from duplicated definitions across ``claude_code_hook.py``,
``gemini_cli_hook.py``, and ``codex_app_server_fixture.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping


def utc_timestamp() -> str:
    """Return the current UTC wall-clock time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def without_empty_values(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of ``payload`` with ``None``, empty-string,
    and empty-list items removed, recursively for nested mappings."""
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None or value == "":
            continue
        if isinstance(value, Mapping):
            nested = without_empty_values(value)
            if nested:
                clean[key] = nested
            continue
        if isinstance(value, list):
            nested_list = [item for item in value if item not in (None, "")]
            if nested_list:
                clean[key] = nested_list
            continue
        clean[key] = value
    return clean

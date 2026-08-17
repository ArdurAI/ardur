"""Tests for ``python -m vibap.proxy`` path argument validation.

The standalone proxy entry point must reject empty or whitespace-only path
arguments before materializing default keys, state, logs, or TLS material paths.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest


_PROXY_PATH_ARGS = (
    "keys-dir",
    "log-path",
    "state-dir",
    "tls-cert",
    "tls-key",
)


@pytest.mark.parametrize("arg_name", _PROXY_PATH_ARGS)
@pytest.mark.parametrize("value", ("", "   "), ids=("empty", "whitespace"))
def test_proxy_rejects_empty_or_whitespace_path_arg(
    arg_name: str,
    value: str,
) -> None:
    """Path args must fail closed with structured JSON, not cwd side effects."""

    result = subprocess.run(
        [sys.executable, "-m", "vibap.proxy", f"--{arg_name}", value],
        capture_output=True,
        text=True,
        timeout=4,
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"] == "proxy_path_arg_invalid"
    assert payload["error_code"] == "proxy_path_arg_invalid"
    assert payload["condition"] == "proxy_path_arg_invalid"
    assert f"--{arg_name}" in payload["message"]
    assert "non-empty path" in payload["message"]
    assert "empty or whitespace-only path argument" in payload["detail"]
    assert isinstance(payload["next_steps"], list)
    assert len(payload["next_steps"]) >= 1

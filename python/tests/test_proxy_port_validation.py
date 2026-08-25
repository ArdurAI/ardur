"""Tests for ``python -m vibap.proxy --port`` domain validation.

These tests verify that out-of-range port values produce a structured JSON
error response (condition ``proxy_port_invalid``) on stdout with exit code 1,
instead of leaking a raw ``OverflowError`` traceback to stderr at socket bind
time. This mirrors the port-validation pattern already established for
``ardur start --port`` and ``ardur hub --port`` in ``cli.py``.
"""

from __future__ import annotations

import json
import subprocess
import sys


def _run_proxy(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run ``python -m vibap.proxy`` with the given extra args (4s timeout)."""
    return subprocess.run(
        [sys.executable, "-m", "vibap.proxy", *args],
        capture_output=True,
        text=True,
        timeout=4,
    )


def test_port_negative_one_emits_structured_error() -> None:
    """``--port -1`` must not leak an OverflowError traceback."""
    result = _run_proxy(["--port", "-1"])
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "OverflowError" not in result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"] == "proxy_port_invalid"
    assert payload["error_code"] == "proxy_port_invalid"
    assert payload["condition"] == "proxy_port_invalid"
    assert "TCP port range" in payload["message"]
    assert "0 through 65535" in payload["detail"]
    assert isinstance(payload["next_steps"], list)
    assert len(payload["next_steps"]) >= 1


def test_port_above_max_emits_structured_error() -> None:
    """``--port 99999`` must not leak an OverflowError traceback."""
    result = _run_proxy(["--port", "99999"])
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "OverflowError" not in result.stderr
    payload = json.loads(result.stdout)
    assert payload["condition"] == "proxy_port_invalid"


def test_port_zero_does_not_trigger_validation_error() -> None:
    """``--port 0`` is valid (OS assigns ephemeral); must not emit port_invalid.

    The proxy will try to bind and may succeed or fail for other reasons
    (TLS cert generation, etc.), but it must not emit the structured
    ``proxy_port_invalid`` error.
    """
    try:
        result = _run_proxy(["--port", "0"])
    except subprocess.TimeoutExpired:
        # Server started successfully and is listening — that's fine.
        # Port 0 is valid.
        return
    # If it exited, it should not be the port validation error.
    if result.stdout.strip():
        try:
            payload = json.loads(result.stdout)
            assert payload.get("condition") != "proxy_port_invalid"
        except json.JSONDecodeError:
            pass  # Non-JSON output is fine — it's not our structured error.

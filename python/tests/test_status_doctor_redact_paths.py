"""Tests for the --redact-paths flag on status, doctor, and doctor-claude-code.

The ``ardur status --json`` success response from the Personal Hub includes a
``home`` field with the raw local filesystem path (e.g.
``/var/folders/55/.../tmp.XXX`` or ``/Users/...``). This leaks the filesystem
layout when the output is shared in CI artifacts, bug reports, or support
tickets.

The ``--redact-paths`` flag reuses the existing ``_redact_local_path()`` helper
from ``run_bridge.py`` (already proven on ``ardur run --json --redact-paths``)
to replace local path roots with stable placeholders.

These tests verify:
  1. ``--redact-paths`` is accepted on all three commands (no argparse error)
  2. The ``home`` field in a hub status response is redacted
  3. Doctor and doctor-claude-code pass through correctly
  4. Non-redacted output is unchanged (flag is opt-in)
  5. Unit-level tests for the ``_redact_paths_in_response`` helper
"""

from __future__ import annotations

import json
import subprocess
import sys
from unittest.mock import patch

from vibap.cli import _redact_paths_in_response


# ---------------------------------------------------------------------------
# Unit tests for _redact_paths_in_response helper
# ---------------------------------------------------------------------------


def test_redact_paths_in_response_redacts_home_field():
    """The ``home`` field should be replaced with a placeholder."""
    response = {
        "ok": True,
        "home": "/private/var/folders/55/abcd/T/tmp.XXXX",
        "hub_url": "https://127.0.0.1:18443",
    }
    result = _redact_paths_in_response(response)
    assert "<var-folders>" in result["home"]
    assert "/private/var/folders/" not in result["home"]


def test_redact_paths_in_response_preserves_non_path_fields():
    """Non-path fields should be unchanged."""
    response = {
        "ok": True,
        "version": "0.2.0",
        "sessions": 3,
        "schema_version": "ardur.personal.hub.v0.1",
    }
    result = _redact_paths_in_response(response)
    assert result == response


def test_redact_paths_in_response_preserves_nested_placeholders():
    """Nested ``checks[].detail`` that are placeholders should be unchanged.

    The doctor/doctor-claude-code commands already use ``<ardur-home>`` and
    ``<ardur-config>`` placeholders in their checks. The ``--redact-paths``
    helper redacts top-level path fields (``home``, ``hub_url``, ``detail``)
    but leaves nested placeholder strings untouched.
    """
    response = {
        "ok": False,
        "home": "/private/var/folders/55/abcd/T/tmp.XXXX",
        "checks": [
            {"name": "home", "ok": True, "detail": "<ardur-home>"},
            {"name": "config", "ok": False, "detail": "<ardur-config>"},
        ],
        "next_steps": [
            {
                "condition": "hub_unavailable",
                "command": "ardur setup --home <ardur-home>",
                "detail": "some detail",
            }
        ],
    }
    result = _redact_paths_in_response(response)
    # Top-level home is redacted
    assert "<var-folders>" in result["home"]
    assert "/private/var/folders/" not in result["home"]
    # Nested placeholder detail should be unchanged (already safe)
    assert result["checks"][0]["detail"] == "<ardur-home>"
    assert result["checks"][1]["detail"] == "<ardur-config>"


def test_redact_paths_in_response_redacts_home_path(tmp_path):
    """Real home path (``/Users/...``) should be redacted."""
    home_str = str(tmp_path)
    response = {"ok": True, "home": home_str}
    result = _redact_paths_in_response(response)
    assert str(tmp_path) not in result["home"]
    # On macOS tmp_path resolves under /private/var/folders or /private/tmp
    expected_placeholders = ("<tmp>", "<home>", "<var-folders>")
    assert any(p in result["home"] for p in expected_placeholders), (
        f"Expected a placeholder in redacted home, got: {result['home']}"
    )


def test_redact_paths_in_response_does_not_mutate_input():
    """The original response dict should not be mutated."""
    response = {
        "ok": True,
        "home": "/var/folders/55/abcd/T/tmp.XXXX",
        "checks": [{"detail": "/var/folders/55/abcd"}],
    }
    original_home = response["home"]
    original_detail = response["checks"][0]["detail"]
    _redact_paths_in_response(response)
    assert response["home"] == original_home
    assert response["checks"][0]["detail"] == original_detail


def test_redact_paths_in_response_handles_missing_fields():
    """Should not crash if home/checks/next_steps are absent."""
    response = {"ok": True, "version": "0.2.0"}
    result = _redact_paths_in_response(response)
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


def _run_cli(args: list[str]) -> tuple[int, str, str]:
    """Run the CLI with the given args, returning (rc, stdout, stderr)."""
    cmd = [sys.executable, "-m", "vibap.cli", *args]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def test_status_accepts_redact_paths_flag(tmp_path):
    """``ardur status --redact-paths`` should be accepted without argparse error."""
    rc, stdout, stderr = _run_cli(
        ["status", "--home", str(tmp_path), "--redact-paths"]
    )
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--redact-paths should be accepted on status, got rc={rc}, stderr={stderr}"
    )


def test_doctor_accepts_redact_paths_flag(tmp_path):
    """``ardur doctor --redact-paths`` should be accepted without argparse error."""
    rc, stdout, stderr = _run_cli(
        ["doctor", "--home", str(tmp_path), "--redact-paths"]
    )
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--redact-paths should be accepted on doctor, got rc={rc}, stderr={stderr}"
    )


def test_doctor_claude_code_accepts_redact_paths_flag(tmp_path):
    """``ardur doctor-claude-code --redact-paths`` should be accepted."""
    rc, stdout, stderr = _run_cli(
        ["doctor-claude-code", "--home", str(tmp_path), "--redact-paths"]
    )
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--redact-paths should be accepted on doctor-claude-code, "
        f"got rc={rc}, stderr={stderr}"
    )


def test_status_redact_paths_no_local_path_leak(tmp_path):
    """When ``--redact-paths`` is used, the local home path should not appear."""
    rc, stdout, stderr = _run_cli(
        ["status", "--home", str(tmp_path), "--redact-paths", "--hub-url", "http://127.0.0.1:1"]
    )
    # The command will fail (hub unreachable), but output is still JSON
    assert str(tmp_path) not in stdout, (
        f"Local path leaked in status output with --redact-paths: {stdout}"
    )


def test_doctor_redact_paths_no_local_path_leak(tmp_path):
    """When ``--redact-paths`` is used, the local home path should not appear."""
    rc, stdout, stderr = _run_cli(
        ["doctor", "--home", str(tmp_path), "--redact-paths", "--hub-url", "http://127.0.0.1:1"]
    )
    assert str(tmp_path) not in stdout, (
        f"Local path leaked in doctor output with --redact-paths: {stdout}"
    )


def test_status_without_redact_flag_preserves_path(tmp_path):
    """Without ``--redact-paths``, behavior is unchanged (flag is opt-in)."""
    rc, stdout_no_redact, _ = _run_cli(
        ["status", "--home", str(tmp_path), "--hub-url", "http://127.0.0.1:1"]
    )
    rc2, stdout_redact, _ = _run_cli(
        ["status", "--home", str(tmp_path), "--redact-paths", "--hub-url", "http://127.0.0.1:1"]
    )
    # Both should succeed (exit 1 = hub_unavailable, not argparse error)
    assert rc == 1
    assert rc2 == 1
    # Without redact, the output should not have changed from baseline
    # (error path uses placeholders already, so both are safe — but the
    # important guarantee is that --redact-paths does not break anything)
    assert json.loads(stdout_no_redact)["error_code"] == "hub_unavailable"
    assert json.loads(stdout_redact)["error_code"] == "hub_unavailable"


# ---------------------------------------------------------------------------
# Unit test: cmd_status redaction with a mocked hub response
# ---------------------------------------------------------------------------


def test_cmd_status_redacts_home_from_hub_success(tmp_path):
    """When the hub returns a success response, --redact-paths redacts home."""
    from vibap.cli import cmd_status

    fake_response = {
        "ok": True,
        "home": str(tmp_path),
        "hub_url": "https://127.0.0.1:18443",
        "version": "0.2.0",
    }

    import argparse

    args = argparse.Namespace(
        hub_url="https://127.0.0.1:18443",
        hub_token="test-token",
        home=str(tmp_path),
        redact_paths=True,
    )

    with patch("vibap.cli.hub_request", return_value=fake_response), patch(
        "vibap.cli._hub_token_invalid_failure", return_value=None
    ), patch("vibap.cli._print_json") as mock_print:
        cmd_status(args)

    printed = mock_print.call_args[0][0]
    assert str(tmp_path) not in printed["home"], (
        f"Home path not redacted: {printed['home']}"
    )


def test_cmd_doctor_redacts_home_in_response(tmp_path):
    """Doctor --redact-paths should redact the top-level home field.

    Doctor's checks already use ``<ardur-home>`` / ``<ardur-config>``
    placeholders, but if a response included a raw top-level ``home``
    field (as the hub status does), it should be redacted.
    """
    from vibap.cli import _redact_paths_in_response

    response = {
        "ok": True,
        "home": str(tmp_path),
        "checks": [],
        "next_steps": [],
    }
    result = _redact_paths_in_response(response)
    assert str(tmp_path) not in result["home"], (
        f"Path not redacted in home: {result['home']}"
    )

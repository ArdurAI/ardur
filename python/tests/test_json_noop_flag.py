"""Tests for the --json no-op flag on always-JSON commands.

Several Ardur CLI commands always emit JSON output regardless of flags.
Users who expect a --json flag (present on ``ardur run --json`` and
``ardur verify --json``) were getting ``unrecognized arguments: --json``
when they tried it on these commands. The fix adds an accepted-but-no-op
``--json`` flag to: status, doctor, doctor-claude-code, setup, kill-switch,
uninstall.

These tests verify that:
  1. ``--json`` is accepted (no argparse error)
  2. Output is identical with and without ``--json``
  3. The flag is a no-op (does not change behavior)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run_cli(args: list[str], *, home: str | None = None) -> tuple[int, str, str]:
    """Run the CLI with the given args, returning (rc, stdout, stderr)."""
    cmd = [sys.executable, "-m", "vibap.cli", *args]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def test_status_accepts_json_flag(tmp_path):
    """``ardur status --json`` should not error with 'unrecognized arguments'."""
    rc, stdout, stderr = _run_cli(["status", "--home", str(tmp_path), "--json"])
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--json should be accepted on status, got rc={rc}, stderr={stderr}"
    )


def test_status_json_is_noop(tmp_path):
    """``ardur status --json`` output should match ``ardur status`` (without --json)."""
    rc1, out1, _ = _run_cli(["status", "--home", str(tmp_path)])
    rc2, out2, _ = _run_cli(["status", "--home", str(tmp_path), "--json"])
    assert rc1 == rc2
    assert out1 == out2


def test_doctor_accepts_json_flag(tmp_path):
    """``ardur doctor --json`` should not error with 'unrecognized arguments'."""
    rc, stdout, stderr = _run_cli(["doctor", "--home", str(tmp_path), "--json"])
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--json should be accepted on doctor, got rc={rc}, stderr={stderr}"
    )


def test_doctor_json_is_noop(tmp_path):
    """``ardur doctor --json`` output should match ``ardur doctor``."""
    rc1, out1, _ = _run_cli(["doctor", "--home", str(tmp_path)])
    rc2, out2, _ = _run_cli(["doctor", "--home", str(tmp_path), "--json"])
    assert rc1 == rc2
    assert out1 == out2


def test_doctor_claude_code_accepts_json_flag(tmp_path):
    """``ardur doctor-claude-code --json`` should not error."""
    rc, stdout, stderr = _run_cli(
        ["doctor-claude-code", "--home", str(tmp_path), "--json"]
    )
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--json should be accepted on doctor-claude-code, got rc={rc}, stderr={stderr}"
    )


def test_doctor_claude_code_json_is_noop(tmp_path):
    """``ardur doctor-claude-code --json`` output should match without --json."""
    rc1, out1, _ = _run_cli(["doctor-claude-code", "--home", str(tmp_path)])
    rc2, out2, _ = _run_cli(["doctor-claude-code", "--home", str(tmp_path), "--json"])
    assert rc1 == rc2
    assert out1 == out2


def test_setup_accepts_json_flag(tmp_path):
    """``ardur setup --json`` should not error with 'unrecognized arguments'."""
    rc, stdout, stderr = _run_cli(
        ["setup", "--home", str(tmp_path / "ardur-home"), "--json"]
    )
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--json should be accepted on setup, got rc={rc}, stderr={stderr}"
    )


def test_kill_switch_accepts_json_flag():
    """``ardur kill-switch --json`` should not error with 'unrecognized arguments'."""
    # Use a fake proxy URL so the command fails fast but still parses args
    rc, stdout, stderr = _run_cli(
        ["kill-switch", "--proxy-url", "http://127.0.0.1:1", "--json"]
    )
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--json should be accepted on kill-switch, got rc={rc}, stderr={stderr}"
    )


def test_uninstall_accepts_json_flag(tmp_path):
    """``ardur uninstall --json`` should not error with 'unrecognized arguments'."""
    rc, stdout, stderr = _run_cli(["uninstall", "--home", str(tmp_path), "--json"])
    assert rc != 2 or "unrecognized arguments" not in stderr, (
        f"--json should be accepted on uninstall, got rc={rc}, stderr={stderr}"
    )


def test_uninstall_json_is_noop(tmp_path):
    """``ardur uninstall --json`` output should match without --json."""
    rc1, out1, _ = _run_cli(["uninstall", "--home", str(tmp_path)])
    rc2, out2, _ = _run_cli(["uninstall", "--home", str(tmp_path), "--json"])
    assert rc1 == rc2
    assert out1 == out2


def test_json_help_text_documents_noop():
    """Help text should clarify that --json is a no-op on always-JSON commands."""
    for cmd in ["status", "doctor", "doctor-claude-code", "setup", "kill-switch", "uninstall"]:
        rc, stdout, stderr = _run_cli([cmd, "--help"])
        assert rc == 0
        combined = stdout + stderr
        assert "--json" in combined, f"{cmd} --help should mention --json"
        assert "always JSON" in combined or "consistency" in combined, (
            f"{cmd} --help should document that --json is a no-op"
        )

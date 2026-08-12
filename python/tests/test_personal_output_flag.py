"""Tests for --output flag on personal commands (doctor, status, setup, doctor-claude-code, protect claude-code).

These five commands produce JSON output and support --redact-paths, but were the
only JSON-producing commands lacking --output.  Every other report command
(verify, posture, preflight, telemetry, evidence correlate, run, adapter reports)
already had --output.  This closes the consistency gap.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from vibap import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_cli(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict, str]:
    """Invoke the CLI, return (exit_code, parsed_json_stdout, stderr)."""
    exit_code = cli.main(argv)
    captured = capsys.readouterr()
    return exit_code, json.loads(captured.out), captured.err


def _owner_only(path: str | Path) -> bool:
    """True when the file at *path* has owner-only permissions (0o600)."""
    mode = stat.S_IMODE(os.stat(path).st_mode)
    return mode == 0o600


# ---------------------------------------------------------------------------
# doctor --output
# ---------------------------------------------------------------------------

class TestDoctorOutput:
    """Verify --output on `ardur doctor`."""

    def test_doctor_output_writes_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "doctor-report.json"
        with patch("vibap.cli.doctor_personal") as mock_doc:
            mock_doc.return_value = {"ok": True, "checks": []}
            exit_code, result, _ = _run_cli(
                ["doctor", "--home", str(tmp_path / "ardur-home"), "--output", str(output_file)],
                capsys,
            )
        assert exit_code == 0
        assert result["ok"] is True
        assert result["condition"] == "doctor_report_written"
        assert result["output"] == str(output_file)
        assert "report_sha256" in result
        assert len(result["report_sha256"]) == 64
        # File written
        assert output_file.exists()
        assert _owner_only(output_file)
        written = json.loads(output_file.read_text())
        assert written["ok"] is True

    def test_doctor_output_with_redact_paths(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "doctor-redacted.json"
        real_path = str(tmp_path / "ardur-home")
        with patch("vibap.cli.doctor_personal") as mock_doc:
            mock_doc.return_value = {"ok": True, "home": real_path, "checks": [{"detail": real_path}]}
            exit_code, result, _ = _run_cli(
                ["doctor", "--home", real_path, "--output", str(output_file), "--redact-paths"],
                capsys,
            )
        assert exit_code == 0
        assert result["ok"] is True
        written = json.loads(output_file.read_text())
        assert real_path not in output_file.read_text()

    def test_doctor_output_preserves_failure_exit_code(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "doctor-fail.json"
        with patch("vibap.cli.doctor_personal") as mock_doc:
            mock_doc.return_value = {"ok": False, "error": "hub_unavailable"}
            exit_code, result, _ = _run_cli(
                ["doctor", "--home", str(tmp_path / "ardur-home"), "--output", str(output_file)],
                capsys,
            )
        # Even with --output, a failed doctor should exit 1
        assert exit_code == 1
        # The confirmation still says the report was written
        assert result["condition"] == "doctor_report_written"
        written = json.loads(output_file.read_text())
        assert written["ok"] is False


# ---------------------------------------------------------------------------
# status --output
# ---------------------------------------------------------------------------

class TestStatusOutput:
    """Verify --output on `ardur status`."""

    def test_status_output_writes_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "status-report.json"
        with patch("vibap.cli.hub_request") as mock_hub:
            mock_hub.return_value = {"ok": True, "hub": "running"}
            exit_code, result, _ = _run_cli(
                ["status", "--home", str(tmp_path / "ardur-home"), "--output", str(output_file)],
                capsys,
            )
        assert exit_code == 0
        assert result["ok"] is True
        assert result["condition"] == "status_report_written"
        assert output_file.exists()
        assert _owner_only(output_file)
        written = json.loads(output_file.read_text())
        assert written["ok"] is True

    def test_status_output_with_redact_paths(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "status-redacted.json"
        real_path = str(tmp_path / "ardur-home")
        with patch("vibap.cli.hub_request") as mock_hub:
            mock_hub.return_value = {"ok": True, "home": real_path}
            exit_code, result, _ = _run_cli(
                ["status", "--home", real_path, "--output", str(output_file), "--redact-paths"],
                capsys,
            )
        assert exit_code == 0
        written_text = output_file.read_text()
        assert real_path not in written_text


# ---------------------------------------------------------------------------
# setup --output
# ---------------------------------------------------------------------------

class TestSetupOutput:
    """Verify --output on `ardur setup`."""

    def test_setup_output_writes_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "setup-report.json"
        with patch("vibap.cli.setup_personal") as mock_setup:
            mock_setup.return_value = {"ok": True, "home": str(tmp_path / "ardur-home")}
            exit_code, result, _ = _run_cli(
                ["setup", "--home", str(tmp_path / "ardur-home"), "--output", str(output_file)],
                capsys,
            )
        assert exit_code == 0
        assert result["ok"] is True
        assert result["condition"] == "setup_report_written"
        assert output_file.exists()
        assert _owner_only(output_file)

    def test_setup_output_with_redact_paths(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "setup-redacted.json"
        real_path = str(tmp_path / "ardur-home")
        with patch("vibap.cli.setup_personal") as mock_setup:
            mock_setup.return_value = {"ok": True, "home": real_path, "extension_path": real_path}
            exit_code, result, _ = _run_cli(
                ["setup", "--home", real_path, "--output", str(output_file), "--redact-paths"],
                capsys,
            )
        assert exit_code == 0
        written_text = output_file.read_text()
        assert real_path not in written_text


# ---------------------------------------------------------------------------
# doctor-claude-code --output
# ---------------------------------------------------------------------------

class TestDoctorClaudeCodeOutput:
    """Verify --output on `ardur doctor-claude-code`."""

    def test_doctor_cc_output_writes_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "doctor-cc-report.json"
        with patch("vibap.cli.claude_code_doctor") as mock_doc:
            mock_doc.return_value = {"ok": True, "checks": []}
            exit_code, result, _ = _run_cli(
                ["doctor-claude-code", "--home", str(tmp_path / "ardur-home"), "--output", str(output_file)],
                capsys,
            )
        assert exit_code == 0
        assert result["ok"] is True
        assert result["condition"] == "doctor_claude_code_report_written"
        assert output_file.exists()
        assert _owner_only(output_file)

    def test_doctor_cc_output_with_redact_paths(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "doctor-cc-redacted.json"
        real_path = str(tmp_path / "ardur-home")
        with patch("vibap.cli.claude_code_doctor") as mock_doc:
            mock_doc.return_value = {"ok": True, "home": real_path, "plugin_dir": real_path}
            exit_code, result, _ = _run_cli(
                [
                    "doctor-claude-code",
                    "--home",
                    real_path,
                    "--output",
                    str(output_file),
                    "--redact-paths",
                ],
                capsys,
            )
        assert exit_code == 0
        written_text = output_file.read_text()
        assert real_path not in written_text


# ---------------------------------------------------------------------------
# protect claude-code --output
# ---------------------------------------------------------------------------

class TestProtectClaudeCodeOutput:
    """Verify --output on `ardur protect claude-code`."""

    def test_protect_output_writes_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "protect-report.json"
        scope = tmp_path / "project"
        scope.mkdir()
        with patch("vibap.cli.protect_claude_code") as mock_protect:
            mock_protect.return_value = {
                "ok": True,
                "mode": "safe-coding",
                "scope": str(scope),
                "active_passport": str(tmp_path / "passport.jwt"),
                "run_command": "claude --plugin-dir ...",
            }
            exit_code, result, _ = _run_cli(
                ["protect", "claude-code", "--scope", str(scope), "--output", str(output_file)],
                capsys,
            )
        assert exit_code == 0
        assert result["ok"] is True
        assert result["condition"] == "protect_claude_code_report_written"
        assert output_file.exists()
        assert _owner_only(output_file)
        written = json.loads(output_file.read_text())
        assert written["ok"] is True
        assert written["mode"] == "safe-coding"

    def test_protect_output_with_redact_paths(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "protect-redacted.json"
        scope = tmp_path / "project"
        scope.mkdir()
        real_scope = str(scope)
        with patch("vibap.cli.protect_claude_code") as mock_protect:
            mock_protect.return_value = {
                "ok": True,
                "mode": "safe-coding",
                "scope": real_scope,
                "active_passport": str(tmp_path / "passport.jwt"),
                "run_command": f"claude --plugin-dir {tmp_path}/plugin",
            }
            exit_code, result, _ = _run_cli(
                [
                    "protect",
                    "claude-code",
                    "--scope",
                    str(scope),
                    "--output",
                    str(output_file),
                    "--redact-paths",
                ],
                capsys,
            )
        assert exit_code == 0
        written_text = output_file.read_text()
        assert real_scope not in written_text

    def test_protect_output_failure_exit_code(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """--output on a failed protect should still write the failure and exit 1."""
        output_file = tmp_path / "protect-fail.json"
        scope = tmp_path / "project"
        scope.mkdir()
        with patch("vibap.cli.protect_claude_code") as mock_protect:
            mock_protect.return_value = {
                "ok": False,
                "error": "protect_scope_invalid",
                "message": "scope is invalid",
            }
            exit_code, result, _ = _run_cli(
                ["protect", "claude-code", "--scope", str(scope), "--output", str(output_file)],
                capsys,
            )
        assert exit_code == 1
        assert result["condition"] == "protect_claude_code_report_written"
        written = json.loads(output_file.read_text())
        assert written["ok"] is False


# ---------------------------------------------------------------------------
# Consistency: --output without --json should still work for these commands
# ---------------------------------------------------------------------------

class TestOutputWithoutJson:
    """--output should work even without --json since output is always JSON for these commands."""

    def test_doctor_output_no_json_flag(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        output_file = tmp_path / "doctor-no-json.json"
        with patch("vibap.cli.doctor_personal") as mock_doc:
            mock_doc.return_value = {"ok": True, "checks": []}
            exit_code, result, _ = _run_cli(
                ["doctor", "--home", str(tmp_path / "ardur-home"), "--output", str(output_file)],
                capsys,
            )
        assert exit_code == 0
        assert output_file.exists()
        assert json.loads(output_file.read_text())["ok"] is True

    def test_protect_output_no_json_flag(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """--output without --json on protect should produce JSON, not human-readable."""
        output_file = tmp_path / "protect-no-json.json"
        scope = tmp_path / "project"
        scope.mkdir()
        with patch("vibap.cli.protect_claude_code") as mock_protect:
            mock_protect.return_value = {
                "ok": True,
                "mode": "safe-coding",
                "scope": str(scope),
                "active_passport": str(tmp_path / "passport.jwt"),
                "run_command": "claude --plugin-dir ...",
            }
            exit_code, result, _ = _run_cli(
                ["protect", "claude-code", "--scope", str(scope), "--output", str(output_file)],
                capsys,
            )
        assert exit_code == 0
        assert output_file.exists()
        written = json.loads(output_file.read_text())
        assert written["ok"] is True

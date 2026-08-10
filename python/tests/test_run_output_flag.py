"""Tests for ``ardur run --output`` flag.

The ``--output`` flag writes the governance run result JSON to a file,
matching the ``--output`` contract on every other report-producing command
(``verify``, ``posture``, ``preflight``, ``telemetry``, ``evidence
correlate``).

These tests exercise the ``run_governed_cli`` entry point directly with
mocked ``run_governed`` results, avoiding the need to launch a real agent.
"""

import json
from types import SimpleNamespace
from unittest.mock import patch

from vibap.run_bridge import (
    GovernanceRunResult,
    run_governed_cli,
)


def _mock_result(**overrides):
    """Build a minimal GovernanceRunResult for testing."""
    base = dict(
        exit_code=0,
        session_id="test-session-id",
        mission_id="test-mission",
        agent_id="test-agent",
        adapter="auto",
        via="auto",
        proxy_url="",
        home="/tmp/ardur-test",
        passport_path="/tmp/ardur-test/passport.jwt",
        summary={
            "scope_compliance": "full",
            "elapsed_s": 0.001,
            "unknowns": 0,
            "insufficient_evidence": 0,
            "violations": 0,
            "delegation_count": 0,
            "children_spawned": 0,
            "denied_tools": [],
        },
        permits=0,
        denials=0,
        total_events=0,
        attestation_token="dummy-token",
        attestation_digest="sha-256:abc123",
        receipts_path="/tmp/ardur-test/receipts.jsonl",
        receipt_count=0,
        correlation={"available": False, "reason": "not_configured"},
        kernel_policy={},
        process_lifecycle={},
        notes=[],
    )
    base.update(overrides)
    return GovernanceRunResult(**base)


def _base_args(**overrides):
    """Build minimal args namespace for run_governed_cli."""
    base = dict(
        command=["echo", "hello"],
        mission="test mission",
        allowed_tools=None,
        forbidden_tools=None,
        max_tool_calls=None,
        max_duration_s=None,
        home=None,
        via="auto",
        no_kernel_correlation=False,
        enforce=False,
        resource_scope=None,
        no_resource_scope=False,
        json=False,
        redact_paths=False,
        output=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestRunOutputFile:
    """``--output`` writes the result dict to a file."""

    def test_output_writes_json_file(self, tmp_path):
        """--output writes a valid JSON file with the governance result."""
        output_file = tmp_path / "result.json"
        args = _base_args(output=str(output_file))
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["ok"] is True
        assert data["session_id"] == "test-session-id"
        assert data["mission_id"] == "test-mission"
        assert "summary" in data
        assert data["summary"]["scope_compliance"] == "full"

    def test_output_with_json_flag(self, tmp_path, capsys):
        """--output + --json writes both the file and stderr JSON."""
        output_file = tmp_path / "result.json"
        args = _base_args(json=True, output=str(output_file))
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        assert output_file.exists()
        # File should be valid JSON
        file_data = json.loads(output_file.read_text())
        assert file_data["ok"] is True
        # stderr should also have JSON
        stderr = capsys.readouterr().err
        stderr_data = json.loads(stderr)
        assert stderr_data["ok"] is True
        # stderr should include output_file + output_sha256
        assert "output_file" in stderr_data
        assert "output_sha256" in stderr_data
        assert stderr_data["output_file"] == str(output_file)

    def test_output_without_json_shows_summary(self, tmp_path, capsys):
        """--output without --json shows human summary + file confirmation."""
        output_file = tmp_path / "result.json"
        args = _base_args(output=str(output_file))
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        assert output_file.exists()
        stderr = capsys.readouterr().err
        assert "Ardur governance summary" in stderr
        assert "output file" in stderr
        assert "sha256:" in stderr

    def test_output_creates_file_in_nested_dir(self, tmp_path):
        """--output writes into a pre-existing nested directory."""
        nested = tmp_path / "nested" / "deep"
        nested.mkdir(parents=True)
        output_file = nested / "result.json"
        args = _base_args(output=str(output_file))
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        assert output_file.exists()

    def test_output_file_permissions(self, tmp_path):
        """Written file should be owner-only (0o600)."""
        output_file = tmp_path / "result.json"
        args = _base_args(output=str(output_file))
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        mode = output_file.stat().st_mode & 0o777
        assert mode == 0o600

    def test_output_with_redact_paths(self, tmp_path):
        """--output + --redact-paths substitutes local paths in the file."""
        import os

        real_home = os.path.expanduser("~")
        output_file = tmp_path / "result.json"
        args = _base_args(redact_paths=True, output=str(output_file), json=True)
        mock = _mock_result(
            receipts_path=f"{real_home}/ardur/receipts.jsonl",
            home=f"{real_home}/ardur",
        )
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        raw = output_file.read_text()
        # Real home path should be redacted to <home>
        assert real_home not in raw
        assert "<home>" in raw

    def test_output_content_matches_json_stderr(self, tmp_path, capsys):
        """File content should match stderr JSON content (minus output_* fields)."""
        output_file = tmp_path / "result.json"
        args = _base_args(json=True, output=str(output_file))
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        file_data = json.loads(output_file.read_text())
        stderr = capsys.readouterr().err
        stderr_data = json.loads(stderr)
        # Core data should match
        assert file_data["session_id"] == stderr_data["session_id"]
        assert file_data["exit_code"] == stderr_data["exit_code"]
        assert file_data["summary"] == stderr_data["summary"]
        # stderr has extra output_file/sha256 keys
        assert "output_file" not in file_data
        assert "output_file" in stderr_data


class TestRunOutputError:
    """Error paths for --output."""

    def test_output_unwritable_path_returns_2(self, tmp_path):
        """If the output path is unwritable, exit code 2."""
        # Use a path inside an existing file
        blocking_file = tmp_path / "blocking"
        blocking_file.write_text("data")
        output_file = blocking_file / "result.json"
        args = _base_args(output=str(output_file))
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 2

    def test_output_empty_string_returns_2(self, tmp_path, capsys):
        """Empty --output string is rejected by the atomic writer."""
        args = _base_args(output="")
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 2


class TestRedactPathsWarningGuard:
    """The --redact-paths no-op warning should not fire when --output is active."""

    def test_redact_paths_output_no_warning(self, tmp_path, capsys):
        """--redact-paths + --output (no --json) should NOT print the warning."""
        output_file = tmp_path / "result.json"
        args = _base_args(redact_paths=True, output=str(output_file), json=False)
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        stderr = capsys.readouterr().err
        assert "--redact-paths has no effect" not in stderr

    def test_redact_paths_without_json_or_output_still_warns(self, tmp_path, capsys):
        """--redact-paths alone (no --json, no --output) should still warn."""
        args = _base_args(redact_paths=True, json=False, output=None)
        mock = _mock_result()
        with patch("vibap.run_bridge.run_governed", return_value=mock):
            rc = run_governed_cli(args)
        assert rc == 0
        stderr = capsys.readouterr().err
        assert "--redact-paths has no effect" in stderr

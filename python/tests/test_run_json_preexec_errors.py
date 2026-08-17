"""Test that ``ardur run --json`` pre-execution errors emit structured JSON to stderr.

The ``--json`` contract is: stdout = child process output, stderr = governance JSON.
Pre-execution failures (budget validation, command not found, not executable)
must emit structured JSON to **stderr** (not stdout) so programmatic consumers
can parse ``2>governance.json`` reliably even when the command never launches.
"""

from __future__ import annotations

import json
import subprocess
import sys


def _run_ardur(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the ardur CLI with the given args and capture output."""
    return subprocess.run(
        [sys.executable, "-m", "vibap.cli"] + args,
        capture_output=True,
        text=True,
        timeout=10,
    )


class TestBudgetValidationJsonToStderr:
    """Budget validation errors with --json must go to stderr, not stdout."""

    def test_max_tool_calls_negative_json_on_stderr(self):
        """--max-tool-calls -1 with --json: JSON must be on stderr, not stdout."""
        result = _run_ardur([
            "run", "--json", "--mission", "test",
            "--max-tool-calls", "-1", "--", "echo", "hi",
        ])
        assert result.returncode == 2
        # stdout must be empty (child process never starts)
        assert result.stdout.strip() == ""
        # stderr must have parseable JSON
        data = json.loads(result.stderr)
        assert data["ok"] is False
        assert data["error"] == "run_max_tool_calls_invalid"
        assert "next_steps" in data

    def test_max_duration_negative_json_on_stderr(self):
        """--max-duration-s -5 with --json: JSON must be on stderr, not stdout."""
        result = _run_ardur([
            "run", "--json", "--mission", "test",
            "--max-duration-s", "-5", "--", "echo", "hi",
        ])
        assert result.returncode == 2
        assert result.stdout.strip() == ""
        data = json.loads(result.stderr)
        assert data["ok"] is False
        assert data["error"] == "run_max_duration_invalid"


class TestCommandNotFoundJsonError:
    """Command-not-found with --json must emit structured JSON to stderr."""

    def test_nonexistent_command_json_error(self):
        """Non-existent command with --json: structured JSON error on stderr."""
        result = _run_ardur([
            "run", "--json", "--mission", "test",
            "--", "/nonexistent/command/that/does/not/exist",
        ])
        assert result.returncode == 2
        # stdout must be empty
        assert result.stdout.strip() == ""
        # stderr must be parseable JSON
        data = json.loads(result.stderr)
        assert data["ok"] is False
        assert data["error"] == "run_command_not_found"
        assert "next_steps" in data

    def test_nonexistent_command_human_readable_without_json(self):
        """Without --json, command-not-found stays human-readable on stderr."""
        result = _run_ardur([
            "run", "--mission", "test",
            "--", "/nonexistent/command/that/does/not/exist",
        ])
        assert result.returncode == 2
        # stderr should NOT be parseable JSON (human-readable mode)
        assert not result.stderr.strip().startswith("{")


class TestCommandNotExecutableJsonError:
    """Command-not-executable with --json must emit structured JSON to stderr."""

    def test_not_executable_file_json_error(self):
        """Non-executable file with --json: structured JSON error on stderr."""
        result = _run_ardur([
            "run", "--json", "--mission", "test",
            "--", "/etc/passwd",
        ])
        assert result.returncode == 2
        assert result.stdout.strip() == ""
        data = json.loads(result.stderr)
        assert data["ok"] is False
        assert data["error"] == "run_command_not_executable"
        assert "next_steps" in data


class TestBudgetFailureHelperWritesStderr:
    """Unit test: _run_governed_budget_failure writes to stderr."""

    def test_budget_failure_writes_to_stderr(self, capsys):
        """The budget failure helper must write JSON to stderr."""
        from vibap.run_bridge import _run_governed_budget_failure

        rc = _run_governed_budget_failure(
            "test_condition",
            "test message",
            "test detail",
            [{"action": "test", "command": "test", "detail": "test"}],
        )
        assert rc == 2
        captured = capsys.readouterr()
        # stdout must be empty
        assert captured.out == ""
        # stderr must have parseable JSON
        data = json.loads(captured.err)
        assert data["ok"] is False
        assert data["error"] == "test_condition"


class TestPreexecJsonErrorHelperWritesStderr:
    """Unit test: _run_governed_preexec_json_error writes to stderr."""

    def test_preexec_error_writes_to_stderr(self, capsys):
        """The pre-execution error helper must write JSON to stderr."""
        from vibap.run_bridge import _run_governed_preexec_json_error

        _run_governed_preexec_json_error(
            "test_preexec",
            "test message",
            "test detail",
            [{"action": "test", "command": "test", "detail": "test"}],
        )
        captured = capsys.readouterr()
        # stdout must be empty
        assert captured.out == ""
        # stderr must have parseable JSON
        data = json.loads(captured.err)
        assert data["ok"] is False
        assert data["error"] == "test_preexec"


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])

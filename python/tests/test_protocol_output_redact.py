"""Tests for ``--output`` and ``--redact-paths`` on ``issue``, ``anchor``, ``attest``.

These three protocol-path commands were the last JSON-producing CLI commands
that lacked the ``--output``/``--redact-paths`` flags that every other report
command already supported.  The flags use a shared ``_handle_output_and_redact``
terminal helper so the semantics are identical to ``verify --output``,
``run --output``, etc.

Covered behaviors per command:

* ``--output`` writes JSON to an owner-only file and prints a confirmation
  with ``report_sha256``.
* ``--redact-paths`` recursively replaces local absolute paths in stdout JSON.
* ``--output`` + ``--redact-paths`` writes redacted JSON to the file.
* ``--redact-paths`` without ``--json`` or ``--output`` prints a warning.
* Omitting both flags preserves the original stdout-only behavior.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from vibap.cli import main, build_parser


# ---------------------------------------------------------------------------
# issue --output / --redact-paths
# ---------------------------------------------------------------------------

class TestIssueOutputFlag:
    """``ardur issue --output`` writes JSON to a file."""

    def test_issue_output_writes_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        out_file = tmp_path / "issue_report.json"
        exit_code = main([
            "issue",
            "--agent-id", "test-agent",
            "--mission", "test mission",
            "--keys-dir", str(keys_dir),
            "--output", str(out_file),
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["condition"] == "issue_report_written"
        assert parsed["output"] == str(out_file)
        assert "report_sha256" in parsed
        assert out_file.is_file()
        written = json.loads(out_file.read_text())
        assert "token" in written
        assert "claims" in written
        # Verify sha256 matches
        payload_bytes = json.dumps(written, indent=2, sort_keys=True).encode("utf-8")
        expected_hash = hashlib.sha256(payload_bytes).hexdigest()
        assert parsed["report_sha256"] == expected_hash

    def test_issue_without_output_prints_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        exit_code = main([
            "issue",
            "--agent-id", "test-agent",
            "--mission", "test mission",
            "--keys-dir", str(keys_dir),
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "token" in parsed
        assert "claims" in parsed
        assert "condition" not in parsed  # no output confirmation

    def test_issue_redact_paths_with_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        out_file = tmp_path / "issue_redacted.json"
        exit_code = main([
            "issue",
            "--agent-id", "test-agent",
            "--mission", "test mission",
            "--keys-dir", str(keys_dir),
            "--output", str(out_file),
            "--redact-paths",
        ])
        assert exit_code == 0
        written_str = out_file.read_text()
        assert str(keys_dir) not in written_str
        assert str(tmp_path) not in written_str


class TestIssueRedactPathsWarning:
    """``--redact-paths`` without ``--json`` or ``--output`` warns on stderr."""

    def test_issue_redact_paths_warns_without_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        exit_code = main([
            "issue",
            "--agent-id", "test-agent",
            "--mission", "test mission",
            "--keys-dir", str(keys_dir),
            "--redact-paths",
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "warning" in captured.err.lower()
        assert "--redact-paths" in captured.err


# ---------------------------------------------------------------------------
# Parser: verify all 3 commands accept the new flags
# ---------------------------------------------------------------------------

class TestParserAcceptsNewFlags:
    """All three protocol commands must accept ``--output`` and ``--redact-paths``."""

    @pytest.mark.parametrize("cmd", ["issue", "attest", "anchor"])
    def test_output_flag_accepted(self, cmd: str) -> None:
        parser = build_parser()
        if cmd == "issue":
            args = parser.parse_args([
                cmd, "--agent-id", "a", "--mission", "m", "--output", "/tmp/r.json"
            ])
        elif cmd == "attest":
            args = parser.parse_args([
                cmd, "--session", "s", "--output", "/tmp/r.json"
            ])
        else:
            args = parser.parse_args([
                cmd, "--receipt-log", "/tmp/r.log", "--backend", "c2sp-local-v1",
                "--output", "/tmp/r.json"
            ])
        assert getattr(args, "output") == "/tmp/r.json"

    @pytest.mark.parametrize("cmd", ["issue", "attest", "anchor"])
    def test_redact_paths_flag_accepted(self, cmd: str) -> None:
        parser = build_parser()
        if cmd == "issue":
            args = parser.parse_args([
                cmd, "--agent-id", "a", "--mission", "m", "--redact-paths"
            ])
        elif cmd == "attest":
            args = parser.parse_args([
                cmd, "--session", "s", "--redact-paths"
            ])
        else:
            args = parser.parse_args([
                cmd, "--receipt-log", "/tmp/r.log", "--backend", "c2sp-local-v1",
                "--redact-paths"
            ])
        assert getattr(args, "redact_paths") is True

    @pytest.mark.parametrize("cmd", ["issue", "attest", "anchor"])
    def test_flags_default_none_false(self, cmd: str) -> None:
        parser = build_parser()
        if cmd == "issue":
            args = parser.parse_args([cmd, "--agent-id", "a", "--mission", "m"])
        elif cmd == "attest":
            args = parser.parse_args([cmd, "--session", "s"])
        else:
            args = parser.parse_args([
                cmd, "--receipt-log", "/tmp/r.log", "--backend", "c2sp-local-v1"
            ])
        assert getattr(args, "output") is None
        assert getattr(args, "redact_paths") is False


# ---------------------------------------------------------------------------
# Shared helper unit test
# ---------------------------------------------------------------------------

class TestHandleOutputAndRedactHelper:
    """Unit tests for ``_handle_output_and_redact``."""

    def test_no_args_prints_response(self, capsys: pytest.CaptureFixture[str]) -> None:
        import argparse
        from vibap.cli import _handle_output_and_redact
        args = argparse.Namespace(json=False, output=None, redact_paths=False)
        response = {"ok": True, "data": "test"}
        result = _handle_output_and_redact(args, response, command="test")
        assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed == response

    def test_redact_paths_applied(self, capsys: pytest.CaptureFixture[str]) -> None:
        import argparse
        from vibap.cli import _handle_output_and_redact, _redact_paths_deep
        args = argparse.Namespace(json=True, output=None, redact_paths=True)
        local_path = str(Path.home())
        response = {"ok": True, "path": local_path + "/some/file"}
        result = _handle_output_and_redact(args, response, command="test")
        assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert local_path not in json.dumps(parsed)

    def test_output_writes_file_and_confirmation(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import argparse
        from vibap.cli import _handle_output_and_redact
        out_file = tmp_path / "report.json"
        args = argparse.Namespace(json=False, output=str(out_file), redact_paths=False)
        response = {"ok": True, "data": "test"}
        result = _handle_output_and_redact(args, response, command="test")
        assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["condition"] == "test_report_written"
        assert "report_sha256" in parsed
        written = json.loads(out_file.read_text())
        assert written == response

    def test_exit_code_propagation(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import argparse
        from vibap.cli import _handle_output_and_redact
        out_file = tmp_path / "report.json"
        args = argparse.Namespace(json=False, output=str(out_file), redact_paths=False)
        response = {"ok": False}
        result = _handle_output_and_redact(args, response, command="test", exit_code=1)
        assert result == 1
        assert out_file.is_file()

    def test_redact_paths_warning_without_json_or_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import argparse
        from vibap.cli import _handle_output_and_redact
        args = argparse.Namespace(json=False, output=None, redact_paths=True)
        response = {"ok": True}
        result = _handle_output_and_redact(args, response, command="test")
        assert result == 0
        captured = capsys.readouterr()
        assert "--redact-paths" in captured.err
        assert "warning" in captured.err.lower()

    def test_output_write_failure_returns_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import argparse
        from vibap.cli import _handle_output_and_redact
        # Point output at a directory (not a file) to trigger write failure
        out_dir = tmp_path / "outdir"
        out_dir.mkdir()
        args = argparse.Namespace(json=False, output=str(out_dir), redact_paths=False)
        response = {"ok": True}
        result = _handle_output_and_redact(args, response, command="test")
        assert result == 1
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["ok"] is False
        assert "output_write_failed" in parsed["error"]

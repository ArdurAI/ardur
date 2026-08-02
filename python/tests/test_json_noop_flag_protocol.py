"""Tests for --json no-op flag on always-JSON protocol-path commands.

These commands always emit JSON output. The --json flag is accepted but
has no effect — it exists purely for CLI consistency so users who expect
--json (present on ``ardur run --json`` and ``ardur verify --json``) do
not get ``unrecognized arguments: --json``.
"""

import json
import subprocess
import sys

import pytest

from vibap.cli import build_parser


PROTOCOL_COMMANDS = ["issue", "attest", "anchor"]


class TestJsonNoOpFlagAccepted:
    """Verify --json is accepted by all 3 protocol-path commands."""

    @pytest.mark.parametrize("cmd", PROTOCOL_COMMANDS)
    def test_json_flag_accepted_by_parser(self, cmd):
        """The parser should accept --json without error on all 3 commands."""
        parser = build_parser()
        # Build minimal valid args for each command + --json
        if cmd == "issue":
            args = parser.parse_args([cmd, "--agent-id", "test", "--mission", "test", "--json"])
        elif cmd == "attest":
            args = parser.parse_args([cmd, "--session", "test", "--json"])
        elif cmd == "anchor":
            args = parser.parse_args(
                [cmd, "--receipt-log", "/tmp/test.log", "--backend", "c2sp-local-v1", "--json"]
            )
        assert getattr(args, "json") is True

    @pytest.mark.parametrize("cmd", PROTOCOL_COMMANDS)
    def test_json_flag_defaults_false(self, cmd):
        """Without --json, args.json should be False (store_true default)."""
        parser = build_parser()
        if cmd == "issue":
            args = parser.parse_args([cmd, "--agent-id", "test", "--mission", "test"])
        elif cmd == "attest":
            args = parser.parse_args([cmd, "--session", "test"])
        elif cmd == "anchor":
            args = parser.parse_args(
                [cmd, "--receipt-log", "/tmp/test.log", "--backend", "c2sp-local-v1"]
            )
        assert getattr(args, "json") is False

    @pytest.mark.parametrize("cmd", PROTOCOL_COMMANDS)
    def test_json_flag_in_help(self, cmd):
        """--json should appear in the command's help text."""
        parser = build_parser()
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with pytest.raises(SystemExit):
            with redirect_stdout(f):
                parser.parse_args([cmd, "--help"])
        help_text = f.getvalue()
        assert "--json" in help_text
        assert "consistency" in help_text


class TestJsonNoOpFlagIsNoOp:
    """Verify --json has no effect on output (it's a true no-op)."""

    def _run_cli(self, extra_args):
        """Run the CLI with given args, return (stdout, stderr, returncode)."""
        result = subprocess.run(
            [sys.executable, "-m", "vibap.cli"] + extra_args,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout, result.stderr, result.returncode

    def test_issue_json_noop_identical_error(self):
        """issue --json with invalid args should produce identical error as without --json."""
        # Use a missing required arg scenario to get structured JSON error
        without = self._run_cli(["issue", "--agent-id", "x", "--mission", "x", "--keys-dir", "/nonexistent"])
        with_json = self._run_cli(
            ["issue", "--agent-id", "x", "--mission", "x", "--keys-dir", "/nonexistent", "--json"]
        )
        # Both should produce the same error (keys-dir not found)
        assert without[2] == with_json[2]  # same exit code
        # Parse both as JSON and compare error_code
        without_json = json.loads(without[1]) if without[1].strip().startswith("{") else None
        with_json_obj = json.loads(with_json[1]) if with_json[1].strip().startswith("{") else None
        if without_json and with_json_obj:
            assert without_json.get("error_code") == with_json_obj.get("error_code")

    def test_attest_json_noop_identical_error(self):
        """attest --json with nonexistent session should produce identical error as without."""
        without = self._run_cli(["attest", "--session", "nonexistent-session-id"])
        with_json = self._run_cli(["attest", "--session", "nonexistent-session-id", "--json"])
        assert without[2] == with_json[2]  # same exit code
        # attest writes JSON to stdout; both should produce identical JSON
        assert without[0].strip().startswith("{")
        assert with_json[0].strip().startswith("{")
        assert json.loads(without[0]) == json.loads(with_json[0])

    def test_anchor_json_noop_identical_error(self):
        """anchor --json with nonexistent log should produce identical error as without."""
        without = self._run_cli(
            ["anchor", "--receipt-log", "/nonexistent/test.log", "--backend", "c2sp-local-v1"]
        )
        with_json = self._run_cli(
            [
                "anchor",
                "--receipt-log",
                "/nonexistent/test.log",
                "--backend",
                "c2sp-local-v1",
                "--json",
            ]
        )
        assert without[2] == with_json[2]  # same exit code


class TestFullCliConsistency:
    """Verify --json is now accepted on ALL major Ardur commands."""

    ALL_JSON_COMMANDS = [
        # personal-path (always-JSON, landed in 2cfae7c)
        "status",
        "doctor",
        "doctor-claude-code",
        "setup",
        "kill-switch",
        "uninstall",
        # protocol-path (always-JSON, this commit)
        "issue",
        "attest",
        "anchor",
        # commands with functional --json (already existed)
        "run",
        "verify",
    ]

    @pytest.mark.parametrize("cmd", ALL_JSON_COMMANDS)
    def test_json_accepted_everywhere(self, cmd):
        """Every major Ardur command should accept --json without 'unrecognized arguments'."""
        parser = build_parser()
        # We need to find the subparser and check it has --json
        import io
        from contextlib import redirect_stderr

        f = io.StringIO()
        try:
            with redirect_stderr(f):
                parser.parse_args([cmd, "--help"])
        except SystemExit:
            pass
        help_text = f.getvalue()
        # Some commands output help to stdout
        if "--json" not in help_text:
            f2 = io.StringIO()
            from contextlib import redirect_stdout

            try:
                with redirect_stdout(f2):
                    parser.parse_args([cmd, "--help"])
            except SystemExit:
                pass
            help_text = f2.getvalue()
        assert "--json" in help_text, f"Command '{cmd}' does not accept --json"

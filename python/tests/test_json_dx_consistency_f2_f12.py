"""Tests for DX consistency: --json acceptance on evidence correlate and
latency-gate evaluate (F2), and --json help text on personal-firewall demo
(F12).

These commands emit JSON by default but previously rejected the --json flag
(argparse error) while all other JSON-emitting commands accept it for
consistency. personal-firewall demo accepted --json but had no help text.
"""

import contextlib
import io
import sys
from pathlib import Path

import pytest

from vibap.cli import build_parser
from vibap.cli import main as cli_main


@contextlib.contextmanager
def capture_stdout():
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = saved


class TestEvidenceCorrelateJsonAcceptance:
    """evidence correlate should accept --json without argparse error."""

    def test_accepts_json_flag(self, tmp_path: Path) -> None:
        """--json is accepted (not rejected as unrecognized argument)."""
        journal = tmp_path / "journal.jsonl"
        journal.write_text("")
        events = tmp_path / "events.jsonl"
        events.write_text("")
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        with capture_stdout() as buf:
            cli_main([
                "evidence", "correlate",
                "--json",
                "--source-format", "normalized",
                "--keys-dir", str(keys_dir),
                "--format", "json",
                str(journal),
                str(events),
            ])

        output = buf.getvalue()
        # The key assertion: no argparse rejection of --json
        assert '"unrecognized arguments"' not in output
        assert '"ok"' in output

    def test_json_flag_defaults_false(self) -> None:
        """evidence correlate has --json defaulting to False."""
        parser = build_parser()
        args = parser.parse_args([
            "evidence", "correlate",
            "--source-format", "normalized",
            "--keys-dir", "/tmp",
            "/tmp/a", "/tmp/b",
        ])
        assert hasattr(args, "json")
        assert args.json is False

    def test_json_flag_set_true(self) -> None:
        """evidence correlate --json sets json=True."""
        parser = build_parser()
        args = parser.parse_args([
            "evidence", "correlate",
            "--json",
            "--source-format", "normalized",
            "--keys-dir", "/tmp",
            "/tmp/a", "/tmp/b",
        ])
        assert args.json is True


class TestLatencyGateEvaluateJsonAcceptance:
    """latency-gate evaluate should accept --json without argparse error."""

    def test_accepts_json_flag(self, tmp_path: Path) -> None:
        """--json is accepted (not rejected as unrecognized argument)."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()

        with capture_stdout() as buf:
            cli_main([
                "latency-gate", "evaluate",
                "--json",
                "--reports", str(reports_dir),
            ])

        output = buf.getvalue()
        assert '"unrecognized arguments"' not in output
        assert '"ok"' in output

    def test_json_flag_defaults_false(self) -> None:
        """latency-gate evaluate has --json defaulting to False."""
        parser = build_parser()
        args = parser.parse_args([
            "latency-gate", "evaluate",
            "--reports", "/tmp/reports",
        ])
        assert hasattr(args, "json")
        assert args.json is False

    def test_json_flag_set_true(self) -> None:
        """latency-gate evaluate --json sets json=True."""
        parser = build_parser()
        args = parser.parse_args([
            "latency-gate", "evaluate",
            "--json",
            "--reports", "/tmp/reports",
        ])
        assert args.json is True


class TestPersonalFirewallDemoJsonHelp:
    """personal-firewall demo --json should have help text (F12)."""

    def test_json_has_help_text(self) -> None:
        """--json flag in personal-firewall demo has non-empty help text."""
        with capture_stdout() as buf:
            with pytest.raises(SystemExit):
                cli_main([
                    "personal-firewall", "demo", "--help",
                ])

        output = buf.getvalue()
        # In argparse --help output, the options section lists each flag
        # followed by its help text. The --json line in the options section
        # (not the usage line) must have help text.
        # The options section starts after "options:" or "optional arguments:"
        lines = output.split("\n")
        in_options = False
        json_help = ""
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped in ("options:", "optional arguments:"):
                in_options = True
                continue
            if not in_options:
                continue
            # argparse format: "  --json    <help text>"
            # or multi-line: "  --json" on one line, help indented on next
            if stripped.startswith("--json"):
                remainder = stripped[len("--json"):].strip()
                if remainder:
                    json_help = remainder
                elif i + 1 < len(lines):
                    json_help = lines[i + 1].strip()
                break

        assert json_help, \
            f"--json has no help text in options section. Output:\n{output[:800]}"
        assert "machine-readable" in json_help.lower() or \
               "print" in json_help.lower(), \
               f"--json help text unexpected: {json_help!r}"


class TestJsonDxConsistencyRegression:
    """Regression: ensure no argparse errors when --json is passed."""

    def test_evidence_correlate_no_argparse_error(self, tmp_path: Path) -> None:
        """Regression: evidence correlate --json must not produce argument_error."""
        journal = tmp_path / "journal.jsonl"
        journal.write_text("")
        events = tmp_path / "events.jsonl"
        events.write_text("")
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        with capture_stdout() as buf:
            cli_main([
                "evidence", "correlate",
                "--json",
                "--source-format", "normalized",
                "--keys-dir", str(keys_dir),
                "--format", "json",
                str(journal),
                str(events),
            ])

        output = buf.getvalue()
        assert '"unrecognized arguments: --json"' not in output, \
            "evidence correlate --json regressed to argparse rejection"

    def test_latency_gate_evaluate_no_argparse_error(self, tmp_path: Path) -> None:
        """Regression: latency-gate evaluate --json must not produce argument_error."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()

        with capture_stdout() as buf:
            cli_main([
                "latency-gate", "evaluate",
                "--json",
                "--reports", str(reports_dir),
            ])

        output = buf.getvalue()
        assert '"unrecognized arguments: --json"' not in output, \
            "latency-gate evaluate --json regressed to argparse rejection"

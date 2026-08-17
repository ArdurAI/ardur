"""Tests for ``--output`` and ``--redact-paths`` on ``ardur latency-gate evaluate``.

``latency-gate evaluate`` was the last report-producing CLI command that
lacked the ``--output``/``--redact-paths`` flags that every other JSON-producing
command already supported.  The flags use the shared ``_handle_output_and_redact``
terminal helper so the semantics are identical to ``verify --output``,
``run --output``, etc.

Covered behaviors:

* ``--output`` writes JSON to an owner-only file and prints a confirmation
  with ``report_sha256``.
* ``--output`` preserves the verdict-based exit code (pass=0, fail=1,
  inconclusive=2).
* ``--redact-paths`` replaces local absolute paths in stdout JSON.
* ``--redact-paths`` without ``--json`` or ``--output`` prints a warning.
* ``--output`` + ``--redact-paths`` writes redacted JSON to the file.
* ``--output`` write failure produces structured JSON error.
* Omitting both flags preserves the original stdout-only behavior.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vibap.cli import main, build_parser
from vibap.latency_report import (
    build_report,
    report_to_dict,
)


# ---------------------------------------------------------------------------
# Helpers (mirror test_latency_gate_cli.py)
# ---------------------------------------------------------------------------


def _valid_report_dict(
    samples_ms: list[float],
    *,
    p95_override: float | None = None,
    threshold_ms: float = 10.0,
) -> dict:
    """Build a valid ``ardur.latency_report.v1.0``-shaped dict."""

    report = build_report(
        benchmark_name="cli-test",
        samples_ms=samples_ms,
        threshold_ms=threshold_ms,
        threshold_result="pass",
    )
    payload = report_to_dict(report)
    if p95_override is not None:
        payload["p95_ms"] = float(p95_override)
    return payload


def _write_reports(
    directory: Path,
    reports: list[dict],
    *,
    filenames: list[str] | None = None,
) -> list[Path]:
    """Write report dicts as JSON files in ``directory``. Returns paths."""

    paths: list[Path] = []
    for i, report in enumerate(reports):
        name = (
            filenames[i]
            if filenames and i < len(filenames)
            else f"report-{i:03d}.json"
        )
        path = directory / name
        path.write_text(json.dumps(report), encoding="utf-8")
        paths.append(path)
    return paths


# ---------------------------------------------------------------------------
# 1. --output writes file and returns correct exit code
# ---------------------------------------------------------------------------


class TestLatencyGateOutputFlag:
    """``ardur latency-gate evaluate --output`` writes JSON to a file."""

    def test_output_writes_file_pass(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Three passing reports -> rc=0, file written with envelope."""
        reports = [
            _valid_report_dict([1.0, 2.0], p95_override=v)
            for v in (3.0, 4.0, 5.0)
        ]
        _write_reports(tmp_path, reports)
        out_file = tmp_path / "gate_report.json"
        exit_code = main([
            "latency-gate", "evaluate",
            "--reports", str(tmp_path),
            "--output", str(out_file),
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["condition"] == "latency_gate_evaluate_report_written"
        assert parsed["output"] == str(out_file)
        assert "report_sha256" in parsed
        assert out_file.is_file()
        written = json.loads(out_file.read_text())
        assert written["verdict"] == "pass"
        assert written["ok"] is True
        # Verify sha256 matches
        payload_bytes = json.dumps(written, indent=2, sort_keys=True).encode("utf-8")
        expected_hash = hashlib.sha256(payload_bytes).hexdigest()
        assert parsed["report_sha256"] == expected_hash

    def test_output_preserves_fail_exit_code(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """One over-threshold report -> rc=1, file still written."""
        reports = [
            _valid_report_dict([1.0, 2.0], p95_override=v)
            for v in (3.0, 4.0, 12.0)
        ]
        _write_reports(tmp_path, reports)
        out_file = tmp_path / "gate_fail.json"
        exit_code = main([
            "latency-gate", "evaluate",
            "--reports", str(tmp_path),
            "--output", str(out_file),
        ])
        assert exit_code == 1
        assert out_file.is_file()
        written = json.loads(out_file.read_text())
        assert written["verdict"] == "fail"

    def test_output_preserves_inconclusive_exit_code(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Fewer reports than --min-runs -> rc=2, file still written."""
        reports = [
            _valid_report_dict([1.0, 2.0], p95_override=3.0),
        ]
        _write_reports(tmp_path, reports)
        out_file = tmp_path / "gate_inconclusive.json"
        exit_code = main([
            "latency-gate", "evaluate",
            "--reports", str(tmp_path),
            "--min-runs", "3",
            "--output", str(out_file),
        ])
        assert exit_code == 2
        assert out_file.is_file()
        written = json.loads(out_file.read_text())
        assert written["verdict"] == "inconclusive"

    def test_without_output_prints_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Omitting --output preserves the original stdout-only behavior."""
        reports = [
            _valid_report_dict([1.0, 2.0], p95_override=v)
            for v in (3.0, 4.0, 5.0)
        ]
        _write_reports(tmp_path, reports)
        exit_code = main([
            "latency-gate", "evaluate",
            "--reports", str(tmp_path),
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["verdict"] == "pass"
        assert parsed["ok"] is True
        assert "condition" not in parsed  # no output confirmation


# ---------------------------------------------------------------------------
# 2. --redact-paths
# ---------------------------------------------------------------------------


class TestLatencyGateRedactPaths:
    """``ardur latency-gate evaluate --redact-paths`` redacts local paths."""

    def test_redact_paths_in_stdout(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--redact-paths replaces local absolute paths in stdout JSON."""
        reports = [
            _valid_report_dict([1.0, 2.0], p95_override=v)
            for v in (3.0, 4.0, 5.0)
        ]
        _write_reports(tmp_path, reports)
        exit_code = main([
            "latency-gate", "evaluate",
            "--reports", str(tmp_path),
            "--redact-paths",
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        rendered = captured.out
        # The absolute tmp_path must not appear in the output
        assert str(tmp_path) not in rendered
        # But the verdict should still be present
        parsed = json.loads(rendered)
        assert parsed["verdict"] == "pass"

    def test_redact_paths_with_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--output + --redact-paths: file content has redacted paths."""
        reports = [
            _valid_report_dict([1.0, 2.0], p95_override=v)
            for v in (3.0, 4.0, 5.0)
        ]
        _write_reports(tmp_path, reports)
        out_file = tmp_path / "gate_redacted.json"
        exit_code = main([
            "latency-gate", "evaluate",
            "--reports", str(tmp_path),
            "--output", str(out_file),
            "--redact-paths",
        ])
        assert exit_code == 0
        written_str = out_file.read_text()
        assert str(tmp_path) not in written_str
        # The file should still be valid JSON with the verdict
        written = json.loads(written_str)
        assert written["verdict"] == "pass"

    def test_redact_paths_warns_without_json_or_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--redact-paths without --json or --output prints warning to stderr.
        Uses the default JSON format path (no --format text) so the warning
        fires inside ``_handle_output_and_redact``."""
        reports = [
            _valid_report_dict([1.0, 2.0], p95_override=v)
            for v in (3.0, 4.0, 5.0)
        ]
        _write_reports(tmp_path, reports)
        exit_code = main([
            "latency-gate", "evaluate",
            "--reports", str(tmp_path),
            "--redact-paths",
        ])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "warning" in captured.err.lower()
        assert "--redact-paths" in captured.err


# ---------------------------------------------------------------------------
# 3. --output write failure
# ---------------------------------------------------------------------------


class TestLatencyGateOutputWriteFailure:
    """``ardur latency-gate evaluate --output`` write failure produces
    structured JSON error."""

    def test_output_write_failure_returns_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Point --output at a directory (not a file) to trigger write failure."""
        reports = [
            _valid_report_dict([1.0, 2.0], p95_override=v)
            for v in (3.0, 4.0, 5.0)
        ]
        _write_reports(tmp_path, reports)
        out_dir = tmp_path / "outdir"
        out_dir.mkdir()
        exit_code = main([
            "latency-gate", "evaluate",
            "--reports", str(tmp_path),
            "--output", str(out_dir),
        ])
        assert exit_code == 1
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["ok"] is False
        assert "output_write_failed" in parsed["error"]


# ---------------------------------------------------------------------------
# 4. Parser: latency-gate evaluate accepts the new flags
# ---------------------------------------------------------------------------


class TestLatencyGateParserAcceptsNewFlags:
    """``latency-gate evaluate`` must accept ``--output`` and ``--redact-paths``."""

    def test_output_flag_accepted(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "latency-gate", "evaluate",
            "--reports", "/tmp/reports",
            "--output", "/tmp/r.json",
        ])
        assert getattr(args, "output") == "/tmp/r.json"

    def test_redact_paths_flag_accepted(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "latency-gate", "evaluate",
            "--reports", "/tmp/reports",
            "--redact-paths",
        ])
        assert getattr(args, "redact_paths") is True

    def test_flags_default_none_false(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "latency-gate", "evaluate",
            "--reports", "/tmp/reports",
        ])
        assert getattr(args, "output") is None
        assert getattr(args, "redact_paths") is False

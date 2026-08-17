"""Tests for :mod:`vibap.latency_gate_cli` and the ``ardur latency-gate
evaluate`` CLI integration (issue #380, scope item 4).

Covers the report-loading harness (valid/invalid/empty/nonexistent
directories, mixed content), the :func:`run_gate` wrapper, the
:func:`format_gate_output` formatter (JSON + text), and the full CLI
end-to-end including structured-JSON error handling for empty paths,
nonexistent dirs, and out-of-range numeric thresholds.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vibap.cli import main
from vibap.latency_gate import (
    VERDICT_FAIL,
    VERDICT_PASS,
    GateProtocol,
)
from vibap.latency_gate_cli import (
    LatencyGateCliError,
    format_gate_output,
    load_reports_from_directory,
    run_gate,
)
from vibap.latency_report import (
    build_report,
    report_to_dict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _valid_report_dict(
    samples_ms: list[float],
    *,
    p95_override: float | None = None,
    threshold_ms: float = 10.0,
) -> dict[str, Any]:
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
    reports: list[dict[str, Any]],
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
# 1. load_reports_from_directory: valid reports
# ---------------------------------------------------------------------------


def test_load_valid_reports(tmp_path: Path) -> None:
    reports = [
        _valid_report_dict([1.0, 2.0, 3.0], p95_override=3.0),
        _valid_report_dict([1.0, 2.0, 4.0], p95_override=4.0),
        _valid_report_dict([1.0, 2.0, 5.0], p95_override=5.0),
    ]
    _write_reports(tmp_path, reports)
    valid, invalid = load_reports_from_directory(tmp_path)
    assert len(valid) == 3
    assert len(invalid) == 0
    # Provenance key is set
    for entry in valid:
        assert "_source_file" in entry
        assert entry["_source_file"].endswith(".json")


def test_load_reports_sorted_deterministically(tmp_path: Path) -> None:
    """Files must be processed in sorted filename order so repeated runs
    produce byte-identical input lists regardless of filesystem glob order."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (9.0, 1.0, 5.0)
    ]
    _write_reports(
        tmp_path,
        reports,
        filenames=["c-report.json", "a-report.json", "b-report.json"],
    )
    valid, _ = load_reports_from_directory(tmp_path)
    # Sorted order: a, b, c -> p95s 1.0, 5.0, 9.0
    assert valid[0]["_source_file"] == "a-report.json"
    assert valid[1]["_source_file"] == "b-report.json"
    assert valid[2]["_source_file"] == "c-report.json"
    assert valid[0]["p95_ms"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# 2. load_reports_from_directory: invalid files
# ---------------------------------------------------------------------------


def test_load_reports_with_invalid_json(tmp_path: Path) -> None:
    """A file that is not valid JSON is recorded as invalid, not raised."""

    good = _valid_report_dict([1.0, 2.0, 3.0])
    _write_reports(tmp_path, [good])
    (tmp_path / "broken.json").write_text("{not valid json", encoding="utf-8")
    valid, invalid = load_reports_from_directory(tmp_path)
    assert len(valid) == 1
    assert len(invalid) == 1
    assert invalid[0]["filename"] == "broken.json"
    assert "invalid_json" in invalid[0]["reason"]


def test_load_reports_with_non_object_json(tmp_path: Path) -> None:
    """A JSON array or scalar is not a report dict -> invalid."""

    good = _valid_report_dict([1.0, 2.0, 3.0])
    _write_reports(tmp_path, [good])
    (tmp_path / "array.json").write_text("[1, 2, 3]", encoding="utf-8")
    (tmp_path / "scalar.json").write_text("42", encoding="utf-8")
    valid, invalid = load_reports_from_directory(tmp_path)
    assert len(valid) == 1
    assert len(invalid) == 2
    reasons = {e["reason"] for e in invalid}
    assert any(r.startswith("non_object_json") for r in reasons)


def test_load_reports_mixed_valid_and_invalid(tmp_path: Path) -> None:
    """A directory with a mix of valid and invalid files splits correctly."""

    good = _valid_report_dict([1.0, 2.0, 3.0])
    _write_reports(tmp_path, [good, good])
    (tmp_path / "broken-1.json").write_text("}{", encoding="utf-8")
    (tmp_path / "broken-2.json").write_text("not json at all", encoding="utf-8")
    valid, invalid = load_reports_from_directory(tmp_path)
    assert len(valid) == 2
    assert len(invalid) == 2


# ---------------------------------------------------------------------------
# 3. load_reports_from_directory: empty and nonexistent directories
# ---------------------------------------------------------------------------


def test_load_reports_empty_directory(tmp_path: Path) -> None:
    """An existing but empty directory yields ([], [])."""

    valid, invalid = load_reports_from_directory(tmp_path)
    assert valid == []
    assert invalid == []


def test_load_reports_nonexistent_directory(tmp_path: Path) -> None:
    """A path that does not exist raises LatencyGateCliError."""

    missing = tmp_path / "does-not-exist"
    with pytest.raises(LatencyGateCliError, match="does not exist"):
        load_reports_from_directory(missing)


def test_load_reports_path_is_file_not_directory(tmp_path: Path) -> None:
    """A path that is a file, not a directory, raises."""

    file_path = tmp_path / "not-a-dir.json"
    file_path.write_text("{}", encoding="utf-8")
    with pytest.raises(LatencyGateCliError, match="not a directory"):
        load_reports_from_directory(file_path)


def test_load_reports_ignores_non_json_files(tmp_path: Path) -> None:
    """Only ``*.json`` files are considered; others are silently ignored."""

    good = _valid_report_dict([1.0, 2.0, 3.0])
    _write_reports(tmp_path, [good])
    (tmp_path / "readme.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# notes", encoding="utf-8")
    valid, invalid = load_reports_from_directory(tmp_path)
    assert len(valid) == 1
    assert len(invalid) == 0


# ---------------------------------------------------------------------------
# 4. run_gate wrapper
# ---------------------------------------------------------------------------


def test_run_gate_passes_through_to_evaluator() -> None:
    """run_gate is a thin wrapper; it must produce the same decision the
    evaluator would produce for the same inputs."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 5.0)
    ]
    protocol = GateProtocol(min_independent_runs=3, threshold_ms=10.0)
    decision = run_gate(reports, protocol)
    assert decision.verdict == VERDICT_PASS
    assert decision.valid_report_count == 3


def test_run_gate_rejects_non_gate_protocol() -> None:
    """run_gate raises LatencyGateCliError for a non-GateProtocol argument."""

    with pytest.raises(LatencyGateCliError):
        run_gate([], {"min_independent_runs": 3})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 5. format_gate_output
# ---------------------------------------------------------------------------


def test_format_gate_output_json_is_valid_json() -> None:
    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 5.0)
    ]
    protocol = GateProtocol(min_independent_runs=3, threshold_ms=10.0)
    decision = run_gate(reports, protocol)
    rendered = format_gate_output(decision, "json")
    payload = json.loads(rendered)
    assert payload["verdict"] == "pass"
    assert "aggregate_p95_ms" in payload
    assert "rationale" in payload
    assert "protocol" in payload
    assert "per_report_results" in payload


def test_format_gate_output_text_is_human_readable() -> None:
    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 5.0)
    ]
    protocol = GateProtocol(min_independent_runs=3, threshold_ms=10.0)
    decision = run_gate(reports, protocol)
    rendered = format_gate_output(decision, "text")
    assert "PASS" in rendered
    assert "valid reports" in rendered
    assert "aggregate p95" in rendered


def test_format_gate_output_invalid_format_raises() -> None:
    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 5.0)
    ]
    protocol = GateProtocol(min_independent_runs=3, threshold_ms=10.0)
    decision = run_gate(reports, protocol)
    with pytest.raises(LatencyGateCliError):
        format_gate_output(decision, "xml")  # type: ignore[arg-type]


def test_format_gate_output_text_includes_fail_verdict() -> None:
    """The text renderer must surface FAIL, not just PASS."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 12.0)
    ]
    protocol = GateProtocol(min_independent_runs=3, threshold_ms=10.0)
    decision = run_gate(reports, protocol)
    assert decision.verdict == VERDICT_FAIL
    rendered = format_gate_output(decision, "text")
    assert "FAIL" in rendered


# ---------------------------------------------------------------------------
# 6. CLI integration: valid end-to-end
# ---------------------------------------------------------------------------


def test_cli_evaluate_pass(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """End-to-end: three passing reports -> rc=0, verdict=pass in JSON."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 5.0)
    ]
    _write_reports(tmp_path, reports)
    rc = main(["latency-gate", "evaluate", "--reports", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["ok"] is True
    assert payload["verdict"] == "pass"
    assert payload["decision"]["verdict"] == "pass"
    assert payload["decision"]["valid_report_count"] == 3
    assert payload["invalid_files"] == []


def test_cli_evaluate_fail(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """End-to-end: one over-threshold report -> rc=1, verdict=fail."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 12.0)
    ]
    _write_reports(tmp_path, reports)
    rc = main(["latency-gate", "evaluate", "--reports", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)
    assert payload["verdict"] == "fail"


def test_cli_evaluate_inconclusive_exit_code_2(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Fewer reports than --min-runs -> INCONCLUSIVE -> rc=2."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=3.0),
    ]
    _write_reports(tmp_path, reports)
    rc = main(
        ["latency-gate", "evaluate", "--reports", str(tmp_path), "--min-runs", "3"]
    )
    captured = capsys.readouterr()
    assert rc == 2
    payload = json.loads(captured.out)
    assert payload["verdict"] == "inconclusive"


def test_cli_evaluate_text_output(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """--format text produces a human-readable summary, not JSON."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 5.0)
    ]
    _write_reports(tmp_path, reports)
    rc = main(
        [
            "latency-gate",
            "evaluate",
            "--reports",
            str(tmp_path),
            "--format",
            "text",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "PASS" in captured.out
    # Text output is not valid JSON (it's multi-line human text)
    with pytest.raises(json.JSONDecodeError):
        json.loads(captured.out)


def test_cli_evaluate_output_format_alias(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """--output-format is accepted as a backward-compatible alias for --format."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 5.0)
    ]
    _write_reports(tmp_path, reports)
    rc = main(
        [
            "latency-gate",
            "evaluate",
            "--reports",
            str(tmp_path),
            "--output-format",
            "text",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "PASS" in captured.out


# ---------------------------------------------------------------------------
# 7. CLI error handling: structured JSON on invalid inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["", "   ", "\t\n  "],
)
def test_cli_evaluate_empty_reports_path(
    capsys: pytest.CaptureFixture[str], value: str
) -> None:
    """Empty/whitespace --reports must return structured JSON, rc=1."""

    rc = main(["latency-gate", "evaluate", "--reports", value])
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error"] == "latency_gate_reports_empty"
    assert "Traceback" not in captured.out


def test_cli_evaluate_nonexistent_reports_dir(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A --reports path that does not exist must return structured JSON."""

    missing = tmp_path / "no-such-dir"
    rc = main(["latency-gate", "evaluate", "--reports", str(missing)])
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error"] == "latency_gate_reports_dir_not_found"


def test_cli_evaluate_reports_path_is_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A --reports path that is a file, not a dir, must return JSON."""

    file_path = tmp_path / "file.json"
    file_path.write_text("[]", encoding="utf-8")
    rc = main(["latency-gate", "evaluate", "--reports", str(file_path)])
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)
    assert payload["error"] == "latency_gate_reports_not_directory"


def test_cli_evaluate_threshold_ms_zero_or_negative(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """--threshold-ms <= 0 must return structured JSON before loading."""

    for bad in (0.0, -5.0):
        rc = main(
            [
                "latency-gate",
                "evaluate",
                "--reports",
                str(tmp_path),
                "--threshold-ms",
                str(bad),
            ]
        )
        captured = capsys.readouterr()
        assert rc == 1, f"--threshold-ms {bad} should fail"
        payload = json.loads(captured.out)
        assert payload["error"] == "latency_gate_threshold_ms_invalid"


def test_cli_evaluate_min_runs_below_one(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """--min-runs < 1 must return structured JSON before loading."""

    rc = main(
        [
            "latency-gate",
            "evaluate",
            "--reports",
            str(tmp_path),
            "--min-runs",
            "0",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)
    assert payload["error"] == "latency_gate_min_runs_invalid"


def test_cli_evaluate_percentile_out_of_range(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """--percentile outside 1..100 must return structured JSON."""

    for bad in (0, 101):
        rc = main(
            [
                "latency-gate",
                "evaluate",
                "--reports",
                str(tmp_path),
                "--percentile",
                str(bad),
            ]
        )
        captured = capsys.readouterr()
        assert rc == 1, f"--percentile {bad} should fail"
        payload = json.loads(captured.out)
        assert payload["error"] == "latency_gate_percentile_invalid"


# ---------------------------------------------------------------------------
# 8. CLI: mixed valid/invalid files in directory
# ---------------------------------------------------------------------------


def test_cli_evaluate_mixed_valid_invalid_files(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Broken JSON files are reported in ``invalid_files``; valid reports
    still drive the gate verdict."""

    good = _valid_report_dict([1.0, 2.0], p95_override=3.0)
    _write_reports(tmp_path, [good, good, good])
    (tmp_path / "broken.json").write_text("}{", encoding="utf-8")
    rc = main(["latency-gate", "evaluate", "--reports", str(tmp_path)])
    captured = capsys.readouterr()
    # 3 valid reports pass the default min-runs=3; the broken file is
    # surfaced in invalid_files but does not flip the verdict.
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["verdict"] == "pass"
    assert len(payload["invalid_files"]) == 1
    assert payload["invalid_files"][0]["filename"] == "broken.json"


# ---------------------------------------------------------------------------
# 9. CLI: no secrets / private paths in output
# ---------------------------------------------------------------------------


def test_cli_evaluate_output_has_no_secrets_or_paths(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """The JSON output must not contain the raw report directory path,
    absolute host paths, or any token-shaped strings."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 5.0)
    ]
    _write_reports(tmp_path, reports)
    rc = main(["latency-gate", "evaluate", "--reports", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 0
    rendered = captured.out
    # The absolute tmp_path must not leak into the decision body. Filenames
    # are fine (they're basename-only), but the directory prefix is not.
    assert str(tmp_path) not in rendered
    # No token-shaped content
    assert "Bearer" not in rendered
    assert "eyJ" not in rendered  # JWT prefix


# ---------------------------------------------------------------------------
# 10. CLI: custom thresholds work end-to-end
# ---------------------------------------------------------------------------


def test_cli_evaluate_custom_threshold_passes_under(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A custom --threshold-ms of 20 lets p95=12 reports pass."""

    reports = [
        _valid_report_dict([1.0, 2.0], p95_override=v)
        for v in (3.0, 4.0, 12.0)
    ]
    _write_reports(tmp_path, reports)
    rc = main(
        [
            "latency-gate",
            "evaluate",
            "--reports",
            str(tmp_path),
            "--threshold-ms",
            "20.0",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["verdict"] == "pass"
    assert payload["decision"]["protocol"]["threshold_ms"] == pytest.approx(20.0)

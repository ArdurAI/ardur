"""Unit tests for :mod:`vibap.latency_report`.

Covers schema/version invariants, raw-sample validation, percentile
recomputation, functional-error vs threshold-violation separation, partial
report persistence after a simulated native failure, metadata allowlist, and
host-path/token redaction. Also includes a workflow contract test proving
the ``latency-bench`` job uploads artifacts with ``if: always()``, a
digest-pinned ``actions/upload-artifact``, ``${{ runner.temp }}`` output,
and bounded retention.
"""

from __future__ import annotations

import json
import math
import os
import re
import statistics
import time
from pathlib import Path

import pytest

from vibap import latency_report as lr
from vibap.latency_report import (
    REPORT_SCHEMA_VERSION,
    build_report,
    classify_native_exit,
    collect_runner_metadata,
    functional_failure_from_subprocess,
    nearest_rank,
    parse_native_diag,
    report_to_dict,
    validate_samples,
    write_report_atomic,
    FunctionalFailure,
    LatencyReport,
    LatencyReportError,
    ValidatedSamples,
)


# ---------------------------------------------------------------------------
# Schema / version / required-field tests
# ---------------------------------------------------------------------------


def test_schema_version_is_versioned_string() -> None:
    assert REPORT_SCHEMA_VERSION.startswith("ardur.latency_report.")
    # vMAJOR.MINOR shape so consumers can parse compatibility.
    assert re.match(r"^ardur\.latency_report\.v\d+\.\d+$", REPORT_SCHEMA_VERSION)


def test_report_has_required_fields() -> None:
    report = build_report(
        benchmark_name="unit-test-benchmark",
        samples_ms=[1.0, 2.0, 3.0, 4.0, 5.0],
        threshold_ms=10.0,
        threshold_result="pass",
    )
    payload = report_to_dict(report)
    required = {
        "schema_version",
        "benchmark_name",
        "percentile_method",
        "created_at_epoch_s",
        "created_at_iso",
        "samples_ms",
        "sample_count",
        "median_ms",
        "p95_ms",
        "p99_ms",
        "threshold_ms",
        "threshold_result",
        "functional_failures",
        "runner_metadata",
        "validation",
    }
    missing = required - set(payload.keys())
    assert not missing, f"report missing required fields: {missing}"
    # No extra top-level keys: schema additions must be intentional.
    extra = set(payload.keys()) - required
    assert not extra, f"report has unexpected top-level fields: {extra}"


def test_percentile_method_is_nearest_rank() -> None:
    report = build_report(
        benchmark_name="unit-test-benchmark",
        samples_ms=[1.0, 2.0, 3.0],
        threshold_ms=10.0,
        threshold_result="pass",
    )
    assert report.percentile_method == "nearest_rank"


def test_threshold_result_must_be_known_value() -> None:
    with pytest.raises(LatencyReportError):
        build_report(
            benchmark_name="x",
            samples_ms=[1.0],
            threshold_ms=1.0,
            threshold_result="bogus",
        )


def test_benchmark_name_must_not_be_empty() -> None:
    with pytest.raises(LatencyReportError):
        build_report(
            benchmark_name="   ",
            samples_ms=[1.0],
            threshold_ms=1.0,
            threshold_result="pass",
        )


# ---------------------------------------------------------------------------
# Raw sample validation
# ---------------------------------------------------------------------------


def test_validate_samples_preserves_order_and_rejects_none() -> None:
    result = validate_samples([1.0, None, 2.0, 3.0])
    assert result.accepted == [1.0, 2.0, 3.0]
    assert result.rejected_count == 1
    assert result.rejected[0]["ordinal"] == 2
    assert result.rejected[0]["reason"] == "missing"


def test_validate_samples_rejects_non_finite() -> None:
    result = validate_samples([1.0, float("nan"), float("inf"), -float("inf"), 2.0])
    assert result.accepted == [1.0, 2.0]
    reasons = {r["reason"] for r in result.rejected}
    assert reasons == {"non_finite"}
    assert result.rejected_count == 3


def test_validate_samples_rejects_negative() -> None:
    result = validate_samples([1.0, -0.1, 2.0])
    assert result.accepted == [1.0, 2.0]
    assert result.rejected[0]["reason"] == "negative"


def test_validate_samples_rejects_non_numeric() -> None:
    result = validate_samples([1.0, "oops", 2.0])  # type: ignore[list-item]
    assert result.accepted == [1.0, 2.0]
    assert result.rejected[0]["reason"] == "non_numeric"


def test_validate_samples_rejects_duplicate_adjacent() -> None:
    # Exact-equality adjacency is a feeding bug signal (same value captured
    # twice). Legitimate near-equal timings differ in at least one float bit.
    result = validate_samples([1.0, 1.0, 2.0])
    assert result.accepted == [1.0, 2.0]
    assert result.rejected[0]["reason"] == "duplicate"
    assert result.rejected[0]["ordinal"] == 2


def test_validate_samples_accepts_legitimate_value_fluctuation() -> None:
    """Latency samples legitimately fluctuate; value-based monotonicity must
    NOT reject a normal distribution like [2ms, 5ms, 2ms]. Only exact-equality
    adjacency is a duplicate-feeding signal."""
    result = validate_samples([2.0, 5.0, 2.0, 3.0, 1.5, 4.0])
    assert result.accepted == [2.0, 5.0, 2.0, 3.0, 1.5, 4.0]
    assert result.rejected_count == 0


def test_validate_samples_preserves_ordinal_position() -> None:
    """The ``ordinal`` field must be the 1-indexed position in the original
    input sequence so a reviewer can see exactly where a bad sample was
    dropped (deterministic measurement index)."""
    result = validate_samples([1.0, None, "bad", 2.0, float("nan"), 3.0])  # type: ignore[list-item]
    ordinals = [r["ordinal"] for r in result.rejected]
    assert ordinals == [2, 3, 5]
    assert result.accepted == [1.0, 2.0, 3.0]


def test_validate_samples_rejects_string_input() -> None:
    with pytest.raises(LatencyReportError):
        validate_samples("not-a-list")


def test_validate_samples_rejects_none_input() -> None:
    with pytest.raises(LatencyReportError):
        validate_samples(None)


def test_validate_samples_rejects_bytes_input() -> None:
    with pytest.raises(LatencyReportError):
        validate_samples(b"\x00\x01")


def test_validate_samples_rejects_non_iterable() -> None:
    with pytest.raises(LatencyReportError):
        validate_samples(42)  # type: ignore[arg-type]


def test_validate_samples_empty_list_is_accepted_empty() -> None:
    result = validate_samples([])
    assert result.accepted == []
    assert result.rejected_count == 0


# ---------------------------------------------------------------------------
# Percentile recomputation
# ---------------------------------------------------------------------------


def test_report_percentiles_recomputable_from_samples() -> None:
    samples = [float(i) for i in range(1, 101)]  # 1..100, strictly increasing
    report = build_report(
        benchmark_name="recomp",
        samples_ms=samples,
        threshold_ms=1000.0,
        threshold_result="pass",
    )
    # Reviewer recomputation using the documented nearest-rank method.
    assert report.median_ms == pytest.approx(statistics.median(samples))
    assert report.p95_ms == pytest.approx(nearest_rank(samples, 95))
    assert report.p99_ms == pytest.approx(nearest_rank(samples, 99))
    # Sanity: p95 and p99 come from the raw distribution.
    assert report.p95_ms in samples
    assert report.p99_ms in samples


def test_nearest_rank_matches_documented_method() -> None:
    values = [float(i) for i in range(1, 21)]  # n=20
    # ceil(0.95 * 20) = 19 -> index 18 -> 19.0
    assert nearest_rank(values, 95) == 19.0
    # ceil(0.99 * 20) = 20 -> index 19 -> 20.0
    assert nearest_rank(values, 99) == 20.0


def test_nearest_rank_empty_returns_none() -> None:
    assert nearest_rank([], 95) is None


def test_empty_samples_yield_none_percentiles_and_zero_count() -> None:
    report = build_report(
        benchmark_name="empty",
        samples_ms=[],
        threshold_ms=10.0,
        threshold_result="telemetry_only",
    )
    assert report.sample_count == 0
    assert report.median_ms is None
    assert report.p95_ms is None
    assert report.p99_ms is None
    assert report.threshold_result == "telemetry_only"


def test_sample_count_matches_accepted_length() -> None:
    # Input:    [1.0, None, 2.0, 999.0, NaN, 3.0]
    # Accepted: [1.0,        2.0, 999.0,          3.0]   (value fluctuation is OK)
    # Rejected: [None(missing),           NaN(non_finite)]
    report = build_report(
        benchmark_name="count",
        samples_ms=[1.0, None, 2.0, 999.0, float("nan"), 3.0],
        threshold_ms=10.0,
        threshold_result="pass",
    )
    assert report.sample_count == len(report.samples_ms)
    assert report.sample_count == 4
    assert report.samples_ms == [1.0, 2.0, 999.0, 3.0]
    assert report.validation["rejected_count"] == 2


# ---------------------------------------------------------------------------
# Functional failure vs threshold violation separation
# ---------------------------------------------------------------------------


def test_functional_failure_distinct_from_threshold_violation() -> None:
    """A functional failure (warmup crash) and a threshold violation are
    separate fields. A report can carry both, neither, or one without the
    other."""
    functional = FunctionalFailure(
        stage="warmup",
        message="native client exited",
        native_exit_code=11,
        native_errno_classification="EAGAIN",
        native_stage="response-read",
    )
    report = build_report(
        benchmark_name="mixed",
        samples_ms=[1.0, 2.0, 3.0],
        threshold_ms=0.5,  # below all samples -> threshold fail
        threshold_result="fail",
        functional_failures=[functional],
    )
    payload = report_to_dict(report)
    # Functional failures live in functional_failures; threshold result lives
    # in threshold_result. They are separate keys.
    assert payload["threshold_result"] == "fail"
    assert len(payload["functional_failures"]) == 1
    assert payload["functional_failures"][0]["stage"] == "warmup"


def test_threshold_pass_report_has_no_functional_failures() -> None:
    report = build_report(
        benchmark_name="clean",
        samples_ms=[1.0, 2.0],
        threshold_ms=100.0,
        threshold_result="pass",
    )
    assert report.threshold_result == "pass"
    assert report.functional_failures == []


def test_functional_failure_from_subprocess_classifies_exit_11() -> None:
    stderr = (
        "some shell noise\n"
        "ardur-native: stage=response-read errno=11 name=EAGAIN desc=Resource temporarily unavailable\n"
    )
    failure = functional_failure_from_subprocess(
        stage="measured",
        returncode=11,
        stderr_text=stderr,
    )
    assert failure.stage == "measured"
    assert failure.native_exit_code == 11
    assert failure.native_stage == "response-read"
    assert failure.native_errno_classification == "EAGAIN"


def test_functional_failure_falls_back_when_no_diag_line() -> None:
    failure = functional_failure_from_subprocess(
        stage="measured",
        returncode=7,  # socket-connect
        stderr_text=None,
    )
    assert failure.native_exit_code == 7
    assert failure.native_stage == "socket-connect"
    assert failure.native_errno_classification == "socket-connect"


def test_functional_failure_unknown_exit_is_unclassified() -> None:
    failure = functional_failure_from_subprocess(
        stage="measured",
        returncode=99,
        stderr_text=None,
    )
    assert failure.native_errno_classification == "unclassified"
    assert failure.native_stage is None


def test_classify_native_exit_table() -> None:
    assert classify_native_exit(11) == ("response-read", "response-read")
    assert classify_native_exit(2) == ("missing-socket-argument", "missing-socket-argument")
    assert classify_native_exit(None) == (None, None)
    assert classify_native_exit(250) == (None, "unclassified")


def test_parse_native_diag_extracts_fields() -> None:
    diag = parse_native_diag("ardur-native: stage=response-read errno=11 name=EAGAIN desc=x")
    assert diag == {"stage": "response-read", "errno": 11, "name": "EAGAIN"}


def test_parse_native_diag_returns_none_for_empty() -> None:
    assert parse_native_diag(None) is None
    assert parse_native_diag("") is None
    assert parse_native_diag("no diag here") is None


# ---------------------------------------------------------------------------
# Partial report persistence after simulated native failure
# ---------------------------------------------------------------------------


def test_partial_report_persisted_when_native_call_fails(tmp_path: Path) -> None:
    """If the native call fails mid-benchmark, a partial report with the
    samples collected so far plus a functional failure must still be
    written. This is criterion #7."""
    failure = functional_failure_from_subprocess(
        stage="measured",
        returncode=11,
        stderr_text="ardur-native: stage=response-read errno=11 name=EAGAIN desc=timeout",
    )
    report = build_report(
        benchmark_name="partial-native-failure",
        samples_ms=[1.0, 2.0, 3.0],  # only some samples collected before failure
        threshold_ms=0.1,  # threshold not met on partial samples
        threshold_result="fail",
        functional_failures=[failure],
    )
    path = write_report_atomic(report, output_dir=tmp_path)
    assert path.is_file()
    raw = path.read_text()
    data = json.loads(raw)
    assert data["sample_count"] == 3
    assert len(data["functional_failures"]) == 1
    assert data["functional_failures"][0]["native_exit_code"] == 11
    assert data["threshold_result"] == "fail"


def test_partial_report_when_warmup_fails_has_zero_samples(tmp_path: Path) -> None:
    """A warmup failure before any measured sample must still produce a
    persisted report (criterion #7) with zero samples and the functional
    failure recorded."""
    failure = FunctionalFailure(
        stage="warmup",
        message="warmup call crashed",
        native_exit_code=7,
        native_errno_classification="socket-connect",
        native_stage="socket-connect",
    )
    report = build_report(
        benchmark_name="warmup-failure",
        samples_ms=[],
        threshold_ms=10.0,
        threshold_result="telemetry_only",
        functional_failures=[failure],
    )
    path = write_report_atomic(report, output_dir=tmp_path)
    data = json.loads(path.read_text())
    assert data["sample_count"] == 0
    assert data["samples_ms"] == []
    assert len(data["functional_failures"]) == 1
    assert data["functional_failures"][0]["stage"] == "warmup"


# ---------------------------------------------------------------------------
# Metadata allowlist + host-path/token redaction
# ---------------------------------------------------------------------------


def test_metadata_allowlist_only_named_env_vars() -> None:
    env = {
        "GITHUB_SHA": "abc123",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_NAME": "push",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "ImageOS": "ubuntu24",
        "ImageVersion": "20260731.1",
        # Disallowed env vars that must NEVER appear:
        "ARDUR_MISSION_PASSPORT": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.SflKxwRJSMeKKF2QT4f",
        "OPENROUTER_API_KEY": "sk-or-...",
        "HOME": "/Users/secret",
        "USER": "secret_user",
        "PATH": "/usr/bin:/bin",
    }
    metadata = collect_runner_metadata(env=env)
    payload = json.dumps(metadata)
    # Allowlisted keys present:
    assert metadata["source_sha"] == "abc123"
    assert metadata["run_id"] == "42"
    assert metadata["run_attempt"] == "1"
    assert metadata["event"] == "push"
    assert metadata["runner_os"] == "Linux"
    assert metadata["runner_architecture"] == "X64"
    assert metadata["image_os"] == "ubuntu24"
    assert metadata["image_version"] == "20260731.1"
    # Python runtime fields:
    assert metadata["python_implementation"]
    assert metadata["python_version"]
    # Disallowed values never appear:
    assert "secret" not in payload
    assert "sk-or" not in payload
    assert "eyJhbGci" not in payload
    assert "Users" not in payload
    assert "ARDUR_MISSION_PASSPORT" not in payload
    assert "OPENROUTER_API_KEY" not in payload


def test_metadata_missing_env_emits_none_not_absent() -> None:
    metadata = collect_runner_metadata(env={})
    # Missing allowlisted keys must be explicitly None, not silently omitted.
    assert metadata["source_sha"] is None
    assert metadata["run_id"] is None
    assert metadata["event"] is None
    assert metadata["runner_os"] is None
    # Python fields are always present.
    assert metadata["python_implementation"]


def test_metadata_redacts_paths_in_allowlisted_values_defense_in_depth() -> None:
    """Even if an allowlisted env var somehow carried a path, it must be
    redacted. ``GITHUB_SHA`` would never legitimately carry a path, but the
    redaction is defense-in-depth."""
    env = {"GITHUB_SHA": "/Users/leaker/x"}
    metadata = collect_runner_metadata(env=env)
    assert metadata["source_sha"] == "<path>"
    assert "/Users" not in json.dumps(metadata)


def test_sanitize_message_redacts_paths_tokens_jwts() -> None:
    # Direct exercise of the redaction layer via a realistic leaky message.
    # JWT segments are base64url and realistically 8+ chars each.
    leaky = (
        "failed at /Users/foo/secret/ardur for token "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.SflKxwRJSMeKKF2QT4f"
        " bearer sk-or-1234567890abcdef and file:///etc/passwd C:\\Users\\leak"
    )
    failure = FunctionalFailure(stage="measured", message=leaky)
    # The dataclass keeps the raw message; the sanitizer is applied when the
    # message originates from stderr via functional_failure_from_subprocess.
    # Confirm the helper directly:
    sanitized = lr._sanitize_message(leaky)
    assert "/Users" not in sanitized
    assert "eyJhbGci" not in sanitized
    assert "sk-or" not in sanitized
    assert "file://" not in sanitized
    assert "C:\\Users" not in sanitized
    assert "<path>" in sanitized
    assert "<jwt>" in sanitized
    assert "<bearer>" in sanitized


def test_functional_failure_message_from_stderr_is_redacted() -> None:
    stderr = (
        "ardur-native: stage=response-read errno=11 name=EAGAIN desc=x\n"
        "  leaked context: /Users/secret/token eyJhbGci.payload.sig\n"
    )
    failure = functional_failure_from_subprocess(
        stage="measured", returncode=11, stderr_text=stderr
    )
    assert "/Users" not in failure.message
    assert "eyJhbGci" not in failure.message
    # Native diagnostic preserved (it's already sanitized at the source).
    assert "stage=response-read" in failure.message


def test_sanitize_message_truncates_long_text() -> None:
    long_text = "x" * 500
    sanitized = lr._sanitize_message(long_text)
    assert len(sanitized) <= 256


# ---------------------------------------------------------------------------
# Atomic write behavior
# ---------------------------------------------------------------------------


def test_write_report_atomic_creates_file_with_mode_0600(tmp_path: Path) -> None:
    report = build_report(
        benchmark_name="atomic",
        samples_ms=[1.0, 2.0, 3.0],
        threshold_ms=10.0,
        threshold_result="pass",
    )
    path = write_report_atomic(report, output_dir=tmp_path)
    assert path.is_file()
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_write_report_atomic_is_valid_canonical_json(tmp_path: Path) -> None:
    report = build_report(
        benchmark_name="canonical",
        samples_ms=[1.0, 2.0, 3.0],
        threshold_ms=10.0,
        threshold_result="pass",
    )
    path = write_report_atomic(report, output_dir=tmp_path)
    data = json.loads(path.read_text())
    assert data["schema_version"] == REPORT_SCHEMA_VERSION
    assert data["benchmark_name"] == "canonical"


def test_write_report_atomic_filename_is_safe_and_unique(tmp_path: Path) -> None:
    """Filename must be filesystem-safe and unique within a run even if the
    same benchmark name is written twice."""
    weird_name = "weird benchmark/name with spaces!!"
    report1 = build_report(
        benchmark_name=weird_name,
        samples_ms=[1.0],
        threshold_ms=10.0,
        threshold_result="pass",
        created_at_epoch_s=1700000000.0,
    )
    report2 = build_report(
        benchmark_name=weird_name,
        samples_ms=[2.0],
        threshold_ms=10.0,
        threshold_result="pass",
        created_at_epoch_s=1700000001.5,
    )
    path1 = write_report_atomic(report1, output_dir=tmp_path)
    path2 = write_report_atomic(report2, output_dir=tmp_path)
    assert path1 != path2
    # No path separators or unsafe chars in the filename itself.
    assert "/" not in path1.name
    assert re.match(r"^[A-Za-z0-9._-]+\.json$", path1.name)


def test_default_report_dir_uses_runner_temp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    out = lr.default_report_dir()
    assert out == tmp_path / lr.DEFAULT_REPORT_DIR_NAME
    assert out.is_dir()


def test_default_report_dir_falls_back_to_tmpdir_without_runner_temp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    out = lr.default_report_dir()
    assert out.name == lr.DEFAULT_REPORT_DIR_NAME
    assert out.is_dir()


# ---------------------------------------------------------------------------
# Workflow contract test for the latency-bench artifact upload
# ---------------------------------------------------------------------------


WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "tests.yml"
)


def _latency_bench_job_block() -> str:
    """Extract the ``latency-bench`` job block from the workflow YAML.

    Naive slice from the job key to the next top-level job/anchor; sufficient
    for contract assertions without pulling in a YAML parser dependency in
    tests. If the slice heuristic fails, we fail loudly so the test author
    fixes the slicer rather than silently passing.
    """

    assert WORKFLOW_PATH.is_file(), f"workflow not found at {WORKFLOW_PATH}"
    text = WORKFLOW_PATH.read_text()
    start = text.find("  latency-bench:")
    assert start != -1, "latency-bench job not found in workflow"
    # Find the next top-level job: a line starting with two spaces and a
    # word character that is NOT indented further (i.e. a sibling job key).
    # Top-level job keys are at column 2 (two-space indent under ``jobs:``).
    remainder = text[start:]
    lines = remainder.splitlines()
    block_lines: list[str] = []
    for i, line in enumerate(lines):
        if i == 0:
            block_lines.append(line)
            continue
        # Stop at the next top-level job (column-2 non-space key) that is
        # NOT ``latency-bench``.
        if re.match(r"^  [A-Za-z0-9_-]+:", line):
            break
        block_lines.append(line)
    return "\n".join(block_lines)


def test_latency_bench_job_remains_continue_on_error_and_excluded_from_tests_aggregate() -> None:
    block = _latency_bench_job_block()
    assert "continue-on-error: true" in block
    # The blocking ``tests`` aggregate must NOT list latency-bench in needs.
    tests_block_start = WORKFLOW_PATH.read_text().find("  tests:")
    assert tests_block_start != -1
    tests_block = WORKFLOW_PATH.read_text()[tests_block_start:]
    tests_lines = tests_block.splitlines()
    agg_lines = []
    in_needs = False
    for line in tests_lines:
        if re.match(r"^  [A-Za-z0-9_-]+:", line) and line.strip().startswith("tests:"):
            in_needs = False
        if line.strip() == "needs:":
            in_needs = True
            continue
        if in_needs:
            if re.match(r"^      - ", line):
                agg_lines.append(line.strip().lstrip("- ").strip())
            else:
                in_needs = False
    assert "latency-bench" not in agg_lines, (
        "latency-bench must remain excluded from the blocking tests aggregate"
    )


def test_latency_bench_job_uploads_artifact_with_if_always() -> None:
    block = _latency_bench_job_block()
    # The job must have an artifact upload step gated by if: always().
    assert "upload-artifact" in block
    assert "if: always()" in block


def test_latency_bench_upload_action_is_digest_pinned() -> None:
    block = _latency_bench_job_block()
    # Must use the repo's digest-pinned actions/upload-artifact (a 40-hex
    # SHA after the @), matching the other upload steps in the workflow.
    match = re.search(r"uses:\s*actions/upload-artifact@([0-9a-f]{40})", block)
    assert match is not None, (
        "latency-bench upload step must use a digest-pinned actions/upload-artifact"
    )


def test_latency_bench_upload_uses_runner_temp_path() -> None:
    block = _latency_bench_job_block()
    assert "${{ runner.temp }}" in block
    assert "ardur-latency-reports" in block


def test_latency_bench_upload_has_bounded_retention() -> None:
    block = _latency_bench_job_block()
    assert "retention-days:" in block
    match = re.search(r"retention-days:\s*(\d+)", block)
    assert match is not None
    days = int(match.group(1))
    assert 1 <= days <= 90, f"retention-days {days} outside bounded range 1..90"


def test_latency_bench_upload_no_silent_missing_file() -> None:
    block = _latency_bench_job_block()
    # ``if-no-files-found`` must be ``error`` (never silent) or ``warn`` at
    # minimum. ``warn`` surfaces a visible annotation; ``error`` fails the
    # step. Either is acceptable per criterion #10; the unacceptable default
    # is the absent key, which would silently accept missing reports.
    assert "if-no-files-found:" in block, (
        "latency-bench upload must set if-no-files-found so missing reports are visible"
    )
    match = re.search(r"if-no-files-found:\s*(\w+)", block)
    assert match is not None
    assert match.group(1) in {"error", "warn"}, (
        f"if-no-files-found must be error or warn, got {match.group(1)}"
    )


# ---------------------------------------------------------------------------
# Integration: build_report + write_report_atomic end-to-end
# ---------------------------------------------------------------------------


def test_build_and_write_roundtrip_preserves_samples(tmp_path: Path) -> None:
    samples = [float(i) for i in range(1, 51)]
    report = build_report(
        benchmark_name="roundtrip",
        samples_ms=samples,
        threshold_ms=100.0,
        threshold_result="pass",
    )
    path = write_report_atomic(report, output_dir=tmp_path)
    data = json.loads(path.read_text())
    assert data["samples_ms"] == samples
    assert data["sample_count"] == 50
    # Recompute percentiles from the persisted raw samples.
    persisted_samples = data["samples_ms"]
    assert data["median_ms"] == pytest.approx(statistics.median(persisted_samples))
    assert data["p95_ms"] == pytest.approx(nearest_rank(persisted_samples, 95))
    assert data["p99_ms"] == pytest.approx(nearest_rank(persisted_samples, 99))

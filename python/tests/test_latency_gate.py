"""Unit tests for :mod:`vibap.latency_gate`.

Covers the deterministic multi-report evaluator for issue #380: decision-rule
ordering (functional failure hard veto → insufficient reports → statistical
threshold with false-positive budget), determinism, per-report result
structure, percentile recomputation, invalid/missing report handling, and
protocol validation.

The evaluator consumes ``ardur.latency_report.v1.0``-shaped dicts. These tests
build reports via :func:`vibap.latency_report.report_to_dict` +
:func:`vibap.latency_report.build_report` so the gate is exercised against the
real emitter shape, then layer in hand-built minimal dicts for edge cases that
the emitter cannot produce (e.g. malformed schema, missing p95).
"""

from __future__ import annotations

import copy
import math
from dataclasses import replace
from typing import Any

import pytest

from vibap.latency_gate import (
    VERDICT_FAIL,
    VERDICT_INCONCLUSIVE,
    VERDICT_PASS,
    GateDecision,
    GateProtocol,
    LatencyGateError,
    PerReportResult,
    evaluate_reports,
)
from vibap.latency_report import (
    REPORT_SCHEMA_VERSION,
    FunctionalFailure,
    build_report,
    report_to_dict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _valid_report(
    samples_ms: list[float],
    *,
    p95_override: float | None = None,
    threshold_ms: float = 10.0,
    threshold_result: str = "pass",
    functional_failures: list[FunctionalFailure] | None = None,
) -> dict[str, Any]:
    """Build a minimal valid ``ardur.latency_report.v1.0``-shaped report dict."""

    report = build_report(
        benchmark_name="gate-test",
        samples_ms=samples_ms,
        threshold_ms=threshold_ms,
        threshold_result=threshold_result,
        functional_failures=functional_failures,
    )
    payload = report_to_dict(report)
    if p95_override is not None:
        payload["p95_ms"] = float(p95_override)
    return payload


def _default_protocol(
    *,
    min_independent_runs: int = 3,
    threshold_ms: float = 10.0,
    percentile: int = 95,
    false_positive_budget_pct: float = 0.0,
    max_missing_reports: int = 0,
) -> GateProtocol:
    """Build a typical protocol. Defaults match the ADR's 3-run example."""

    return GateProtocol(
        min_independent_runs=min_independent_runs,
        threshold_ms=threshold_ms,
        percentile=percentile,
        false_positive_budget_pct=false_positive_budget_pct,
        max_missing_reports=max_missing_reports,
    )


def _three_passing_reports(p95_values: tuple[float, float, float] = (3.0, 4.0, 5.0)) -> list[dict[str, Any]]:
    """Three valid reports whose p95s are all under a 10ms threshold."""

    return [
        _valid_report([1.0, 2.0, p95], p95_override=p95)
        for p95 in p95_values
    ]


# ---------------------------------------------------------------------------
# 1. All-pass scenario
# ---------------------------------------------------------------------------


def test_all_pass_three_runs_under_threshold() -> None:
    reports = _three_passing_reports((3.0, 4.0, 5.0))
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.verdict == VERDICT_PASS
    assert decision.valid_report_count == 3
    assert decision.missing_report_count == 0
    assert decision.invalid_report_count == 0
    assert decision.over_threshold_count == 0
    assert decision.functional_failures_present is False
    # Aggregate p95 of [3,4,5] via nearest_rank is max = 5.0 (n=3, rank=ceil(.95*3)=3).
    assert decision.aggregate_p95_ms == pytest.approx(5.0)
    assert decision.protocol is protocol


# ---------------------------------------------------------------------------
# 2. Single-run over threshold (statistical fail)
# ---------------------------------------------------------------------------


def test_one_run_over_threshold_fails() -> None:
    # p95s: 3, 4, 12 -> aggregate p95 of [3,4,12] is 12 (max). 12 > 10 -> FAIL.
    reports = _three_passing_reports((3.0, 4.0, 12.0))
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.verdict == VERDICT_FAIL
    assert decision.over_threshold_count == 1
    assert decision.aggregate_p95_ms == pytest.approx(12.0)
    assert "FAIL" in decision.rationale


# ---------------------------------------------------------------------------
# 3. Functional failure in any report = immediate FAIL
# ---------------------------------------------------------------------------


def test_functional_failure_in_one_report_forces_fail() -> None:
    """A functional failure is a hard veto that may not be voted away, even
    when latencies are well under the threshold and the other two reports are
    clean."""
    failure = FunctionalFailure(
        stage="measured",
        message="native client exited",
        native_exit_code=11,
        native_errno_classification="EAGAIN",
        native_stage="response-read",
    )
    clean = _valid_report([1.0, 2.0, 3.0])
    failing = _valid_report(
        [1.0, 2.0, 3.0],
        threshold_result="fail",
        functional_failures=[failure],
    )
    reports = [clean, failing, clean]
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.verdict == VERDICT_FAIL
    assert decision.functional_failures_present is True
    # The failing report is still valid (parses correctly); the failure is a
    # content signal, not a structural break.
    assert decision.valid_report_count == 3
    assert decision.invalid_report_count == 0
    assert "functional failure present" in decision.rationale


def test_functional_failure_outvotes_statistical_pass() -> None:
    """Even if every report's latency is well under threshold, a single
    functional failure still forces FAIL."""
    failure = FunctionalFailure(stage="warmup", message="warmup crash")
    reports = [
        _valid_report([1.0, 2.0], functional_failures=[failure]),
        _valid_report([1.0, 2.0]),
        _valid_report([1.0, 2.0]),
    ]
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.verdict == VERDICT_FAIL


def test_functional_failure_present_when_no_samples_in_that_report() -> None:
    """A warmup-failure report carries zero samples but a functional failure;
    it still triggers the hard veto."""
    failure = FunctionalFailure(stage="warmup", message="no warmup")
    failing = _valid_report(
        [],
        threshold_result="telemetry_only",
        functional_failures=[failure],
    )
    # NOTE: build_report with [] samples yields p95_ms=None, which the gate
    # treats as structurally invalid (cannot extract p95). So this report
    # becomes invalid, not functional-failure-valid. We verify the gate handles
    # that boundary: the report is invalid (counted), no functional-failure
    # veto fires from it.
    protocol = _default_protocol(min_independent_runs=2, threshold_ms=10.0)
    decision = evaluate_reports([failing, _valid_report([1.0, 2.0])], protocol)
    assert decision.verdict == VERDICT_INCONCLUSIVE
    assert decision.invalid_report_count == 1
    assert decision.functional_failures_present is False


# ---------------------------------------------------------------------------
# 4. Insufficient valid reports = INCONCLUSIVE
# ---------------------------------------------------------------------------


def test_insufficient_valid_reports_is_inconclusive() -> None:
    reports = _three_passing_reports((3.0, 4.0, 5.0))[:2]  # only 2
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.verdict == VERDICT_INCONCLUSIVE
    assert decision.valid_report_count == 2
    assert "INCONCLUSIVE" in decision.rationale


def test_insufficient_because_some_invalid() -> None:
    clean = _valid_report([1.0, 2.0, 3.0])
    malformed = {"schema_version": "ardur.latency_report.v1.0", "p95_ms": 5.0}
    # malformed lacks samples_ms -> invalid
    reports = [clean, clean, malformed]
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.verdict == VERDICT_INCONCLUSIVE
    assert decision.valid_report_count == 2
    assert decision.invalid_report_count == 1


# ---------------------------------------------------------------------------
# 5. Invalid / malformed report handling
# ---------------------------------------------------------------------------


def test_invalid_schema_version_report_is_rejected_not_raised() -> None:
    """A wrong-schema report is recorded as invalid, not raised."""
    bad = _valid_report([1.0, 2.0, 3.0])
    bad["schema_version"] = "ardur.latency_report.v2.0"  # future major
    clean = _valid_report([1.0, 2.0, 3.0])
    reports = [clean, clean, bad]
    # Tolerate 1 invalid so the 2 valid reports can still PASS; otherwise the
    # missing/invalid ceiling (Rule 2b) correctly forces INCONCLUSIVE.
    protocol = _default_protocol(
        min_independent_runs=2, threshold_ms=10.0, max_missing_reports=1
    )
    decision = evaluate_reports(reports, protocol)
    assert decision.invalid_report_count == 1
    assert decision.verdict == VERDICT_PASS  # 2 valid still pass
    assert decision.invalid_reports[0]["index"] == 2


def test_missing_p95_report_is_invalid() -> None:
    bad = _valid_report([1.0, 2.0, 3.0])
    del bad["p95_ms"]
    clean = _valid_report([1.0, 2.0, 3.0])
    reports = [clean, clean, bad]
    protocol = _default_protocol(min_independent_runs=2, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.invalid_report_count == 1


def test_non_finite_p95_report_is_invalid() -> None:
    bad = _valid_report([1.0, 2.0, 3.0])
    bad["p95_ms"] = float("inf")
    clean = _valid_report([1.0, 2.0, 3.0])
    reports = [clean, clean, bad]
    protocol = _default_protocol(min_independent_runs=2, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.invalid_report_count == 1


def test_non_dict_report_entry_is_invalid() -> None:
    clean = _valid_report([1.0, 2.0, 3.0])
    reports = [clean, clean, "not-a-report"]  # type: ignore[list-item]
    protocol = _default_protocol(min_independent_runs=2, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.invalid_report_count == 1
    assert decision.invalid_reports[0]["reason"].startswith("non_dict:")


def test_none_entry_is_missing_not_invalid() -> None:
    clean = _valid_report([1.0, 2.0, 3.0])
    reports = [clean, None, clean]  # type: ignore[list-item]
    protocol = _default_protocol(min_independent_runs=2, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.missing_report_count == 1
    assert decision.invalid_report_count == 0
    assert decision.missing_reports[0]["index"] == 1


# ---------------------------------------------------------------------------
# 6. Empty report list
# ---------------------------------------------------------------------------


def test_empty_report_list_is_inconclusive() -> None:
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports([], protocol)
    assert decision.verdict == VERDICT_INCONCLUSIVE
    assert decision.valid_report_count == 0
    assert decision.aggregate_p95_ms is None


def test_none_reports_argument_is_treated_as_empty() -> None:
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(None, protocol)  # type: ignore[arg-type]
    assert decision.verdict == VERDICT_INCONCLUSIVE


# ---------------------------------------------------------------------------
# 7. False-positive budget interaction
# ---------------------------------------------------------------------------


def test_false_positive_budget_allows_one_over_threshold() -> None:
    """With budget_pct=50 and 3 valid reports, floor(3*0.5)=1 over-threshold
    report is tolerated IF the aggregate p95 still meets the threshold."""
    # p95s: 3, 4, 11 -> aggregate p95 of [3,4,11] = 11 (max for n=3). 11 > 10
    # so aggregate fails. Use a scenario where aggregate scrapes under.
    # With percentile=50 (median), aggregate of [3,4,11] = 4 -> under 10.
    reports = _three_passing_reports((3.0, 4.0, 11.0))
    protocol = GateProtocol(
        min_independent_runs=3,
        threshold_ms=10.0,
        percentile=50,  # median: aggregate of [3,4,11] = 4
        false_positive_budget_pct=50.0,  # floor(3*0.5)=1 tolerated
        max_missing_reports=0,
    )
    decision = evaluate_reports(reports, protocol)
    assert decision.over_threshold_count == 1
    # budget_allowed = floor(3 * 50 / 100) = 1; over_threshold=1 <= 1; aggregate=4 <= 10 -> PASS
    assert decision.verdict == VERDICT_PASS
    assert decision.aggregate_p95_ms == pytest.approx(4.0)


def test_false_positive_budget_exhausted_forces_fail() -> None:
    """budget=0 (default) means any over-threshold report forces FAIL, even
    when the aggregate p95 is under the threshold."""
    reports = _three_passing_reports((3.0, 4.0, 11.0))
    protocol = GateProtocol(
        min_independent_runs=3,
        threshold_ms=10.0,
        percentile=50,  # median of [3,4,11] = 4, under threshold
        false_positive_budget_pct=0.0,  # zero tolerance
    )
    decision = evaluate_reports(reports, protocol)
    assert decision.over_threshold_count == 1
    # aggregate under threshold but over_threshold=1 > budget_allowed=0 -> FAIL
    assert decision.verdict == VERDICT_FAIL
    assert "budget exhausted" in decision.rationale


def test_false_positive_budget_two_over_threshold() -> None:
    """budget_pct=50, 4 valid reports -> floor(4*0.5)=2 tolerated. Two over-
    threshold reports at the boundary still pass if aggregate is under."""
    reports = [
        _valid_report([1.0], p95_override=3.0),
        _valid_report([1.0], p95_override=4.0),
        _valid_report([1.0], p95_override=11.0),
        _valid_report([1.0], p95_override=12.0),
    ]
    protocol = GateProtocol(
        min_independent_runs=4,
        threshold_ms=10.0,
        percentile=50,  # median of [3,4,11,12] = (4+11)/2 = 7.5
        false_positive_budget_pct=50.0,  # floor(4*0.5)=2 tolerated
    )
    decision = evaluate_reports(reports, protocol)
    assert decision.over_threshold_count == 2
    assert decision.verdict == VERDICT_PASS


# ---------------------------------------------------------------------------
# 8. Percentile recomputation matches nearest_rank
# ---------------------------------------------------------------------------


def test_aggregate_p95_matches_nearest_rank_recomputation() -> None:
    """The aggregate p95 reported by the gate must be exactly recomputable
    from the per-report p95s using the documented nearest-rank method."""
    from vibap.latency_report import nearest_rank

    p95_values = [3.0, 5.0, 7.0, 9.0, 11.0, 13.0]
    reports = [_valid_report([1.0], p95_override=v) for v in p95_values]
    protocol = GateProtocol(
        min_independent_runs=6,
        threshold_ms=100.0,  # well above to isolate percentile math
        percentile=95,
    )
    decision = evaluate_reports(reports, protocol)
    expected = nearest_rank(p95_values, 95)
    assert decision.aggregate_p95_ms == pytest.approx(expected)
    # nearest_rank of 6 values at p95: ceil(.95*6)=6 -> index 5 -> 13.0
    assert decision.aggregate_p95_ms == pytest.approx(13.0)


def test_aggregate_p99_uses_correct_percentile() -> None:
    from vibap.latency_report import nearest_rank

    p95_values = [float(i) for i in range(1, 21)]  # 1..20
    reports = [_valid_report([1.0], p95_override=v) for v in p95_values]
    protocol = GateProtocol(
        min_independent_runs=20,
        threshold_ms=1000.0,
        percentile=99,
    )
    decision = evaluate_reports(reports, protocol)
    expected = nearest_rank(p95_values, 99)
    assert decision.aggregate_p95_ms == pytest.approx(expected)


# ---------------------------------------------------------------------------
# 9. Per-report results correctly structured
# ---------------------------------------------------------------------------


def test_per_report_results_structure_and_order() -> None:
    """per_report_results preserves input order and carries the right fields."""
    clean = _valid_report([1.0, 2.0, 3.0])  # p95 ~3, under 10
    over = _valid_report([1.0, 2.0, 15.0])  # p95 15, over 10
    bad = {"schema_version": "ardur.latency_report.v1.0"}  # missing samples
    missing: Any = None
    reports = [clean, over, bad, missing]
    protocol = _default_protocol(min_independent_runs=2, threshold_ms=10.0, max_missing_reports=2)
    decision = evaluate_reports(reports, protocol)

    assert len(decision.per_report_results) == 4
    r0, r1, r2, r3 = decision.per_report_results

    assert isinstance(r0, PerReportResult)
    assert r0.index == 0
    assert r0.valid is True
    assert r0.over_threshold is False
    assert r0.functional_failures_present is False
    assert r0.reason is None

    assert r1.index == 1
    assert r1.valid is True
    assert r1.over_threshold is True

    assert r2.index == 2
    assert r2.valid is False
    assert r2.p95_ms is None
    assert r2.reason is not None

    assert r3.index == 3
    assert r3.valid is False
    assert r3.reason == "missing"


# ---------------------------------------------------------------------------
# 10. Determinism: same inputs produce same output across repeated calls
# ---------------------------------------------------------------------------


def test_determinism_repeated_calls_produce_identical_decision() -> None:
    """The evaluator is a pure function: the same inputs must produce
    byte-identical output (verdict, aggregate, per-report, rationale) across
    repeated calls. This is the determinism contract from ADR-027."""
    reports = _three_passing_reports((3.0, 4.0, 12.0))
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decisions = [evaluate_reports(reports, protocol) for _ in range(10)]
    first = decisions[0]
    for d in decisions[1:]:
        assert d.verdict == first.verdict
        assert d.aggregate_p95_ms == first.aggregate_p95_ms
        assert d.rationale == first.rationale
        assert d.valid_report_count == first.valid_report_count
        assert d.over_threshold_count == first.over_threshold_count
        assert len(d.per_report_results) == len(first.per_report_results)
        for a, b in zip(d.per_report_results, first.per_report_results):
            assert a == b


def test_determinism_input_list_not_mutated() -> None:
    """The evaluator must not mutate its input list or the report dicts."""
    reports = _three_passing_reports((3.0, 4.0, 5.0))
    reports_snapshot = copy.deepcopy(reports)
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    evaluate_reports(reports, protocol)
    assert reports == reports_snapshot


# ---------------------------------------------------------------------------
# 11. Rationale field is human-readable and contains exact metrics
# ---------------------------------------------------------------------------


def test_rationale_contains_exact_metrics_pass() -> None:
    reports = _three_passing_reports((3.0, 4.0, 5.0))
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    r = decision.rationale
    assert "PASS" in r
    assert "5.000000" in r  # aggregate_p95_ms formatted
    assert "10.000000" in r  # threshold_ms formatted
    assert "p95" in r


def test_rationale_contains_exact_metrics_inconclusive() -> None:
    reports = _three_passing_reports((3.0, 4.0, 5.0))[:1]
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    r = decision.rationale
    assert "INCONCLUSIVE" in r
    assert "min_independent_runs=3" in r
    assert "valid=1" in r


def test_rationale_is_str_and_nonempty() -> None:
    reports = _three_passing_reports((3.0, 4.0, 5.0))
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert isinstance(decision.rationale, str)
    assert len(decision.rationale) > 0


# ---------------------------------------------------------------------------
# 12. Protocol validation
# ---------------------------------------------------------------------------


def test_protocol_min_independent_runs_must_be_positive() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=0, threshold_ms=10.0)


def test_protocol_threshold_must_be_positive() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=1, threshold_ms=0.0)


def test_protocol_threshold_must_be_finite() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=1, threshold_ms=float("inf"))


def test_protocol_threshold_negative_rejected() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=1, threshold_ms=-1.0)


def test_protocol_percentile_must_be_in_range() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=1, threshold_ms=10.0, percentile=0)
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=1, threshold_ms=10.0, percentile=101)


def test_protocol_budget_must_be_non_negative() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(
            min_independent_runs=1, threshold_ms=10.0,
            false_positive_budget_pct=-1.0,
        )


def test_protocol_max_missing_reports_must_be_non_negative() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(
            min_independent_runs=1, threshold_ms=10.0,
            max_missing_reports=-1,
        )


def test_protocol_rejects_non_gate_protocol_argument() -> None:
    """evaluate_reports must raise if protocol is not a GateProtocol."""
    reports = _three_passing_reports((3.0, 4.0, 5.0))
    with pytest.raises(LatencyGateError):
        evaluate_reports(reports, {"min_independent_runs": 3})  # type: ignore[arg-type]


def test_protocol_rejects_bool_min_independent_runs() -> None:
    """bool is a subclass of int; it must be rejected to avoid silent True/1."""
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=True, threshold_ms=10.0)  # type: ignore[arg-type]


def test_protocol_rejects_bool_threshold() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=1, threshold_ms=True)  # type: ignore[arg-type]


def test_protocol_rejects_bool_percentile() -> None:
    with pytest.raises(LatencyGateError):
        GateProtocol(min_independent_runs=1, threshold_ms=10.0, percentile=True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 13. max_missing_reports ceiling behavior
# ---------------------------------------------------------------------------


def test_max_missing_reports_ceiling_flips_to_inconclusive() -> None:
    """5 valid reports but 4 missing, max_missing=2: even though valid=5 >=
    min_independent_runs=3, the missing ceiling is exceeded -> INCONCLUSIVE."""
    clean = _valid_report([1.0, 2.0, 3.0])
    reports: list[Any] = [clean, clean, clean, clean, clean, None, None, None, None]
    protocol = GateProtocol(
        min_independent_runs=3,
        threshold_ms=10.0,
        max_missing_reports=2,
    )
    decision = evaluate_reports(reports, protocol)
    assert decision.valid_report_count == 5
    assert decision.missing_report_count == 4
    assert decision.verdict == VERDICT_INCONCLUSIVE
    assert "ceiling exceeded" in decision.rationale


def test_max_missing_reports_zero_allows_pass_when_valid_meets_min() -> None:
    """With max_missing=0 and exactly min valid reports, all present, PASS."""
    reports = _three_passing_reports((3.0, 4.0, 5.0))
    protocol = GateProtocol(
        min_independent_runs=3,
        threshold_ms=10.0,
        max_missing_reports=0,
    )
    decision = evaluate_reports(reports, protocol)
    assert decision.verdict == VERDICT_PASS


# ---------------------------------------------------------------------------
# 14. Rule-ordering: functional failure beats insufficient-reports
# ---------------------------------------------------------------------------


def test_functional_failure_beats_insufficient_reports_inconclusive() -> None:
    """Rule 1 fires before Rule 2: a functional failure in a valid report
    forces FAIL even when valid_count < min_independent_runs."""
    failure = FunctionalFailure(stage="measured", message="crash")
    failing_valid = _valid_report(
        [1.0, 2.0], threshold_result="fail", functional_failures=[failure]
    )
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports([failing_valid], protocol)
    # valid_count=1 < min=3, but functional failure fires first -> FAIL
    assert decision.verdict == VERDICT_FAIL
    assert decision.functional_failures_present is True


# ---------------------------------------------------------------------------
# 15. Aggregate p95 is None when no valid reports (for inconclusive rationale)
# ---------------------------------------------------------------------------


def test_aggregate_p95_none_when_all_reports_missing() -> None:
    reports: list[Any] = [None, None, None]
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.verdict == VERDICT_INCONCLUSIVE
    assert decision.aggregate_p95_ms is None
    assert decision.valid_report_count == 0
    assert decision.missing_report_count == 3


# ---------------------------------------------------------------------------
# 16. Accepts minor-version schema drift within same major
# ---------------------------------------------------------------------------


def test_accepts_minor_version_schema_drift_within_same_major() -> None:
    """ardur.latency_report.v1.5 should be accepted if the current major is v1."""
    clean = _valid_report([1.0, 2.0, 3.0])
    drift = _valid_report([1.0, 2.0, 3.0])
    drift["schema_version"] = "ardur.latency_report.v1.5"
    reports = [clean, clean, drift]
    protocol = _default_protocol(min_independent_runs=3, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.valid_report_count == 3
    assert decision.verdict == VERDICT_PASS


# ---------------------------------------------------------------------------
# 17. Verdict constants are stable strings
# ---------------------------------------------------------------------------


def test_verdict_constants_are_stable_strings() -> None:
    assert VERDICT_PASS == "pass"
    assert VERDICT_FAIL == "fail"
    assert VERDICT_INCONCLUSIVE == "inconclusive"


# ---------------------------------------------------------------------------
# 18. Functional failures field must be a list (not silently coerced)
# ---------------------------------------------------------------------------


def test_malformed_functional_failures_field_is_invalid() -> None:
    """If functional_failures is present but not a list, the report is invalid
    rather than silently treated as no-failures."""
    bad = _valid_report([1.0, 2.0, 3.0])
    bad["functional_failures"] = {"not": "a list"}
    clean = _valid_report([1.0, 2.0, 3.0])
    reports = [clean, clean, bad]
    protocol = _default_protocol(min_independent_runs=2, threshold_ms=10.0)
    decision = evaluate_reports(reports, protocol)
    assert decision.invalid_report_count == 1
    assert decision.functional_failures_present is False


# ---------------------------------------------------------------------------
# 19. Boundary: aggregate p95 exactly equals threshold -> PASS
# ---------------------------------------------------------------------------


def test_aggregate_p95_exactly_at_threshold_passes() -> None:
    """``<= threshold`` is the rule, so equality passes."""
    reports = _three_passing_reports((5.0, 10.0, 10.0))
    protocol = GateProtocol(
        min_independent_runs=3,
        threshold_ms=10.0,
        percentile=95,
    )
    decision = evaluate_reports(reports, protocol)
    # aggregate p95 of [5,10,10] via nearest_rank (n=3, rank=3) = 10.0
    assert decision.aggregate_p95_ms == pytest.approx(10.0)
    assert decision.verdict == VERDICT_PASS


# ---------------------------------------------------------------------------
# 20. Replace-based protocol immutability (frozen dataclass)
# ---------------------------------------------------------------------------


def test_gate_protocol_is_frozen() -> None:
    """GateProtocol is a frozen dataclass: attribute reassignment must raise."""
    protocol = _default_protocol()
    with pytest.raises(Exception):
        protocol.min_independent_runs = 5  # type: ignore[misc]


def test_gate_decision_is_frozen() -> None:
    protocol = _default_protocol()
    decision = evaluate_reports(
        _three_passing_reports((3.0, 4.0, 5.0)), protocol
    )
    with pytest.raises(Exception):
        decision.verdict = "bogus"  # type: ignore[misc]

"""Deterministic multi-report latency gate evaluator.

This module consumes already-persisted ``ardur.latency_report.v1.0`` reports
from independent first-attempt benchmark runs and produces a single deterministic
gate verdict using a pre-registered statistical model. It is the first slice
toward making the informational ``latency-bench`` CI job a reliable signal
instead of flaky single-run noise.

Design invariants
-----------------

1.  **Pure / deterministic.** ``evaluate_reports`` is a pure function of
    ``(reports, protocol)``. No wall-clock, random, or environment dependence;
    the same inputs always produce byte-identical output.
2.  **Functional failures are a hard veto.** Any functional failure in any
    valid report forces ``verdict == "fail"`` and cannot be voted away by
    statistical aggregation or the false-positive budget.
3.  **Missing evidence is never a silent pass.** If the valid report count is
    below ``min_independent_runs`` or missing/invalid reports exceed
    ``max_missing_reports``, the verdict is ``inconclusive``.
4.  **Per-report p95 aggregation, not sample pooling.** The aggregate p95 is
    computed over the list of per-report ``p95_ms`` values using the same
    ``nearest_rank`` method as the report emitter, preserving run independence.
5.  **Trust the input list.** The evaluator does not verify first-attempt
    selection; the caller/CI workflow is responsible for feeding it only
    first attempts. See ADR-027 for the trust boundary.

See ``docs/decisions/ADR-027-latency-benchmark-gate-evaluator.md`` for the
full pre-registered statistical model, decision rule order, false-positive
budget semantics, and alternatives considered.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .latency_report import REPORT_SCHEMA_VERSION, nearest_rank


def _major_prefix_for(schema_version: str) -> str:
    """Return the ``ardur.latency_report.vMAJOR.`` prefix for a schema string.

    Used to accept any minor version under the same major. Returns the full
    string unchanged if it does not match the expected shape (so the prefix
    comparison simply fails closed).
    """

    # ``ardur.latency_report.v1.0`` -> ``ardur.latency_report.v1.``
    parts = schema_version.split(".")
    if len(parts) >= 4 and parts[0] == "ardur" and parts[1] == "latency_report":
        return ".".join(parts[:3]) + "."
    return schema_version


#: Schema versions we accept as gate inputs. The evaluator accepts any
#: ``ardur.latency_report.vMAJOR.*`` whose MAJOR matches the emitter's current
#: major version. This tolerates additive minor-version drift (new optional
#: fields) while rejecting a future breaking major bump that this evaluator
#: has not been reviewed against.
_ACCEPTED_SCHEMA_MAJOR_PREFIX = _major_prefix_for(REPORT_SCHEMA_VERSION)

#: Verdict constants. Exposed as module-level strings so callers and tests can
#: compare against :data:`VERDICT_PASS` etc. without importing the dataclass.
VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_INCONCLUSIVE = "inconclusive"
_VALID_VERDICTS = frozenset({VERDICT_PASS, VERDICT_FAIL, VERDICT_INCONCLUSIVE})


class LatencyGateError(ValueError):
    """Raised when a gate evaluation cannot be built or validated.

    A ``ValueError`` subclass for generic-handler compatibility, distinct so
    callers can format a stable ``condition`` field. Raised for protocol
    validation failures and unrecoverable input-shape problems; per-report
    invalidity is recorded in :attr:`GateDecision.invalid_reports` rather than
    raised, so one bad report does not poison the whole evaluation.
    """


@dataclass(frozen=True)
class GateProtocol:
    """Pre-registered parameters for a gate evaluation.

    Immutable for the duration of an evaluation. The protocol is the sole
    source of the threshold; per-report ``threshold_ms`` fields are ignored by
    the gate (preserved in reports for provenance).

    Attributes
    ----------
    min_independent_runs:
        Minimum number of valid reports required to produce a non-INCONCLUSIVE
        verdict. Must be ``>= 1``.
    threshold_ms:
        Maximum allowed aggregate p95 latency, in milliseconds. Must be ``> 0``
        and finite.
    percentile:
        Percentile rank used for the statistical rule. Defaults to ``95``.
        Must be in ``1..100`` inclusive.
    false_positive_budget_pct:
        Fraction of valid reports (0..100) whose per-report p95 may exceed
        ``threshold_ms`` without forcing a FAIL. ``0`` disables tolerance.
        Must be ``>= 0`` and finite.
    max_missing_reports:
        Maximum tolerated missing/invalid reports. If
        ``(missing + invalid) > max_missing_reports`` the verdict is
        INCONCLUSIVE regardless of the valid count. Must be ``>= 0``.
    """

    min_independent_runs: int
    threshold_ms: float
    percentile: int = 95
    false_positive_budget_pct: float = 0.0
    max_missing_reports: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.min_independent_runs, int) or isinstance(
            self.min_independent_runs, bool
        ):
            raise LatencyGateError(
                "min_independent_runs must be an int"
            )
        if self.min_independent_runs < 1:
            raise LatencyGateError(
                "min_independent_runs must be >= 1"
            )
        if isinstance(self.threshold_ms, bool) or not isinstance(
            self.threshold_ms, (int, float)
        ):
            raise LatencyGateError("threshold_ms must be a number")
        threshold = float(self.threshold_ms)
        if not math.isfinite(threshold) or threshold <= 0:
            raise LatencyGateError(
                "threshold_ms must be finite and > 0"
            )
        if not isinstance(self.percentile, int) or isinstance(
            self.percentile, bool
        ):
            raise LatencyGateError("percentile must be an int")
        if not (1 <= self.percentile <= 100):
            raise LatencyGateError(
                "percentile must be in 1..100 inclusive"
            )
        if isinstance(self.false_positive_budget_pct, bool) or not isinstance(
            self.false_positive_budget_pct, (int, float)
        ):
            raise LatencyGateError(
                "false_positive_budget_pct must be a number"
            )
        budget = float(self.false_positive_budget_pct)
        if not math.isfinite(budget) or budget < 0:
            raise LatencyGateError(
                "false_positive_budget_pct must be finite and >= 0"
            )
        if not isinstance(self.max_missing_reports, int) or isinstance(
            self.max_missing_reports, bool
        ):
            raise LatencyGateError("max_missing_reports must be an int")
        if self.max_missing_reports < 0:
            raise LatencyGateError(
                "max_missing_reports must be >= 0"
            )
        # Normalize numeric fields to canonical types so equality and
        # determinism checks compare cleanly across int/float construction.
        object.__setattr__(self, "threshold_ms", threshold)
        object.__setattr__(self, "false_positive_budget_pct", budget)


@dataclass(frozen=True)
class PerReportResult:
    """The evaluator's view of a single input report.

    ``index`` is the 0-based position in the input ``reports`` list so a
    reviewer can locate exactly which input produced which result.
    ``valid`` is ``False`` for missing or invalid entries; in that case
    ``p95_ms`` is ``None`` and ``reason`` explains why the entry was excluded.
    """

    index: int
    valid: bool
    p95_ms: float | None
    over_threshold: bool
    functional_failures_present: bool
    reason: str | None = None


@dataclass(frozen=True)
class GateDecision:
    """The outcome of :func:`evaluate_reports`.

    Field order is stable for deterministic serialization. The ``rationale``
    field is a human-readable string containing the exact metrics that drove
    the verdict; it is safe to surface in a CI summary.
    """

    verdict: str
    per_report_results: list[PerReportResult]
    aggregate_p95_ms: float | None
    functional_failures_present: bool
    valid_report_count: int
    missing_report_count: int
    invalid_report_count: int
    over_threshold_count: int
    rationale: str
    protocol: GateProtocol
    #: Input-list indices of reports that were structurally invalid (present
    #: but unparseable / wrong-shape). Parallel to the input order.
    invalid_reports: list[dict[str, Any]] = field(default_factory=list)
    #: Input-list indices of reports that were missing (None / non-dict
    #: entries where an independent report was expected).
    missing_reports: list[dict[str, Any]] = field(default_factory=list)


def evaluate_reports(
    reports: list[dict[str, Any]] | None,
    protocol: GateProtocol,
) -> GateDecision:
    """Evaluate ``reports`` against ``protocol`` and return a gate decision.

    This is the sole public entry point. It applies the decision rules in the
    exact order specified in ADR-027:

    1. Functional-failure hard veto → ``fail``.
    2. Insufficient valid reports → ``inconclusive``.
    3. Statistical threshold with false-positive budget → ``pass`` or ``fail``.

    Parameters
    ----------
    reports:
        List of ``ardur.latency_report.v1.0`` report dicts (as produced by
        :func:`vibap.latency_report.report_to_dict`) plus, optionally,
        ``None`` or non-dict entries representing missing reports. ``None``
        (the whole list) is treated as an empty list and yields INCONCLUSIVE
        given any sane protocol.
    protocol:
        The pre-registered :class:`GateProtocol`. Validated at construction.

    Returns
    -------
    GateDecision
        Always. This function does not raise on bad individual reports; it
        records them in ``invalid_reports`` / ``missing_reports`` and proceeds
        with the remaining valid reports. It only raises
        :class:`LatencyGateError` for protocol validation failures (which
        surface at :class:`GateProtocol` construction time) or a non-GateProtocol
        ``protocol`` argument.
    """

    if not isinstance(protocol, GateProtocol):
        raise LatencyGateError(
            "protocol must be a GateProtocol instance"
        )
    # Re-run validation defensively in case a caller bypassed __post_init__
    # via object.__setattr__ on a frozen dataclass. Cheap and deterministic.
    _validate_protocol_defensive(protocol)

    # Normalize the input list. None (whole list) -> empty list. We do NOT
    # iterate a string/bytes/dict as if it were a list of reports; that would
    # silently produce wrong-shaped results.
    if reports is None:
        reports_list: list[Any] = []
    elif isinstance(reports, (str, bytes, bytearray)):
        raise LatencyGateError(
            "reports must be a list of report dicts, not a string/bytes"
        )
    else:
        try:
            reports_list = list(reports)
        except TypeError as exc:
            raise LatencyGateError(
                "reports must be iterable"
            ) from exc

    per_report: list[PerReportResult] = []
    valid_p95s: list[float] = []
    valid_indices: list[int] = []
    functional_failures_present = False
    over_threshold_count = 0
    invalid_records: list[dict[str, Any]] = []
    missing_records: list[dict[str, Any]] = []

    for index, entry in enumerate(reports_list):
        if entry is None:
            per_report.append(
                PerReportResult(
                    index=index,
                    valid=False,
                    p95_ms=None,
                    over_threshold=False,
                    functional_failures_present=False,
                    reason="missing",
                )
            )
            missing_records.append({"index": index, "reason": "missing"})
            continue
        if not isinstance(entry, dict):
            per_report.append(
                PerReportResult(
                    index=index,
                    valid=False,
                    p95_ms=None,
                    over_threshold=False,
                    functional_failures_present=False,
                    reason=f"non_dict:{type(entry).__name__}",
                )
            )
            invalid_records.append(
                {"index": index, "reason": f"non_dict:{type(entry).__name__}"}
            )
            continue

        validation = _validate_report(entry)
        if validation.error is not None:
            per_report.append(
                PerReportResult(
                    index=index,
                    valid=False,
                    p95_ms=None,
                    over_threshold=False,
                    functional_failures_present=False,
                    reason=validation.error,
                )
            )
            invalid_records.append(
                {"index": index, "reason": validation.error}
            )
            continue

        p95 = validation.p95_ms
        assert p95 is not None  # validated above
        failures = validation.functional_failures_present
        if failures:
            functional_failures_present = True
        over = p95 > protocol.threshold_ms
        if over:
            over_threshold_count += 1
        valid_p95s.append(p95)
        valid_indices.append(index)
        per_report.append(
            PerReportResult(
                index=index,
                valid=True,
                p95_ms=p95,
                over_threshold=over,
                functional_failures_present=failures,
                reason=None,
            )
        )

    valid_count = len(valid_p95s)
    missing_count = len(missing_records)
    invalid_count = len(invalid_records)

    # ----- Rule 1: functional-failure hard veto -----------------------------
    if functional_failures_present:
        aggregate_p95 = _aggregate_p95(valid_p95s, protocol.percentile)
        verdict = VERDICT_FAIL
        rationale = (
            f"functional failure present in one or more valid reports; "
            f"verdict FAIL regardless of latency. "
            f"valid={valid_count} missing={missing_count} "
            f"invalid={invalid_count} "
            f"aggregate_p95_ms={_fmt_ms(aggregate_p95)} "
            f"threshold_ms={_fmt_ms(protocol.threshold_ms)}"
        )
        return _build_decision(
            verdict=verdict,
            per_report=per_report,
            aggregate_p95=aggregate_p95,
            functional_failures_present=True,
            valid_count=valid_count,
            missing_count=missing_count,
            invalid_count=invalid_count,
            over_threshold_count=over_threshold_count,
            rationale=rationale,
            protocol=protocol,
            invalid_records=invalid_records,
            missing_records=missing_records,
        )

    # ----- Rule 2: insufficient valid reports -------------------------------
    if valid_count < protocol.min_independent_runs:
        aggregate_p95 = _aggregate_p95(valid_p95s, protocol.percentile)
        verdict = VERDICT_INCONCLUSIVE
        rationale = (
            f"insufficient valid reports: valid={valid_count} "
            f"< min_independent_runs={protocol.min_independent_runs}; "
            f"verdict INCONCLUSIVE. "
            f"missing={missing_count} invalid={invalid_count} "
            f"max_missing_reports={protocol.max_missing_reports} "
            f"aggregate_p95_ms={_fmt_ms(aggregate_p95)}"
        )
        return _build_decision(
            verdict=verdict,
            per_report=per_report,
            aggregate_p95=aggregate_p95,
            functional_failures_present=False,
            valid_count=valid_count,
            missing_count=missing_count,
            invalid_count=invalid_count,
            over_threshold_count=over_threshold_count,
            rationale=rationale,
            protocol=protocol,
            invalid_records=invalid_records,
            missing_records=missing_records,
        )

    # Also enforce the missing/invalid ceiling. This catches the case where
    # valid_count >= min_independent_runs but the missing+invalid tail is
    # unacceptably large (e.g. 5 valid but 4 missing out of 9 expected).
    if (missing_count + invalid_count) > protocol.max_missing_reports:
        aggregate_p95 = _aggregate_p95(valid_p95s, protocol.percentile)
        verdict = VERDICT_INCONCLUSIVE
        rationale = (
            f"missing/invalid ceiling exceeded: "
            f"missing+invalid={missing_count + invalid_count} "
            f"> max_missing_reports={protocol.max_missing_reports}; "
            f"verdict INCONCLUSIVE. valid={valid_count} "
            f"aggregate_p95_ms={_fmt_ms(aggregate_p95)} "
            f"threshold_ms={_fmt_ms(protocol.threshold_ms)}"
        )
        return _build_decision(
            verdict=verdict,
            per_report=per_report,
            aggregate_p95=aggregate_p95,
            functional_failures_present=False,
            valid_count=valid_count,
            missing_count=missing_count,
            invalid_count=invalid_count,
            over_threshold_count=over_threshold_count,
            rationale=rationale,
            protocol=protocol,
            invalid_records=invalid_records,
            missing_records=missing_records,
        )

    # ----- Rule 3: statistical threshold + false-positive budget ------------
    aggregate_p95 = _aggregate_p95(valid_p95s, protocol.percentile)
    # Rule 3 is only reached when valid_count >= min_independent_runs >= 1,
    # so valid_p95s is guaranteed non-empty and aggregate_p95 is non-None.
    assert aggregate_p95 is not None, "aggregate_p95 must be non-None in Rule 3"
    aggregate_p95_value: float = aggregate_p95
    budget_allowed = _budget_allowed_over(
        valid_count, protocol.false_positive_budget_pct
    )

    if aggregate_p95_value <= protocol.threshold_ms and over_threshold_count <= budget_allowed:
        verdict = VERDICT_PASS
        rationale = (
            f"aggregate p{protocol.percentile} "
            f"({_fmt_ms(aggregate_p95_value)} ms) <= "
            f"threshold_ms ({_fmt_ms(protocol.threshold_ms)} ms); "
            f"over_threshold={over_threshold_count} "
            f"<= budget_allowed={budget_allowed}; verdict PASS. "
            f"valid={valid_count}"
        )
    elif over_threshold_count > budget_allowed:
        # Budget exhausted: over-threshold reports alone force FAIL even if
        # the aggregate p95 happens to scrape under the threshold.
        verdict = VERDICT_FAIL
        rationale = (
            f"false-positive budget exhausted: over_threshold="
            f"{over_threshold_count} > budget_allowed={budget_allowed} "
            f"(budget_pct={_fmt_pct(protocol.false_positive_budget_pct)}% "
            f"of valid={valid_count}); verdict FAIL. "
            f"aggregate_p95_ms={_fmt_ms(aggregate_p95_value)} "
            f"threshold_ms={_fmt_ms(protocol.threshold_ms)}"
        )
    else:
        verdict = VERDICT_FAIL
        rationale = (
            f"aggregate p{protocol.percentile} "
            f"({_fmt_ms(aggregate_p95_value)} ms) > "
            f"threshold_ms ({_fmt_ms(protocol.threshold_ms)} ms); "
            f"verdict FAIL. valid={valid_count} "
            f"over_threshold={over_threshold_count} "
            f"budget_allowed={budget_allowed}"
        )

    return _build_decision(
        verdict=verdict,
        per_report=per_report,
        aggregate_p95=aggregate_p95,
        functional_failures_present=False,
        valid_count=valid_count,
        missing_count=missing_count,
        invalid_count=invalid_count,
        over_threshold_count=over_threshold_count,
        rationale=rationale,
        protocol=protocol,
        invalid_records=invalid_records,
        missing_records=missing_records,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ReportValidation:
    """Result of :func:`_validate_report`."""

    p95_ms: float | None
    functional_failures_present: bool
    error: str | None


def _validate_report(report: dict[str, Any]) -> _ReportValidation:
    """Validate a single report dict and extract its p95 + failure flag.

    Returns a :class:`_ReportValidation` with ``error`` set if the report is
    structurally unusable. Never raises on bad-shape input; the caller records
    the error and proceeds.
    """

    schema = report.get("schema_version")
    if not isinstance(schema, str) or not schema.startswith(
        _ACCEPTED_SCHEMA_MAJOR_PREFIX
    ):
        return _ReportValidation(
            p95_ms=None,
            functional_failures_present=False,
            error=f"schema_version_unaccepted:{schema!r}",
        )

    samples = report.get("samples_ms")
    if not isinstance(samples, list) or not samples:
        return _ReportValidation(
            p95_ms=None,
            functional_failures_present=False,
            error="samples_ms_empty_or_missing",
        )

    p95 = report.get("p95_ms")
    if p95 is None:
        return _ReportValidation(
            p95_ms=None,
            functional_failures_present=False,
            error="p95_ms_missing",
        )
    if isinstance(p95, bool) or not isinstance(p95, (int, float)):
        return _ReportValidation(
            p95_ms=None,
            functional_failures_present=False,
            error=f"p95_ms_non_numeric:{type(p95).__name__}",
        )
    p95_float = float(p95)
    if not math.isfinite(p95_float) or p95_float < 0:
        return _ReportValidation(
            p95_ms=None,
            functional_failures_present=False,
            error=f"p95_ms_invalid:{p95!r}",
        )

    failures = report.get("functional_failures")
    if failures is None:
        failures_present = False
    elif isinstance(failures, list):
        failures_present = len(failures) > 0
    else:
        # Malformed failures field: treat as invalid rather than guessing.
        return _ReportValidation(
            p95_ms=None,
            functional_failures_present=False,
            error=f"functional_failures_non_list:{type(failures).__name__}",
        )

    return _ReportValidation(
        p95_ms=p95_float,
        functional_failures_present=failures_present,
        error=None,
    )


def _aggregate_p95(p95s: list[float], percentile: int) -> float | None:
    """Compute the aggregate p95 over per-report p95 values.

    Uses the same ``nearest_rank`` method as the report emitter. Returns
    ``None`` only for an empty list (which yields an INCONCLUSIVE verdict via
    the insufficient-reports rule).
    """

    return nearest_rank(p95s, percentile)


def _budget_allowed_over(
    valid_count: int, budget_pct: float
) -> int:
    """Number of over-threshold reports tolerated by the false-positive budget.

    ``floor(valid_count * budget_pct / 100)``. Always an integer >= 0. A budget
    of 0 disables tolerance.
    """

    if valid_count <= 0 or budget_pct <= 0:
        return 0
    return int(math.floor(valid_count * budget_pct / 100.0))


def _build_decision(
    *,
    verdict: str,
    per_report: list[PerReportResult],
    aggregate_p95: float | None,
    functional_failures_present: bool,
    valid_count: int,
    missing_count: int,
    invalid_count: int,
    over_threshold_count: int,
    rationale: str,
    protocol: GateProtocol,
    invalid_records: list[dict[str, Any]],
    missing_records: list[dict[str, Any]],
) -> GateDecision:
    """Construct a :class:`GateDecision` with consistent field ordering."""

    assert verdict in _VALID_VERDICTS, f"unexpected verdict {verdict!r}"
    return GateDecision(
        verdict=verdict,
        per_report_results=list(per_report),
        aggregate_p95_ms=aggregate_p95,
        functional_failures_present=functional_failures_present,
        valid_report_count=valid_count,
        missing_report_count=missing_count,
        invalid_report_count=invalid_count,
        over_threshold_count=over_threshold_count,
        rationale=rationale,
        protocol=protocol,
        invalid_reports=list(invalid_records),
        missing_reports=list(missing_records),
    )


def _validate_protocol_defensive(protocol: GateProtocol) -> None:
    """Re-run protocol invariants in case a caller bypassed __post_init__."""

    if protocol.min_independent_runs < 1:
        raise LatencyGateError("min_independent_runs must be >= 1")
    if not math.isfinite(protocol.threshold_ms) or protocol.threshold_ms <= 0:
        raise LatencyGateError("threshold_ms must be finite and > 0")
    if not (1 <= protocol.percentile <= 100):
        raise LatencyGateError("percentile must be in 1..100 inclusive")
    if not math.isfinite(protocol.false_positive_budget_pct) or protocol.false_positive_budget_pct < 0:
        raise LatencyGateError(
            "false_positive_budget_pct must be finite and >= 0"
        )
    if protocol.max_missing_reports < 0:
        raise LatencyGateError("max_missing_reports must be >= 0")


def _fmt_ms(value: float | None) -> str:
    """Format a millisecond value for the rationale string deterministically."""

    if value is None:
        return "none"
    # Trim to microsecond precision; deterministic across platforms.
    return f"{value:.6f}"


def _fmt_pct(value: float) -> str:
    """Format a percentage value for the rationale string deterministically."""

    return f"{value:.6f}"


__all__ = [
    "VERDICT_PASS",
    "VERDICT_FAIL",
    "VERDICT_INCONCLUSIVE",
    "LatencyGateError",
    "GateProtocol",
    "PerReportResult",
    "GateDecision",
    "evaluate_reports",
]

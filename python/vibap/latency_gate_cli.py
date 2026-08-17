"""CLI harness for the deterministic latency gate evaluator.

This module wires the landed :mod:`vibap.latency_gate` evaluator (commit
``996abdd``, ADR-027) into a usable tool: it loads multiple
``ardur.latency_report.v1.0`` JSON reports from a directory, runs the
deterministic gate, and emits a machine-readable decision.

Design invariants
-----------------

1.  **Read-only over the report directory.** The loader never writes,
    creates, or mutates anything on disk; it only opens ``*.json`` files
    for reading.
2.  **One bad file does not poison the run.** Unreadable, unparseable, or
    wrong-shape files are recorded in ``invalid_reports`` with their
    filename and a stable reason; the gate evaluator then decides whether
    the surviving valid reports are enough.
3.  **No secrets or private paths in output.** Filenames are surfaced
    verbatim (the caller chose them), but file contents are only ever
    forwarded to the evaluator, which never echoes raw report bodies. The
    loader never reads, logs, or serializes values from inside reports.
4.  **Deterministic ordering.** Files are sorted by filename so repeated
    runs over the same directory produce byte-identical input lists.
5.  **Thin wrapper.** :func:`run_gate` does not re-implement the evaluator;
    it builds a :class:`GateProtocol` from CLI-shaped arguments and delegates
    to :func:`evaluate_reports`.

See ``docs/decisions/ADR-027-latency-benchmark-gate-evaluator.md`` for the
statistical model and decision-rule order this CLI surfaces.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .latency_gate import (
    GateDecision,
    GateProtocol,
    evaluate_reports,
)


class LatencyGateCliError(ValueError):
    """Raised by the loader/harness for CLI-level failures.

    A ``ValueError`` subclass for generic-handler compatibility, kept
    distinct from :class:`LatencyGateError` (which covers protocol/report
    validation inside the evaluator) and :class:`LatencyReportError` (which
    covers report *emission*). The CLI handler formats a stable
    ``condition`` field from the message.
    """


def load_reports_from_directory(
    report_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load every ``*.json`` file in ``report_dir`` as a candidate report.

    Each file is read, parsed as JSON, and classified:

    * **Valid:** a JSON object that the gate evaluator can consume. The
      loader does not deeply validate the report shape (that is the
      evaluator's job); it only rejects entries that are not JSON objects
      so the evaluator sees a clean list. The original filename is
      preserved under the ``_source_file`` key for provenance.
    * **Invalid:** files that could not be read, could not be parsed as
      JSON, or whose top-level JSON value is not an object. Each invalid
      entry records ``filename`` and a stable ``reason``.

    Files are processed in sorted filename order so the returned lists are
    deterministic across runs over the same directory.

    Parameters
    ----------
    report_dir:
        Directory to scan. Must exist and be a directory; a
        :class:`LatencyGateCliError` is raised otherwise. The caller is
        expected to have already validated non-empty/non-whitespace path
        strings before constructing the :class:`Path`.

    Returns
    -------
    tuple[list[dict], list[dict]]
        ``(valid_reports, invalid_reports)``. ``valid_reports`` is the list
        to feed to :func:`evaluate_reports`. ``invalid_reports`` is metadata
        about rejected files (never contains file contents).
    """

    if not isinstance(report_dir, Path):
        raise LatencyGateCliError("report_dir must be a pathlib.Path")
    if not report_dir.exists():
        raise LatencyGateCliError(
            f"reports directory does not exist: {report_dir}"
        )
    if not report_dir.is_dir():
        raise LatencyGateCliError(
            f"reports path is not a directory: {report_dir}"
        )

    valid: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []

    # Sorted for determinism: repeated runs over the same directory must
    # produce byte-identical input lists. ``glob`` order is filesystem-
    # dependent and must not be trusted.
    json_files = sorted(report_dir.glob("*.json"))
    for file_path in json_files:
        parsed = _read_json_file(file_path, invalid)
        if parsed is None:
            continue
        if not isinstance(parsed, dict):
            invalid.append(
                {
                    "filename": file_path.name,
                    "reason": f"non_object_json:{type(parsed).__name__}",
                }
            )
            continue
        # Mark provenance without copying the whole dict. The evaluator
        # ignores unknown keys, and this field never carries content.
        parsed["_source_file"] = file_path.name
        valid.append(parsed)

    return valid, invalid


def _read_json_file(
    file_path: Path,
    invalid: list[dict[str, Any]],
) -> Any:
    """Read and parse one JSON file, recording failures into ``invalid``.

    Returns the parsed value on success, or ``None`` on any read/parse
    failure (the failure is appended to ``invalid`` by this function).
    Kept as a helper so the main loader loop stays flat and testable.
    """

    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        invalid.append(
            {
                "filename": file_path.name,
                "reason": f"unreadable:{exc.__class__.__name__}",
            }
        )
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        invalid.append(
            {
                "filename": file_path.name,
                "reason": f"invalid_json:line_{exc.lineno}_col_{exc.colno}",
            }
        )
        return None


def run_gate(
    reports: list[dict[str, Any]],
    protocol: GateProtocol,
) -> GateDecision:
    """Run :func:`evaluate_reports` with ``protocol`` over ``reports``.

    Thin wrapper that exists so the CLI handler can keep protocol
    construction (from string args) separate from evaluation. ``reports``
    is the output of :func:`load_reports_from_directory`'s first return
    value (valid reports only).

    Parameters
    ----------
    reports:
        List of report dicts. May be empty; the evaluator returns
        ``INCONCLUSIVE`` for empty input.
    protocol:
        A constructed :class:`GateProtocol`. Validated at construction and
        re-validated defensively inside the evaluator.

    Returns
    -------
    GateDecision
        Always. Raises only on protocol-validation failures (which surface
        at :class:`GateProtocol` construction).
    """

    if not isinstance(protocol, GateProtocol):
        raise LatencyGateCliError("protocol must be a GateProtocol instance")
    return evaluate_reports(reports, protocol)


def format_gate_output(
    decision: GateDecision,
    output_format: str,
) -> str:
    """Render ``decision`` as JSON or human-readable text.

    The JSON form is canonical (sorted keys, no whitespace-inside-objects)
    so CI can diff it deterministically. The text form is a compact
    multi-line summary suitable for a CI job log.

    Neither form ever includes raw report contents; only the evaluator's
    derived fields (verdict, counts, per-report p95s, rationale) appear.

    Parameters
    ----------
    decision:
        A :class:`GateDecision` from :func:`run_gate` /
        :func:`evaluate_reports`.
    output_format:
        ``"json"`` or ``"text"``. Any other value raises
        :class:`LatencyGateCliError`.

    Returns
    -------
    str
        The rendered output, with a trailing newline.
    """

    if output_format == "json":
        payload = _decision_to_dict(decision)
        return json.dumps(payload, sort_keys=True) + "\n"
    if output_format == "text":
        return _decision_to_text(decision)
    raise LatencyGateCliError(
        f"output_format must be 'json' or 'text', got {output_format!r}"
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decision_to_dict(decision: GateDecision) -> dict[str, Any]:
    """Convert a :class:`GateDecision` to a JSON-serializable dict.

    Drops the nested ``protocol`` dataclass (replaced by a flat
    ``protocol`` dict) and the ``per_report_results`` dataclasses (replaced
    by plain dicts) so the output is pure JSON.
    """

    return {
        "verdict": decision.verdict,
        "aggregate_p95_ms": decision.aggregate_p95_ms,
        "valid_report_count": decision.valid_report_count,
        "missing_report_count": decision.missing_report_count,
        "invalid_report_count": decision.invalid_report_count,
        "over_threshold_count": decision.over_threshold_count,
        "functional_failures_present": decision.functional_failures_present,
        "rationale": decision.rationale,
        "protocol": asdict(decision.protocol),
        "per_report_results": [asdict(r) for r in decision.per_report_results],
        "invalid_reports": list(decision.invalid_reports),
        "missing_reports": list(decision.missing_reports),
    }


def _decision_to_text(decision: GateDecision) -> str:
    """Render a compact human-readable summary of the decision."""

    lines = [
        f"Ardur latency gate: {decision.verdict.upper()}",
        f"  valid reports:      {decision.valid_report_count}",
        f"  missing reports:    {decision.missing_report_count}",
        f"  invalid reports:    {decision.invalid_report_count}",
        f"  over threshold:     {decision.over_threshold_count}",
        f"  aggregate p95 (ms): {_fmt_ms(decision.aggregate_p95_ms)}",
        f"  threshold (ms):     {_fmt_ms(decision.protocol.threshold_ms)}",
        f"  percentile:         {decision.protocol.percentile}",
        (
            f"  functional failures:{' yes' if decision.functional_failures_present else ' no'}"
        ),
        f"  rationale:          {decision.rationale}",
    ]
    return "\n".join(lines) + "\n"


def _fmt_ms(value: float | None) -> str:
    """Format a millisecond value for text output."""

    if value is None:
        return "n/a"
    return f"{value:.6f}"


__all__ = [
    "LatencyGateCliError",
    "load_reports_from_directory",
    "run_gate",
    "format_gate_output",
]

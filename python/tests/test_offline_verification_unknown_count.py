"""Regression tests for ``unknown`` verdict counting and reason_code in offline verification.

The ``unknown`` verdict was added for honest observation-gap abstention.
While ``_verdict_label`` was patched to include ``unknown``, the *summary*
counters and the ``reason_code`` fallback in offline verification still
omitted it:

* ``unknown_count`` was missing from the summary dict entirely (silent
  miscount — unknown receipts were invisible in aggregate).
* ``reason_code`` fell through to ``"insufficient_evidence"`` for unknown
  and violation verdicts, mislabeling observation gaps as transient
  operational failures.

These tests guard against both regressions.
"""

from __future__ import annotations

from vibap.offline_verification import _default_reason_code


def test_default_reason_code_compliant() -> None:
    assert _default_reason_code("compliant") == "policy_permit"


def test_default_reason_code_unknown() -> None:
    """Unknown verdict must not be labeled as insufficient_evidence."""
    assert _default_reason_code("unknown") == "observation_gap"


def test_default_reason_code_violation() -> None:
    """Violation verdict must not be labeled as insufficient_evidence."""
    assert _default_reason_code("violation") == "policy_denied"


def test_default_reason_code_insufficient_evidence() -> None:
    assert _default_reason_code("insufficient_evidence") == "insufficient_evidence"


def test_default_reason_code_unknown_not_insufficient() -> None:
    """The whole point of the fix: unknown ≠ insufficient_evidence."""
    assert _default_reason_code("unknown") != "insufficient_evidence"

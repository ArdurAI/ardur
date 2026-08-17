"""Regression tests for ``unknown`` verdict handling in offline verification.

The ``unknown`` verdict was added for honest observation-gap abstention but
was missing from ``_verdict_label``, causing a ``KeyError`` that crashed the
entire offline verification pipeline whenever a receipt chain contained an
``unknown`` verdict.  These tests guard against that regression.
"""

from __future__ import annotations

from vibap.offline_verification import _verdict_label


def test_verdict_label_unknown() -> None:
    """``unknown`` must map to ``UNKNOWN`` not crash with KeyError."""
    assert _verdict_label("unknown") == "UNKNOWN"


def test_verdict_label_all_five_verdicts() -> None:
    """Every verdict in the receipt codomain must have a decision label."""
    expected = {
        "compliant": "PERMIT",
        "violation": "DENY",
        "insufficient_evidence": "ERROR",
        "unknown": "UNKNOWN",
    }
    for verdict, decision in expected.items():
        assert _verdict_label(verdict) == decision


def test_verdict_label_unknown_not_permit() -> None:
    """UNKNOWN must not be PERMIT — callers must treat it as fail-closed."""
    assert _verdict_label("unknown") != "PERMIT"

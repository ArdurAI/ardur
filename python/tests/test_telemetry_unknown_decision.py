"""Regression tests for ``UNKNOWN`` decision in telemetry export.

The ``UNKNOWN`` decision (mapped from the ``unknown`` verdict) was missing
from the OTel severity mapping in ``receipt_telemetry.py``, which would crash
telemetry export with ``KeyError`` for any receipt chain containing an
``unknown`` verdict.  These tests guard against that regression.
"""

from __future__ import annotations

from typing import Any, Mapping

from vibap.receipt_telemetry import _budget_decision


def test_budget_decision_unknown_is_not_allowed() -> None:
    """UNKNOWN must not be treated as budget-allowed (fail-closed)."""
    item: Mapping[str, Any] = {
        "decision": "UNKNOWN",
        "reason_code": "observation_gap",
    }
    assert _budget_decision(item) == "not_applicable"


def test_budget_decision_permit_remains_allowed() -> None:
    item: Mapping[str, Any] = {
        "decision": "PERMIT",
        "reason_code": "policy_permit",
    }
    assert _budget_decision(item) == "allowed"


def test_budget_decision_deny_remains_not_applicable() -> None:
    item: Mapping[str, Any] = {
        "decision": "DENY",
        "reason_code": "policy_deny",
    }
    assert _budget_decision(item) == "not_applicable"

"""Tests for the `unknown` verdict as a first-class receipt outcome."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import Mock

import jsonschema

from vibap.proxy import PolicyEvent
from vibap.receipt import (
    _DENIAL_REASONS,
    _VERDICTS,
    _public_denial_reason,
    _verdict_from_decision,
    build_receipt,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# _VERDICTS
# ---------------------------------------------------------------------------
def test_verdicts_includes_unknown() -> None:
    assert "unknown" in _VERDICTS


# ---------------------------------------------------------------------------
# _DENIAL_REASONS
# ---------------------------------------------------------------------------
def test_denial_reasons_includes_unknown() -> None:
    assert "unknown" in _DENIAL_REASONS


# ---------------------------------------------------------------------------
# _verdict_from_decision
# ---------------------------------------------------------------------------
def test_verdict_from_decision_unknown() -> None:
    decision = Mock()
    decision.value = "UNKNOWN"
    assert _verdict_from_decision(decision) == "unknown"


def test_verdict_from_decision_permit() -> None:
    decision = Mock()
    decision.value = "PERMIT"
    assert _verdict_from_decision(decision) == "compliant"


def test_verdict_from_decision_deny() -> None:
    decision = Mock()
    decision.value = "DENY"
    assert _verdict_from_decision(decision) == "violation"


def test_verdict_from_decision_insufficient_evidence() -> None:
    decision = Mock()
    decision.value = "INSUFFICIENT_EVIDENCE"
    assert _verdict_from_decision(decision) == "insufficient_evidence"


def test_verdict_from_decision_violation() -> None:
    decision = Mock()
    decision.value = "VIOLATION"
    assert _verdict_from_decision(decision) == "violation"


# ---------------------------------------------------------------------------
# _public_denial_reason
# ---------------------------------------------------------------------------
def test_public_denial_reason_unknown_no_code() -> None:
    assert _public_denial_reason("unknown", None) == "unknown"


def test_public_denial_reason_unknown_with_code() -> None:
    """Verdict takes priority over internal denial code."""
    assert _public_denial_reason("unknown", "some_code") == "unknown"


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------
def _unknown_decision():
    """Mock decision with .value = 'UNKNOWN' (Decision enum not yet extended)."""
    decision = Mock()
    decision.value = "UNKNOWN"
    return decision


def _event_for_unknown() -> PolicyEvent:
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return PolicyEvent(
        timestamp=timestamp,
        step_id="step-unknown-1",
        actor="spiffe://example.test/agent",
        verifier_id="vibap-governance-proxy",
        tool_name="bash",
        arguments={"command": "echo hello"},
        action_class="write",
        target="bash",
        resource_family="process",
        side_effect_class="process_launch",
        decision=_unknown_decision(),
        reason="Tool call observed but evidence is structurally absent (observation gap).",
        passport_jti="grant-unknown-1",
        trace_id="trace-unknown-1",
        run_nonce="fixture-run-nonce-unknown",
    )


def test_receipt_with_unknown_verdict_passes_schema_validation() -> None:
    """A receipt carrying verdict 'unknown' must validate against the v0.2 schema."""
    receipt = build_receipt(_unknown_decision(), _event_for_unknown())
    claims = receipt.to_dict()

    assert claims["verdict"] == "unknown"
    assert claims["public_denial_reason"] == "unknown"

    schema_path = (
        REPO_ROOT / "python/vibap/_specs/execution_receipt_v02.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(claims)


# ---------------------------------------------------------------------------
# Schema enum check
# ---------------------------------------------------------------------------
def test_execution_receipt_v02_schema_verdict_enum_includes_unknown() -> None:
    schema_path = (
        REPO_ROOT / "python/vibap/_specs/execution_receipt_v02.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    verdict_enum = schema["properties"]["verdict"]["enum"]
    assert "unknown" in verdict_enum

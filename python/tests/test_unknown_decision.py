"""Tests for the UNKNOWN Decision enum value and observation-gap wiring.

The UNKNOWN decision represents a genuine observation gap where the verifier
observed the call but the evidence is structurally outside the capture
boundary. It is distinct from INSUFFICIENT_EVIDENCE (transient operational
failure) and maps to the same ``unknown`` receipt verdict introduced in the
prior landing (commit 42cf640). These tests verify the proxy-level enum,
the denial-reason mapping, the visibility-insufficient code path, and the
fixture-module ``_status_from_verdict`` handling.
"""

from __future__ import annotations

from vibap.denial import DenialReason
from vibap.proxy import Decision, _legacy_denial_reason


# ---------------------------------------------------------------------------
# Decision enum
# ---------------------------------------------------------------------------
def test_decision_enum_has_unknown() -> None:
    assert hasattr(Decision, "UNKNOWN")
    assert Decision.UNKNOWN.value == "UNKNOWN"


def test_decision_enum_has_five_members() -> None:
    members = {d.value for d in Decision}
    assert members == {
        "PERMIT",
        "DENY",
        "VIOLATION",
        "INSUFFICIENT_EVIDENCE",
        "UNKNOWN",
    }


def test_decision_unknown_is_blocking() -> None:
    """UNKNOWN must NOT be PERMIT — callers must treat it as fail-closed."""
    assert Decision.UNKNOWN != Decision.PERMIT


def test_decision_unknown_is_not_insufficient_evidence() -> None:
    """The whole point: UNKNOWN is distinct from INSUFFICIENT_EVIDENCE."""
    assert Decision.UNKNOWN != Decision.INSUFFICIENT_EVIDENCE


# ---------------------------------------------------------------------------
# DenialReason enum
# ---------------------------------------------------------------------------
def test_denial_reason_has_observation_gap() -> None:
    assert hasattr(DenialReason, "OBSERVATION_GAP")
    assert DenialReason.OBSERVATION_GAP.value == "observation_gap"


# ---------------------------------------------------------------------------
# _legacy_denial_reason mapping
# ---------------------------------------------------------------------------
def test_legacy_denial_reason_unknown_returns_observation_gap() -> None:
    result = _legacy_denial_reason(Decision.UNKNOWN, "visibility_insufficient:partial")
    assert result == DenialReason.OBSERVATION_GAP


def test_legacy_denial_reason_insufficient_evidence_still_telemetry_missing() -> None:
    result = _legacy_denial_reason(
        Decision.INSUFFICIENT_EVIDENCE, "state_file_corrupted"
    )
    assert result == DenialReason.TELEMETRY_MISSING


# ---------------------------------------------------------------------------
# Fixture-module _status_from_verdict
# ---------------------------------------------------------------------------
def test_status_from_verdict_unknown_codex() -> None:
    from vibap.codex_app_server_fixture import _status_from_verdict

    assert _status_from_verdict("unknown") == "unknown"
    assert _status_from_verdict("compliant") == "allow"
    assert _status_from_verdict("violation") == "deny"
    assert _status_from_verdict("insufficient_evidence") == "unknown"


def test_status_from_verdict_unknown_gemini() -> None:
    from vibap.gemini_cli_hook import _status_from_verdict

    assert _status_from_verdict("unknown") == "unknown"
    assert _status_from_verdict("compliant") == "allow"
    assert _status_from_verdict("violation") == "deny"
    assert _status_from_verdict("insufficient_evidence") == "unknown"


def test_status_from_verdict_unknown_provider_adapter() -> None:
    from vibap.provider_adapter_fixture import _status_from_verdict

    assert _status_from_verdict("unknown") == "unknown"
    assert _status_from_verdict("compliant") == "allow"
    assert _status_from_verdict("violation") == "deny"
    assert _status_from_verdict("insufficient_evidence") == "unknown"

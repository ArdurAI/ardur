"""Tests for verdict breakdown in the signed attestation JWT.

The signed attestation token historically carried only ``permits`` and
``denials``. The aggregate verdict breakdown (``unknowns``,
``insufficient_evidence``, ``violations``, ``denied_tools``) existed only
in the unsigned summary dict — so an auditor verifying only the signed JWT
could not see *why* a session was non-compliant, or which tools were
blocked. These tests verify the verdict breakdown is now signed into the
JWT itself via ``extra_claims`` so it is independently verifiable from the
token alone.
"""

from __future__ import annotations

from vibap.attestation import issue_attestation, verify_attestation


def test_verdict_breakdown_in_attestation(private_key, public_key):
    """Verdict breakdown fields must appear in the signed JWT claims."""
    token = issue_attestation(
        passport_jti="j",
        agent_id="a",
        mission="m",
        events=[],
        permits=2,
        denials=3,
        elapsed_s=1.0,
        private_key=private_key,
        extra_claims={
            "unknowns": 1,
            "insufficient_evidence": 1,
            "violations": 1,
            "denied_tools": ["write_file", "delete_file"],
        },
    )
    claims = verify_attestation(token, public_key)
    assert claims["unknowns"] == 1
    assert claims["insufficient_evidence"] == 1
    assert claims["violations"] == 1
    assert claims["denied_tools"] == ["write_file", "delete_file"]


def test_verdict_breakdown_defaults_omitted(private_key, public_key):
    """When no extra_claims are passed, verdict fields are absent (back-compat)."""
    token = issue_attestation(
        passport_jti="j",
        agent_id="a",
        mission="m",
        events=[],
        permits=1,
        denials=0,
        elapsed_s=1.0,
        private_key=private_key,
    )
    claims = verify_attestation(token, public_key)
    # These fields must NOT appear when not provided — backward compatible.
    assert "unknowns" not in claims
    assert "insufficient_evidence" not in claims
    assert "violations" not in claims
    assert "denied_tools" not in claims


def test_verdict_breakdown_empty_denied_tools(private_key, public_key):
    """An empty denied_tools list should be present when explicitly passed."""
    token = issue_attestation(
        passport_jti="j",
        agent_id="a",
        mission="m",
        events=[],
        permits=1,
        denials=0,
        elapsed_s=1.0,
        private_key=private_key,
        extra_claims={
            "unknowns": 0,
            "insufficient_evidence": 0,
            "violations": 0,
            "denied_tools": [],
        },
    )
    claims = verify_attestation(token, public_key)
    assert claims["unknowns"] == 0
    assert claims["insufficient_evidence"] == 0
    assert claims["violations"] == 0
    assert claims["denied_tools"] == []

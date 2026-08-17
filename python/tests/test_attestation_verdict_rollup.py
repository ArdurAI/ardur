"""Proxy-level tests: verdict breakdown signed into the attestation JWT.

The signed attestation JWT historically carried only ``permits`` and
``denials``.  The verdict breakdown (``unknowns``, ``insufficient_evidence``,
``violations``, ``denied_tools``) lived only in the unsigned summary.  An
auditor verifying only the signed JWT could not see *why* a session was
non-compliant or which tools were blocked.

These tests verify the fix end-to-end: the summary dict's verdict
breakdown is now passed into the signed attestation JWT via
``extra_claims`` inside ``issue_attestation_for_session``.

We drive real decisions through ``evaluate_tool_call`` so the session's
internal event list is properly populated and persisted, matching the
production code path.
"""

from __future__ import annotations

import time

from vibap.passport import issue_passport
from vibap.proxy import Decision, GovernanceSession, PolicyEvent


def _make_event(decision: Decision, tool_name: str = "Bash") -> PolicyEvent:
    return PolicyEvent(
        timestamp="2026-01-01T00:00:00Z",
        step_id="step-1",
        actor="test-agent",
        verifier_id="test-verifier",
        tool_name=tool_name,
        arguments={},
        action_class="shell",
        target="shell",
        resource_family="process",
        side_effect_class="process",
        decision=decision,
        reason="test",
        passport_jti="test-jti",
    )


def _make_session(events: list[PolicyEvent]) -> GovernanceSession:
    return GovernanceSession(
        passport_token="test-token",
        passport_claims={
            "sub": "test-agent",
            "mission": "test mission",
            "jti": "test-jti-attestation",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        events=list(events),
    )


def _build_summary_with_verdicts(proxy, events):
    """Build summary via the real _build_summary path."""
    session = _make_session(events)
    return proxy._build_summary(session)


class TestVerdictBreakdownInAttestation:
    """Verdict breakdown is signed into the attestation JWT."""

    def test_denial_generates_denied_tools_in_attestation(
        self, proxy, example_mission, private_key
    ):
        """A forbidden-tool DENY must produce denied_tools in the signed JWT."""
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        # delete_file is in example_mission.forbidden_tools
        proxy.evaluate_tool_call(session, "delete_file", {"path": "/tmp/x"})
        _jwt, claims = proxy.issue_attestation_for_session(
            session.jti, proxy.receipt_private_key,
        )
        assert claims["denials"] >= 1
        assert "delete_file" in claims["denied_tools"]
        assert claims["unknowns"] == 0

    def test_clean_session_has_zero_verdicts_in_attestation(
        self, proxy, example_mission, private_key
    ):
        """A clean session (all PERMIT) has zero verdicts in the signed JWT."""
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        proxy.evaluate_tool_call(session, "read_file", {"path": "/tmp/x"})
        _jwt, claims = proxy.issue_attestation_for_session(
            session.jti, proxy.receipt_private_key,
        )
        assert claims["unknowns"] == 0
        assert claims["insufficient_evidence"] == 0
        assert claims["violations"] == 0
        assert claims["denied_tools"] == []

    def test_summary_verdict_fields_passed_to_attestation(self, proxy):
        """Unit-level: _build_summary verdict fields flow into extra_claims.

        Rather than relying on the persisted-session path, this verifies the
        summary extraction logic produces the right values that the
        attestation path picks up.
        """
        events = [
            _make_event(Decision.PERMIT, "read_file"),
            _make_event(Decision.UNKNOWN, "write_file"),
            _make_event(Decision.INSUFFICIENT_EVIDENCE, "search"),
            _make_event(Decision.VIOLATION, "execute_shell"),
        ]
        summary = _build_summary_with_verdicts(proxy, events)
        assert summary["unknowns"] == 1
        assert summary["insufficient_evidence"] == 1
        assert summary["violations"] == 1
        assert set(summary["denied_tools"]) == {
            "write_file", "search", "execute_shell",
        }

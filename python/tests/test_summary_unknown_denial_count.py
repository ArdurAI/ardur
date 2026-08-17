"""Tests that _build_summary counts Decision.UNKNOWN as a denial.

When the ``UNKNOWN`` Decision was added to the five-state taxonomy
(commit 3f452a0), the ``_build_summary`` method in ``proxy.py`` was not
updated — its denials tuple only covered ``DENY``, ``INSUFFICIENT_EVIDENCE``,
and ``VIOLATION``.  An ``UNKNOWN`` event would silently pass uncounted,
understating the aggregate denial count and incorrectly reporting
``scope_compliance: full``.

These tests prove the fix: ``UNKNOWN`` is now included in the denials
tuple and is also broken out as a separate ``unknowns`` field for audit
clarity.
"""

from __future__ import annotations

import time

from vibap.proxy import (
    Decision,
    GovernanceProxy,
    GovernanceSession,
    PolicyEvent,
)


def _make_event(decision: Decision) -> PolicyEvent:
    """Create a minimal policy event with the given decision."""
    return PolicyEvent(
        timestamp="2026-01-01T00:00:00Z",
        step_id="step-1",
        actor="test-agent",
        verifier_id="test-verifier",
        tool_name="Bash",
        arguments={"command": "echo test"},
        action_class="shell",
        target="shell",
        resource_family="process",
        side_effect_class="process",
        decision=decision,
        reason="test",
        passport_jti="test-jti",
    )


def _make_session(events: list[PolicyEvent]) -> GovernanceSession:
    """Build a minimal session with the given events for summary tests."""
    return GovernanceSession(
        passport_token="test-token",
        passport_claims={
            "sub": "test-agent",
            "mission": "test mission",
            "jti": "test-jti-summary",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        events=list(events),
    )


class TestSummaryCountsUnknownAsDenial:
    """Regression tests for _build_summary counting UNKNOWN as a denial."""

    def test_unknown_counted_in_denials(self) -> None:
        """A single UNKNOWN event must appear in the denials count."""
        proxy = GovernanceProxy.__new__(GovernanceProxy)
        session = _make_session([_make_event(Decision.UNKNOWN)])
        summary = proxy._build_summary(session)
        assert summary["denials"] == 1
        assert summary["unknowns"] == 1
        assert summary["scope_compliance"] == "violated"

    def test_unknown_does_not_silently_pass(self) -> None:
        """Before the fix, UNKNOWN events were not counted at all.

        Verify total_events == denials when all events are non-PERMIT.
        """
        proxy = GovernanceProxy.__new__(GovernanceProxy)
        events = [
            _make_event(Decision.UNKNOWN),
            _make_event(Decision.INSUFFICIENT_EVIDENCE),
            _make_event(Decision.DENY),
            _make_event(Decision.VIOLATION),
        ]
        session = _make_session(events)
        summary = proxy._build_summary(session)
        assert summary["total_events"] == 4
        assert summary["permits"] == 0
        assert summary["denials"] == 4
        assert summary["unknowns"] == 1
        assert summary["insufficient_evidence"] == 1
        assert summary["scope_compliance"] == "violated"

    def test_mixed_permit_and_unknown(self) -> None:
        """A session with PERMIT + UNKNOWN should have 1 denial."""
        proxy = GovernanceProxy.__new__(GovernanceProxy)
        events = [
            _make_event(Decision.PERMIT),
            _make_event(Decision.UNKNOWN),
        ]
        session = _make_session(events)
        summary = proxy._build_summary(session)
        assert summary["permits"] == 1
        assert summary["denials"] == 1
        assert summary["unknowns"] == 1
        assert summary["scope_compliance"] == "violated"

    def test_all_permit_has_zero_unknowns(self) -> None:
        """A clean session has zero unknowns and full compliance."""
        proxy = GovernanceProxy.__new__(GovernanceProxy)
        events = [_make_event(Decision.PERMIT), _make_event(Decision.PERMIT)]
        session = _make_session(events)
        summary = proxy._build_summary(session)
        assert summary["permits"] == 2
        assert summary["denials"] == 0
        assert summary["unknowns"] == 0
        assert summary["insufficient_evidence"] == 0
        assert summary["scope_compliance"] == "full"

    def test_insufficient_evidence_broken_out(self) -> None:
        """INSUFFICIENT_EVIDENCE is counted in denials AND broken out separately."""
        proxy = GovernanceProxy.__new__(GovernanceProxy)
        events = [_make_event(Decision.INSUFFICIENT_EVIDENCE)]
        session = _make_session(events)
        summary = proxy._build_summary(session)
        assert summary["denials"] == 1
        assert summary["insufficient_evidence"] == 1
        assert summary["unknowns"] == 0

    def test_summary_keys_include_new_fields(self) -> None:
        """The summary dict includes 'unknowns' and 'insufficient_evidence' keys."""
        proxy = GovernanceProxy.__new__(GovernanceProxy)
        session = _make_session([_make_event(Decision.PERMIT)])
        summary = proxy._build_summary(session)
        assert "unknowns" in summary
        assert "insufficient_evidence" in summary

"""Regression tests for child-lifecycle summary verdict propagation.

The ``_child_lifecycle_summary`` method in ``proxy.py`` builds an audit
summary for a delegated child session.  Prior to this fix it propagated
``permits`` and ``denials`` from the child session's ``_build_summary``
output but **dropped** ``unknowns`` and ``insufficient_evidence`` counts.

After the fix, all four verdict counts are present in the child-lifecycle
summary so audit rollups cannot silently lose UNKNOWN / INSUFFICIENT_EVIDENCE
decisions from delegated subagents.
"""

from __future__ import annotations

from typing import Any

from vibap.proxy import (
    Decision,
    GovernanceProxy,
    GovernanceSession,
    PolicyEvent,
)


def _make_event(decision: Decision, step_id: str = "step-1") -> PolicyEvent:
    """Build a minimal PolicyEvent with the given decision."""
    return PolicyEvent(
        timestamp="2026-08-07T00:00:00Z",
        step_id=step_id,
        actor="child-agent",
        verifier_id="test-verifier",
        tool_name="Bash",
        arguments={},
        action_class="exec",
        target="target",
        resource_family="shell",
        side_effect_class="process",
        decision=decision,
        reason="test",
        passport_jti="child-jti-1",
    )


def _make_child_session(
    events: list[PolicyEvent],
    summary: dict[str, Any] | None = None,
) -> GovernanceSession:
    """Build a minimal child GovernanceSession."""
    return GovernanceSession(
        passport_token="child-token",
        passport_claims={
            "jti": "child-jti-1",
            "sub": "child-agent",
            "mission": "child mission",
        },
        events=events,
        summary=summary,
    )


class TestChildLifecycleSummaryVerdictPropagation:
    """``_child_lifecycle_summary`` must include unknowns + insufficient_evidence."""

    def test_unknown_count_propagated(self, tmp_path):
        """A child session with an UNKNOWN decision must report unknowns=1."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        child_events = [
            _make_event(Decision.PERMIT, "s1"),
            _make_event(Decision.UNKNOWN, "s2"),
        ]
        child_session = _make_child_session(child_events, summary=None)
        proxy.sessions["child-jti-1"] = child_session

        record = {
            "child_jti": "child-jti-1",
            "parent_jti": "parent-jti",
            "child_agent_id": "child-agent",
            "child_mission": "child mission",
            "child_allowed_tools": ["Bash"],
            "child_tool_scope_mode": "allowlist",
            "child_forbidden_tools": [],
            "child_max_tool_calls": 10,
            "delegated_budget_reserved": 0,
        }
        result = proxy._child_lifecycle_summary(record)
        assert result["unknowns"] == 1, f"Expected unknowns=1, got {result.get('unknowns')}"
        assert result["permits"] == 1
        assert result["denials"] == 1  # UNKNOWN counts as denial (fail-closed)

    def test_insufficient_evidence_count_propagated(self, tmp_path):
        """A child session with INSUFFICIENT_EVIDENCE must report it."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        child_events = [
            _make_event(Decision.PERMIT, "s1"),
            _make_event(Decision.INSUFFICIENT_EVIDENCE, "s2"),
            _make_event(Decision.INSUFFICIENT_EVIDENCE, "s3"),
        ]
        child_session = _make_child_session(child_events, summary=None)
        proxy.sessions["child-jti-1"] = child_session

        record = {
            "child_jti": "child-jti-1",
            "parent_jti": "parent-jti",
            "child_agent_id": "child-agent",
            "child_mission": "child mission",
            "child_allowed_tools": ["Bash"],
            "child_tool_scope_mode": "allowlist",
            "child_forbidden_tools": [],
            "child_max_tool_calls": 10,
            "delegated_budget_reserved": 0,
        }
        result = proxy._child_lifecycle_summary(record)
        assert result["insufficient_evidence"] == 2, (
            f"Expected insufficient_evidence=2, got {result.get('insufficient_evidence')}"
        )
        assert result["unknowns"] == 0

    def test_both_unknown_and_insufficient_propagated(self, tmp_path):
        """Mixed verdicts are all propagated."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        child_events = [
            _make_event(Decision.PERMIT, "s1"),
            _make_event(Decision.DENY, "s2"),
            _make_event(Decision.UNKNOWN, "s3"),
            _make_event(Decision.INSUFFICIENT_EVIDENCE, "s4"),
        ]
        child_session = _make_child_session(child_events, summary=None)
        proxy.sessions["child-jti-1"] = child_session

        record = {
            "child_jti": "child-jti-1",
            "parent_jti": "parent-jti",
            "child_agent_id": "child-agent",
            "child_mission": "child mission",
            "child_allowed_tools": ["Bash"],
            "child_tool_scope_mode": "allowlist",
            "child_forbidden_tools": [],
            "child_max_tool_calls": 10,
            "delegated_budget_reserved": 0,
        }
        result = proxy._child_lifecycle_summary(record)
        assert result["permits"] == 1
        assert result["denials"] == 3  # DENY + UNKNOWN + INSUFFICIENT_EVIDENCE
        assert result["unknowns"] == 1
        assert result["insufficient_evidence"] == 1

    def test_zero_unknowns_when_no_unknown_events(self, tmp_path):
        """Clean session with only PERMITs should report unknowns=0."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        child_events = [
            _make_event(Decision.PERMIT, "s1"),
            _make_event(Decision.PERMIT, "s2"),
        ]
        child_session = _make_child_session(child_events, summary=None)
        proxy.sessions["child-jti-1"] = child_session

        record = {
            "child_jti": "child-jti-1",
            "parent_jti": "parent-jti",
            "child_agent_id": "child-agent",
            "child_mission": "child mission",
            "child_allowed_tools": ["Bash"],
            "child_tool_scope_mode": "allowlist",
            "child_forbidden_tools": [],
            "child_max_tool_calls": 10,
            "delegated_budget_reserved": 0,
        }
        result = proxy._child_lifecycle_summary(record)
        assert result["unknowns"] == 0
        assert result["insufficient_evidence"] == 0
        assert result["permits"] == 2
        assert result["denials"] == 0

    def test_precomputed_summary_propagates_verdicts(self, tmp_path):
        """When child_session.summary is pre-set, its verdict counts are used."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        precomputed = {
            "type": "session_end",
            "jti": "child-jti-1",
            "agent": "child-agent",
            "mission": "child mission",
            "total_events": 5,
            "permits": 2,
            "denials": 3,
            "unknowns": 2,
            "insufficient_evidence": 1,
            "elapsed_s": 1.5,
            "scope_compliance": "violated",
            "delegation_count": 0,
            "children_spawned": 0,
            "child_jtis": [],
            "delegated_budget_reserved": 0,
        }
        child_session = _make_child_session([], summary=precomputed)
        proxy.sessions["child-jti-1"] = child_session

        record = {
            "child_jti": "child-jti-1",
            "parent_jti": "parent-jti",
            "child_agent_id": "child-agent",
            "child_mission": "child mission",
            "child_allowed_tools": ["Bash"],
            "child_tool_scope_mode": "allowlist",
            "child_forbidden_tools": [],
            "child_max_tool_calls": 10,
            "delegated_budget_reserved": 0,
        }
        result = proxy._child_lifecycle_summary(record)
        assert result["unknowns"] == 2
        assert result["insufficient_evidence"] == 1

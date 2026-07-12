"""B.10 — approval-rate governance (proxy + ApprovalRateTracker)."""

from __future__ import annotations

import pytest

from vibap.approvals import ApprovalRateTracker
from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import Decision, GovernanceProxy


class TestApprovalRateTracker:
    def test_twenty_approvals_in_five_minutes_under_cap(self) -> None:
        """20 approvals inside 5 minutes with budget 30/hour — all within budget."""
        base = 1_000_000.0
        span_s = 5 * 60
        tracker = ApprovalRateTracker(30, window_s=3600.0)
        for i in range(20):
            ts = base + (i / 19) * span_s if i else base
            assert tracker.check("operator-1", ts)
            tracker.record_approval("operator-1", ts)

    def test_thirty_first_exceeds_hourly_budget(self) -> None:
        tracker = ApprovalRateTracker(30, window_s=3600.0)
        t0 = 500_000.0
        for i in range(30):
            ts = t0 + float(i)
            assert tracker.check("op", ts)
            tracker.record_approval("op", ts)
        assert not tracker.check("op", t0 + 100.0)

    def test_window_rolls_old_approvals_do_not_count(self) -> None:
        tracker = ApprovalRateTracker(30, window_s=3600.0)
        base = 2_000_000.0
        for i in range(30):
            ts = base + float(i)
            assert tracker.check("op", ts)
            tracker.record_approval("op", ts)
        assert not tracker.check("op", base + 50.0)
        assert tracker.check("op", base + 3601.0)

    def test_exact_window_boundary_expires_oldest_approval(self) -> None:
        tracker = ApprovalRateTracker(1, window_s=3600.0)
        tracker.record_approval("op", 10_000.0)
        assert tracker.check("op", 13_600.0)

    def test_operator_counters_are_isolated(self) -> None:
        tracker = ApprovalRateTracker(1, window_s=3600.0)
        tracker.record_approval("operator-1", 10_000.0)
        assert not tracker.check("operator-1", 10_001.0)
        assert tracker.check("operator-2", 10_001.0)

    def test_invalid_max_raises(self) -> None:
        with pytest.raises(ValueError, match="max_approvals"):
            ApprovalRateTracker(0)

    def test_invalid_window_raises(self) -> None:
        with pytest.raises(ValueError, match="window_s"):
            ApprovalRateTracker(10, window_s=0.0)


class TestProxyApprovalIntegration:
    def test_proxy_thirty_one_st_approval_fatigue(
        self, tmp_path, public_key, private_key
    ) -> None:
        mission = MissionPassport(
            agent_id="agent-test",
            mission="approval fatigue demo",
            allowed_tools=["read_file"],
            forbidden_tools=[],
            resource_scope=["**"],
            max_tool_calls=200,
            max_duration_s=600,
        )
        token = issue_passport(
            mission,
            private_key,
            ttl_s=600,
            extra_claims={
                "approval_policy": {"max_approvals_per_hour_per_operator": 30},
            },
        )
        proxy = GovernanceProxy(
            log_path=tmp_path / "g.jsonl",
            state_dir=tmp_path / "state",
            public_key=public_key,
        )
        session = proxy.start_session(token)
        for _ in range(30):
            d, r = proxy.evaluate_tool_call(
                session,
                "read_file",
                {"path": "/x", "operator_id": "human-1"},
            )
            assert d == Decision.PERMIT, r
        d, r = proxy.evaluate_tool_call(
            session,
            "read_file",
            {"path": "/x", "operator_id": "human-1"},
        )
        assert d == Decision.INSUFFICIENT_EVIDENCE
        assert r == "approval_fatigue_threshold"

    def test_proxy_without_operator_id_fails_closed_when_policy_set(
        self, tmp_path, public_key, private_key
    ) -> None:
        mission = MissionPassport(
            agent_id="agent-test",
            mission="needs operator",
            allowed_tools=["read_file"],
            forbidden_tools=[],
            resource_scope=["**"],
            max_tool_calls=10,
            max_duration_s=60,
        )
        token = issue_passport(
            mission,
            private_key,
            ttl_s=60,
            extra_claims={
                "approval_policy": {"max_approvals_per_hour_per_operator": 5},
            },
        )
        proxy = GovernanceProxy(
            log_path=tmp_path / "g2.jsonl",
            state_dir=tmp_path / "state2",
            public_key=public_key,
        )
        session = proxy.start_session(token)
        d, r = proxy.evaluate_tool_call(session, "read_file", {"path": "/x"})
        assert d == Decision.INSUFFICIENT_EVIDENCE
        assert r == "approval_operator_unavailable"

    def test_proxy_missing_operator_does_not_consume_budget(
        self, tmp_path, public_key, private_key
    ) -> None:
        mission = MissionPassport(
            agent_id="agent-test",
            mission="needs operator",
            allowed_tools=["read_file"],
            forbidden_tools=[],
            resource_scope=["**"],
            max_tool_calls=10,
            max_duration_s=60,
        )
        token = issue_passport(
            mission,
            private_key,
            ttl_s=60,
            extra_claims={
                "approval_policy": {"max_approvals_per_hour_per_operator": 1},
            },
        )
        proxy = GovernanceProxy(
            log_path=tmp_path / "g3.jsonl",
            state_dir=tmp_path / "state3",
            public_key=public_key,
        )
        session = proxy.start_session(token)

        decision, reason = proxy.evaluate_tool_call(session, "read_file", {"path": "/x"})
        assert decision == Decision.INSUFFICIENT_EVIDENCE
        assert reason == "approval_operator_unavailable"

        decision, reason = proxy.evaluate_tool_call(
            session,
            "read_file",
            {"path": "/x", "operator_id": "human-1"},
        )
        assert decision == Decision.PERMIT
        assert reason == "within scope"

    def test_proxy_no_approval_policy_unchanged(
        self, proxy, example_mission, private_key
    ) -> None:
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        d, r = proxy.evaluate_tool_call(session, "read_file", {"path": "/x"})
        assert d == Decision.PERMIT
        assert r == "within scope"

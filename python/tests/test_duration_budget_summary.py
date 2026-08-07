"""Tests for duration-budget display in governance summary format_summary()."""

from dataclasses import dataclass, field
from typing import Any

from vibap.run_bridge import GovernanceRunResult, format_summary


def _make_result(**overrides: Any) -> GovernanceRunResult:
    """Build a minimal GovernanceRunResult for summary testing."""
    defaults: dict[str, Any] = dict(
        exit_code=0,
        session_id="sess-123",
        mission_id="miss-456",
        agent_id="agent-789",
        adapter="env",
        via="env",
        proxy_url="http://127.0.0.1:0",
        home="/tmp/ardur-home",
        passport_path="/tmp/passport.json",
        summary={},
        permits=0,
        denials=0,
        total_events=0,
        attestation_token="",
        attestation_digest="abc123",
        receipts_path="/tmp/receipts.jsonl",
        receipt_count=0,
        correlation={},
        kernel_policy={},
        process_lifecycle={},
        notes=[],
    )
    defaults.update(overrides)
    return GovernanceRunResult(**defaults)


class TestDurationBudgetDisplay:
    """format_summary should show duration budget usage when duration_budget_s is present."""

    def test_budget_within_range_shows_percentage(self):
        """When wall_clock < duration_budget, show 'budget Xs/Ys (Z%)'."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 15.0,
                "duration_budget_s": 300,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget 15.0s/300s (5%)" in summary

    def test_budget_near_limit_shows_high_percentage(self):
        """At 90% of budget, the percentage should reflect that."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 270.0,
                "duration_budget_s": 300,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget 270.0s/300s (90%)" in summary

    def test_budget_exceeded_shows_warning(self):
        """When wall_clock >= duration_budget, show 'budget exceeded'."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 305.0,
                "duration_budget_s": 300,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget exceeded" in summary

    def test_budget_exactly_at_limit(self):
        """When wall_clock == duration_budget exactly, treat as exceeded."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 300.0,
                "duration_budget_s": 300,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget exceeded" in summary

    def test_no_budget_no_budget_text(self):
        """When duration_budget_s is absent, no budget text appears."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 15.0,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget" not in summary.lower()

    def test_zero_budget_no_budget_text(self):
        """When duration_budget_s is 0, no budget text appears (avoid div-by-zero)."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 15.0,
                "duration_budget_s": 0,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget" not in summary.lower()

    def test_negative_budget_no_budget_text(self):
        """When duration_budget_s is negative, no budget text appears."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 15.0,
                "duration_budget_s": -1,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget" not in summary.lower()

    def test_budget_with_string_budget_ignored(self):
        """Non-numeric duration_budget_s should be ignored gracefully."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 15.0,
                "duration_budget_s": "300",
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        # String budget should not cause a crash and should not produce budget text
        assert "budget" not in summary.lower()

    def test_budget_zero_wall_clock(self):
        """A 0s wall clock with a real budget should show 0%."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 0.0,
                "duration_budget_s": 300,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget 0.0s/300s (0%)" in summary

    def test_budget_missing_wall_clock_defaults_to_zero(self):
        """Missing wall_clock_s should default to 0 without crashing."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "duration_budget_s": 300,
                "exit_code": 0,
                "capture_tier": "host-observer",
            }
        )
        summary = format_summary(result)
        assert "budget 0.0s/300s (0%)" in summary

    def test_process_line_still_shown_without_lifecycle(self):
        """When no process_lifecycle at all, process/descendants lines should be absent."""
        result = _make_result(process_lifecycle={})
        summary = format_summary(result)
        assert "process" not in summary.lower() or "tool calls" in summary

    def test_budget_shown_alongside_descendants(self):
        """Budget and descendants lines should both appear when both are present."""
        result = _make_result(
            process_lifecycle={
                "root_pid": 1234,
                "wall_clock_s": 50.0,
                "duration_budget_s": 300,
                "exit_code": 0,
                "capture_tier": "host-observer",
                "children": [
                    {"pid": 1235, "depth": 0, "parent_pid": 1234},
                    {"pid": 1236, "depth": 1, "parent_pid": 1235},
                ],
            }
        )
        summary = format_summary(result)
        assert "budget 50.0s/300s (17%)" in summary
        assert "descendants" in summary
        assert "max depth 1" in summary

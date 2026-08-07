"""Tests for descendant-process summary in format_summary output.

When ``process_lifecycle`` includes a ``children`` array (descendant
processes captured by the host-observer tier), the human-readable
``format_summary`` output should include a ``descendants`` line showing
the count and max depth, so users get immediate visibility without
parsing the JSON.

When no children are present, the line should be absent.
"""

from __future__ import annotations

from typing import Any

from vibap.run_bridge import format_summary, GovernanceRunResult


def _make_result(
    *,
    process_lifecycle: dict[str, Any] | None = None,
) -> GovernanceRunResult:
    """Build a minimal GovernanceRunResult for summary testing."""
    return GovernanceRunResult(
        session_id="test-session",
        mission_id="test-mission",
        agent_id="test-agent",
        adapter="env",
        via="env",
        proxy_url="http://127.0.0.1:0",
        home="/tmp/test-home",
        passport_path="/tmp/test-passport.json",
        summary={},
        exit_code=0,
        total_events=0,
        permits=0,
        denials=0,
        attestation_token="",
        receipt_count=0,
        receipts_path="/tmp/test-receipts.jsonl",
        attestation_digest="abc123",
        correlation={"reason": "no kernel daemon"},
        kernel_policy={"reason": "permissive"},
        process_lifecycle=process_lifecycle or {},
        notes=[],
    )


class TestDescendantSummaryPresent:
    """format_summary shows descendant info when children are captured."""

    def test_single_child_shows_descendants_line(self) -> None:
        pl = {
            "root_pid": 12345,
            "command": ["echo", "hello"],
            "started_at": "2026-01-01T00:00:00.000000Z",
            "wall_clock_s": 0.123,
            "exit_code": 0,
            "exit_signal": None,
            "capture_tier": "host-observer",
            "children": [
                {
                    "pid": 12346,
                    "command": ["sleep", "1"],
                    "started_at": "2026-01-01T00:00:00.100000Z",
                    "wall_clock_s": 1.0,
                    "exit_code": None,
                    "exit_signal": None,
                    "depth": 0,
                    "parent_pid": 12345,
                },
            ],
        }
        summary = format_summary(_make_result(process_lifecycle=pl))
        assert "descendants" in summary
        assert "1 captured" in summary
        assert "max depth 0" in summary

    def test_multiple_children_with_depth(self) -> None:
        pl = {
            "root_pid": 100,
            "command": ["bash", "script.sh"],
            "started_at": "2026-01-01T00:00:00.000000Z",
            "wall_clock_s": 2.5,
            "exit_code": 0,
            "exit_signal": None,
            "capture_tier": "host-observer",
            "children": [
                {
                    "pid": 101,
                    "command": ["python", "worker.py"],
                    "started_at": "2026-01-01T00:00:00.100000Z",
                    "wall_clock_s": 2.4,
                    "exit_code": 0,
                    "exit_signal": None,
                    "depth": 0,
                    "parent_pid": 100,
                },
                {
                    "pid": 102,
                    "command": ["node", "helper.js"],
                    "started_at": "2026-01-01T00:00:00.200000Z",
                    "wall_clock_s": 1.0,
                    "exit_code": 0,
                    "exit_signal": None,
                    "depth": 1,
                    "parent_pid": 101,
                },
                {
                    "pid": 103,
                    "command": ["grep", "pattern"],
                    "started_at": "2026-01-01T00:00:00.300000Z",
                    "wall_clock_s": 0.5,
                    "exit_code": 0,
                    "exit_signal": None,
                    "depth": 2,
                    "parent_pid": 102,
                },
            ],
        }
        summary = format_summary(_make_result(process_lifecycle=pl))
        assert "descendants" in summary
        assert "3 captured" in summary
        assert "max depth 2" in summary

    def test_deep_tree_shows_correct_max_depth(self) -> None:
        pl = {
            "root_pid": 1,
            "command": ["test"],
            "started_at": "2026-01-01T00:00:00.000000Z",
            "wall_clock_s": 0.1,
            "exit_code": 0,
            "exit_signal": None,
            "capture_tier": "host-observer",
            "children": [
                {
                    "pid": c,
                    "command": [f"cmd{c}"],
                    "started_at": "2026-01-01T00:00:00.000000Z",
                    "wall_clock_s": 0.01,
                    "exit_code": 0,
                    "exit_signal": None,
                    "depth": c,
                    "parent_pid": c - 1 if c > 0 else None,
                }
                for c in range(5)
            ],
        }
        summary = format_summary(_make_result(process_lifecycle=pl))
        assert "5 captured" in summary
        assert "max depth 4" in summary


class TestDescendantSummaryAbsent:
    """format_summary omits descendant info when no children captured."""

    def test_no_children_key(self) -> None:
        pl = {
            "root_pid": 12345,
            "command": ["echo", "hello"],
            "started_at": "2026-01-01T00:00:00.000000Z",
            "wall_clock_s": 0.123,
            "exit_code": 0,
            "exit_signal": None,
            "capture_tier": "host-observer",
        }
        summary = format_summary(_make_result(process_lifecycle=pl))
        assert "descendants" not in summary

    def test_empty_children_list(self) -> None:
        pl = {
            "root_pid": 12345,
            "command": ["echo", "hello"],
            "started_at": "2026-01-01T00:00:00.000000Z",
            "wall_clock_s": 0.123,
            "exit_code": 0,
            "exit_signal": None,
            "capture_tier": "host-observer",
            "children": [],
        }
        summary = format_summary(_make_result(process_lifecycle=pl))
        assert "descendants" not in summary

    def test_no_process_lifecycle(self) -> None:
        summary = format_summary(_make_result(process_lifecycle={}))
        assert "descendants" not in summary
        assert "process" not in summary


class TestDescendantSummaryEdgeCases:
    """Edge cases for descendant summary computation."""

    def test_children_missing_depth_defaults_to_zero(self) -> None:
        """Children without depth field should default to depth 0."""
        pl = {
            "root_pid": 1,
            "command": ["test"],
            "started_at": "2026-01-01T00:00:00.000000Z",
            "wall_clock_s": 0.1,
            "exit_code": 0,
            "exit_signal": None,
            "capture_tier": "host-observer",
            "children": [
                {
                    "pid": 2,
                    "command": ["child"],
                    "started_at": "2026-01-01T00:00:00.000000Z",
                    "wall_clock_s": 0.01,
                    "exit_code": 0,
                    "exit_signal": None,
                    "parent_pid": 1,
                },
            ],
        }
        summary = format_summary(_make_result(process_lifecycle=pl))
        assert "1 captured" in summary
        assert "max depth 0" in summary

    def test_process_line_still_present_with_descendants(self) -> None:
        """The root process line should still appear alongside descendants."""
        pl = {
            "root_pid": 42,
            "command": ["test"],
            "started_at": "2026-01-01T00:00:00.000000Z",
            "wall_clock_s": 1.0,
            "exit_code": 0,
            "exit_signal": None,
            "capture_tier": "host-observer",
            "children": [
                {
                    "pid": 43,
                    "command": ["child"],
                    "started_at": "2026-01-01T00:00:00.100000Z",
                    "wall_clock_s": 0.5,
                    "exit_code": 0,
                    "exit_signal": None,
                    "depth": 0,
                    "parent_pid": 42,
                },
            ],
        }
        summary = format_summary(_make_result(process_lifecycle=pl))
        assert "process" in summary
        assert "pid=42" in summary
        assert "descendants" in summary

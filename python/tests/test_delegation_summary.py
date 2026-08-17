"""Tests for delegation summary in ``format_summary`` output.

When the governance session summary includes ``delegation_count > 0``
(the agent delegated to subagents via ``delegate_passport``), the
human-readable ``format_summary`` output should include a
``delegations`` line showing the count of delegation requests and the
number of child sessions spawned, so users get immediate visibility
into multi-agent runs without parsing JSON.

When no delegations occurred, the line should be absent.
"""

from __future__ import annotations

from typing import Any

from vibap.run_bridge import format_summary, GovernanceRunResult


def _make_result(
    *,
    summary: dict[str, Any] | None = None,
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
        summary=summary or {},
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


class TestDelegationSummaryPresent:
    """``format_summary`` shows delegation info when delegations occurred."""

    def test_single_delegation_shows_line(self) -> None:
        summary = format_summary(
            _make_result(
                summary={
                    "delegation_count": 1,
                    "children_spawned": 1,
                }
            )
        )
        assert "delegations" in summary
        assert "1 requested" in summary
        assert "1 child sessions" in summary

    def test_multiple_delegations_multiple_children(self) -> None:
        summary = format_summary(
            _make_result(
                summary={
                    "delegation_count": 3,
                    "children_spawned": 2,
                }
            )
        )
        assert "delegations" in summary
        assert "3 requested" in summary
        assert "2 child sessions" in summary

    def test_delegations_with_some_failed(self) -> None:
        """delegation_count > children_spawned means some were denied."""
        summary = format_summary(
            _make_result(
                summary={
                    "delegation_count": 5,
                    "children_spawned": 3,
                }
            )
        )
        assert "delegations" in summary
        assert "5 requested" in summary
        assert "3 child sessions" in summary

    def test_delegation_line_appears_after_process_line(self) -> None:
        """When both process lifecycle and delegation data exist,
        the delegation line should appear after the process/descendants
        lines and before any notes."""
        pl = {
            "root_pid": 100,
            "command": ["agent"],
            "started_at": "2026-01-01T00:00:00.000000Z",
            "wall_clock_s": 5.0,
            "exit_code": 0,
            "exit_signal": None,
            "capture_tier": "host-observer",
        }
        summary = format_summary(
            _make_result(
                summary={"delegation_count": 2, "children_spawned": 2},
                process_lifecycle=pl,
            )
        )
        lines = summary.splitlines()
        proc_idx = next(i for i, line in enumerate(lines) if "process" in line and "pid=" in line)
        del_idx = next(i for i, line in enumerate(lines) if "delegations" in line)
        assert del_idx > proc_idx


class TestDelegationSummaryAbsent:
    """``format_summary`` omits delegation info when no delegations occurred."""

    def test_empty_summary(self) -> None:
        summary = format_summary(_make_result(summary={}))
        assert "delegations" not in summary

    def test_zero_delegation_count(self) -> None:
        summary = format_summary(
            _make_result(
                summary={
                    "delegation_count": 0,
                    "children_spawned": 0,
                }
            )
        )
        assert "delegations" not in summary

    def test_missing_delegation_count_key(self) -> None:
        summary = format_summary(
            _make_result(summary={"permits": 5, "denials": 0})
        )
        assert "delegations" not in summary


class TestDelegationSummaryEdgeCases:
    """Edge cases for delegation summary computation."""

    def test_children_spawned_zero_with_delegations(self) -> None:
        """All delegations denied — line still shows requested count."""
        summary = format_summary(
            _make_result(
                summary={
                    "delegation_count": 2,
                    "children_spawned": 0,
                }
            )
        )
        assert "delegations" in summary
        assert "2 requested" in summary
        assert "0 child sessions" in summary

    def test_non_integer_delegation_count(self) -> None:
        """Non-integer values from summary dict should be coerced safely."""
        summary = format_summary(
            _make_result(
                summary={
                    "delegation_count": "1",
                    "children_spawned": "1",
                }
            )
        )
        assert "delegations" in summary
        assert "1 requested" in summary

    def test_delegation_line_with_notes(self) -> None:
        """Delegation line should appear before notes."""
        summary = format_summary(
            _make_result(
                summary={"delegation_count": 1, "children_spawned": 1},
            ).__class__(
                **{
                    **_make_result(
                        summary={"delegation_count": 1, "children_spawned": 1}
                    ).__dict__,
                    "notes": ["test note"],
                }
            )
        )
        lines = summary.splitlines()
        del_idx = next(i for i, line in enumerate(lines) if "delegations" in line)
        note_idx = next(i for i, line in enumerate(lines) if "note" in line)
        assert del_idx < note_idx

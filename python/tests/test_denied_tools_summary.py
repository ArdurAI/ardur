"""Tests for denied-tools surfacing in the governance summary.

When a governed session has denials, the summary must show *which* tools
were blocked — not just a count — so the user does not have to open
receipts to find out.
"""

from __future__ import annotations

from vibap.run_bridge import format_summary
from vibap.run_bridge import GovernanceRunResult


def _make_result(
    *,
    permits: int = 0,
    denials: int = 0,
    denied_tools: list[str] | None = None,
) -> GovernanceRunResult:
    return GovernanceRunResult(
        exit_code=0,
        session_id="test-session",
        mission_id="test-mission",
        agent_id="test-agent",
        adapter="test",
        via="env",
        proxy_url="http://127.0.0.1:0",
        home="/tmp/ardur-test",
        passport_path="/tmp/ardur-test/passport.json",
        summary={
            "permits": permits,
            "denials": denials,
            "total_events": permits + denials,
            "denied_tools": denied_tools or [],
        },
        permits=permits,
        denials=denials,
        total_events=permits + denials,
        attestation_token="dummy",
        attestation_digest="sha-256:deadbeef",
        receipts_path="/tmp/ardur-test/receipts.jsonl",
        receipt_count=permits + denials,
        correlation={},
        kernel_policy={},
    )


class TestDeniedToolsSummary:
    def test_denied_tools_shown_when_denials_present(self):
        """A single denied tool appears on the ``denied`` line."""
        result = _make_result(
            permits=2,
            denials=1,
            denied_tools=["Bash"],
        )
        summary = format_summary(result)
        assert "denied        Bash" in summary

    def test_multiple_denied_tools_shown(self):
        """Multiple unique denied tools are comma-separated."""
        result = _make_result(
            permits=1,
            denials=3,
            denied_tools=["Bash", "Write", "WebFetch"],
        )
        summary = format_summary(result)
        assert "denied        Bash, Write, WebFetch" in summary

    def test_denied_line_absent_when_no_denials(self):
        """When there are zero denials the ``denied`` line is omitted."""
        result = _make_result(permits=3, denials=0, denied_tools=[])
        summary = format_summary(result)
        assert "denied" not in summary

    def test_denied_line_absent_when_denied_tools_empty(self):
        """Even if denials > 0 but denied_tools is empty, no line."""
        # This is a safety fallback: denied_tools should always be populated
        # when denials > 0, but the renderer should not crash if it isn't.
        result = _make_result(permits=1, denials=1, denied_tools=[])
        summary = format_summary(result)
        assert "denied        " not in summary

    def test_denied_tools_truncated_at_five(self):
        """More than 5 unique denied tools get truncated with a suffix."""
        tools = [f"Tool{i}" for i in range(8)]
        result = _make_result(
            permits=0,
            denials=8,
            denied_tools=tools,
        )
        summary = format_summary(result)
        assert "Tool0" in summary
        assert "Tool4" in summary
        assert "Tool5" not in summary  # truncated
        assert "(+3 more)" in summary

    def test_denied_tools_order_preserved_by_first_occurrence(self):
        """The order of denied_tools follows first occurrence in the list."""
        result = _make_result(
            permits=0,
            denials=3,
            denied_tools=["Write", "Bash", "WebFetch"],
        )
        summary = format_summary(result)
        assert "denied        Write, Bash, WebFetch" in summary

    def test_tool_calls_line_still_shows_count(self):
        """The existing tool calls count line is unchanged."""
        result = _make_result(
            permits=3,
            denials=2,
            denied_tools=["Bash"],
        )
        summary = format_summary(result)
        assert "3 permit / 2 deny" in summary

    def test_denied_line_positioned_before_scope(self):
        """The denied line appears before the scope line."""
        result = _make_result(
            permits=1,
            denials=1,
            denied_tools=["Bash"],
        )
        summary = format_summary(result)
        denied_pos = summary.index("denied        Bash")
        scope_pos = summary.index("scope")
        assert denied_pos < scope_pos

    def test_exactly_five_denied_tools_no_truncation(self):
        """Five unique denied tools: all shown, no truncation suffix."""
        tools = [f"Tool{i}" for i in range(5)]
        result = _make_result(
            permits=0,
            denials=5,
            denied_tools=tools,
        )
        summary = format_summary(result)
        assert "Tool4" in summary
        assert "more" not in summary

    def test_six_denied_tools_truncated_to_five(self):
        """Six unique denied tools: five shown, one truncated."""
        tools = [f"Tool{i}" for i in range(6)]
        result = _make_result(
            permits=0,
            denials=6,
            denied_tools=tools,
        )
        summary = format_summary(result)
        assert "(+1 more)" in summary
        assert "Tool5" not in summary

    def test_repeated_denial_of_same_tool_shown_once(self):
        """The denied_tools list from _build_summary deduplicates."""
        # Simulate what _build_summary produces: same tool denied twice
        # appears only once in the list.
        result = _make_result(
            permits=0,
            denials=2,
            denied_tools=["Bash"],  # deduplicated upstream
        )
        summary = format_summary(result)
        assert summary.count("Bash") == 1

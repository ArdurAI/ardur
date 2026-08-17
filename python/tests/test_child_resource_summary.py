"""Tests for aggregate child resource usage in governance summary.

When ``process_lifecycle.children`` contains per-child ``cpu_user_s``,
``cpu_system_s``, and ``rss_bytes`` fields (captured by
``_child_process_snapshot``), ``format_summary`` should surface aggregate
totals in the human-readable text: summed CPU time across all children and
the maximum child RSS.  Children without resource fields (e.g. AccessDenied)
are skipped gracefully and do not prevent the aggregate from rendering.
"""

from __future__ import annotations

import re

from vibap.run_bridge import format_summary, GovernanceRunResult


def _make_result(
    process_lifecycle: dict | None = None,
    summary: dict | None = None,
) -> GovernanceRunResult:
    return GovernanceRunResult(
        exit_code=0,
        session_id="test-session",
        mission_id="test-mission",
        agent_id="test-agent",
        adapter="env",
        via="env",
        proxy_url="http://127.0.0.1:0",
        home="/tmp/ardur-test-home",
        passport_path="/tmp/ardur-test-home/passport.json",
        summary=summary or {},
        permits=1,
        denials=0,
        total_events=1,
        attestation_token="dummy",
        attestation_digest="sha-256:deadbeef",
        receipts_path="/tmp/ardur-test-home/receipts.jsonl",
        receipt_count=1,
        correlation={"available": False},
        kernel_policy={},
        process_lifecycle=process_lifecycle or {},
    )


class TestChildResourceSummary:
    """Aggregate child CPU/RSS rendering in ``format_summary``."""

    def test_child_cpu_and_rss_shown_when_present(self):
        """Children with resource fields produce child cpu + child max rss lines."""
        pl = {
            "root_pid": 1000,
            "wall_clock_s": 1.5,
            "capture_tier": "host-observer",
            "exit_code": 0,
            "children": [
                {
                    "pid": 1001,
                    "depth": 1,
                    "cpu_user_s": 0.3,
                    "cpu_system_s": 0.1,
                    "rss_bytes": 5 * 1024 * 1024,
                },
                {
                    "pid": 1002,
                    "depth": 2,
                    "cpu_user_s": 0.5,
                    "cpu_system_s": 0.2,
                    "rss_bytes": 8 * 1024 * 1024,
                },
            ],
        }
        text = format_summary(_make_result(process_lifecycle=pl))
        # Aggregate child CPU: 0.3+0.5 user + 0.1+0.2 sys = 1.1s total
        assert "child cpu" in text
        assert "1.100s" in text
        # Max child RSS: 8 MiB
        assert "child max rss" in text
        assert "8.0 MB" in text

    def test_child_resource_lines_absent_when_children_have_no_metrics(self):
        """Children without cpu/rss fields do not produce child cpu/rss lines."""
        pl = {
            "root_pid": 1000,
            "wall_clock_s": 0.5,
            "capture_tier": "host-observer",
            "exit_code": 0,
            "children": [
                {"pid": 1001, "depth": 1},
                {"pid": 1002, "depth": 2},
            ],
        }
        text = format_summary(_make_result(process_lifecycle=pl))
        assert "child cpu" not in text
        assert "child max rss" not in text
        # Descendant count should still show
        assert "descendants   2 captured" in text

    def test_partial_children_with_and_without_metrics(self):
        """Mix of metric-bearing and metric-less children aggregates correctly."""
        pl = {
            "root_pid": 1000,
            "wall_clock_s": 1.0,
            "capture_tier": "host-observer",
            "exit_code": 0,
            "children": [
                {
                    "pid": 1001,
                    "depth": 1,
                    "cpu_user_s": 0.4,
                    "cpu_system_s": 0.1,
                    "rss_bytes": 3 * 1024 * 1024,
                },
                {"pid": 1002, "depth": 2},  # no metrics (e.g. AccessDenied)
                {
                    "pid": 1003,
                    "depth": 1,
                    "cpu_user_s": 0.2,
                    "cpu_system_s": 0.3,
                    "rss_bytes": 6 * 1024 * 1024,
                },
            ],
        }
        text = format_summary(_make_result(process_lifecycle=pl))
        # Only children with metrics contribute: 0.4+0.2 user + 0.1+0.3 sys = 1.0s
        assert "child cpu" in text
        assert "1.000s" in text
        # Max RSS from children with metrics: 6 MiB
        assert "child max rss" in text
        assert "6.0 MB" in text

    def test_no_child_lines_when_no_children(self):
        """No children means no child resource lines."""
        pl = {
            "root_pid": 1000,
            "wall_clock_s": 0.5,
            "capture_tier": "host-observer",
            "exit_code": 0,
        }
        text = format_summary(_make_result(process_lifecycle=pl))
        assert "child cpu" not in text
        assert "child max rss" not in text

    def test_child_lines_absent_when_process_lifecycle_none(self):
        """No lifecycle means no child resource lines."""
        text = format_summary(_make_result(process_lifecycle=None))
        assert "child cpu" not in text
        assert "child max rss" not in text

    def test_single_child_with_zero_cpu_shows_no_child_cpu(self):
        """A child with explicit 0 CPU (but nonzero RSS) skips child cpu line."""
        pl = {
            "root_pid": 1000,
            "wall_clock_s": 0.5,
            "capture_tier": "host-observer",
            "exit_code": 0,
            "children": [
                {
                    "pid": 1001,
                    "depth": 1,
                    "cpu_user_s": 0.0,
                    "cpu_system_s": 0.0,
                    "rss_bytes": 2 * 1024 * 1024,
                },
            ],
        }
        text = format_summary(_make_result(process_lifecycle=pl))
        assert "child cpu" not in text
        assert "child max rss" in text
        assert "2.0 MB" in text

    def test_redact_paths_preserves_numeric_child_fields(self):
        """Numeric child resource fields survive redact_paths substitution."""
        from vibap.shareable_redaction import redact_local_path_text

        pl = {
            "root_pid": 1000,
            "wall_clock_s": 1.0,
            "capture_tier": "host-observer",
            "exit_code": 0,
            "children": [
                {
                    "pid": 1001,
                    "depth": 1,
                    "cpu_user_s": 0.5,
                    "cpu_system_s": 0.2,
                    "rss_bytes": 4 * 1024 * 1024,
                },
            ],
        }
        redacted = redact_local_path_text(
            repr(pl),
            root_pairs=[("/tmp/ardur-test-home", "<HOME>")],
        )
        # Numeric fields are not paths and should be unchanged
        assert "0.5" in redacted
        assert str(4 * 1024 * 1024) in redacted

    def test_child_cpu_format_matches_root_cpu_format(self):
        """The child cpu line format mirrors the root cpu line format."""
        pl = {
            "root_pid": 1000,
            "wall_clock_s": 1.0,
            "capture_tier": "host-observer",
            "exit_code": 0,
            "cpu_user_s": 0.1,
            "cpu_system_s": 0.05,
            "children": [
                {
                    "pid": 1001,
                    "depth": 1,
                    "cpu_user_s": 0.3,
                    "cpu_system_s": 0.1,
                    "rss_bytes": 5 * 1024 * 1024,
                },
            ],
        }
        text = format_summary(_make_result(process_lifecycle=pl))
        # Both root cpu and child cpu should follow the same format
        root_match = re.search(r"cpu\s+[\d.]+s\s+\(user [\d.]+s / sys [\d.]+s\)", text)
        child_match = re.search(
            r"child cpu\s+[\d.]+s\s+\(user [\d.]+s / sys [\d.]+s\)", text
        )
        assert root_match, f"Root cpu line not found in:\n{text}"
        assert child_match, f"Child cpu line not found in:\n{text}"

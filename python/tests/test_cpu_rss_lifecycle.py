"""Tests for CPU/memory usage in process-lifecycle evidence and governance summary.

Covers the ``cpu_user_s``, ``cpu_system_s``, and ``peak_rss_bytes`` fields
added to ``_build_process_lifecycle_evidence`` via the ``rusage_delta``
parameter, the ``_get_child_rusage`` / ``_compute_rusage_delta`` helpers,
and the corresponding ``cpu`` / ``peak rss`` lines in ``format_summary``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any

from vibap.run_bridge import (
    _build_process_lifecycle_evidence,
    _compute_rusage_delta,
    _format_bytes,
    _get_child_rusage,
    format_summary,
)


# ── _get_child_rusage ──────────────────────────────────────────────────────────


class TestGetChildRusage:
    def test_returns_dict_with_expected_keys(self):
        result = _get_child_rusage()
        assert "ru_utime" in result
        assert "ru_stime" in result
        assert "ru_maxrss" in result

    def test_values_are_floats(self):
        result = _get_child_rusage()
        assert isinstance(result["ru_utime"], float)
        assert isinstance(result["ru_stime"], float)
        assert isinstance(result["ru_maxrss"], float)

    def test_values_non_negative(self):
        result = _get_child_rusage()
        assert result["ru_utime"] >= 0.0
        assert result["ru_stime"] >= 0.0
        assert result["ru_maxrss"] >= 0.0


# ── _compute_rusage_delta ───────────────────────────────────────────────────────


class TestComputeRusageDelta:
    def test_simple_delta(self):
        before = {"ru_utime": 1.0, "ru_stime": 0.5, "ru_maxrss": 1000.0}
        after = {"ru_utime": 3.0, "ru_stime": 1.5, "ru_maxrss": 5000.0}
        delta = _compute_rusage_delta(before, after)
        assert delta["ru_utime"] == 2.0
        assert delta["ru_stime"] == 1.0
        assert delta["ru_maxrss"] == 4000.0

    def test_zero_delta(self):
        snapshot = {"ru_utime": 5.0, "ru_stime": 2.0, "ru_maxrss": 10000.0}
        delta = _compute_rusage_delta(snapshot, snapshot)
        assert delta["ru_utime"] == 0.0
        assert delta["ru_stime"] == 0.0
        assert delta["ru_maxrss"] == 0.0

    def test_negative_clamped_to_zero(self):
        before = {"ru_utime": 5.0, "ru_stime": 3.0, "ru_maxrss": 8000.0}
        after = {"ru_utime": 3.0, "ru_stime": 1.0, "ru_maxrss": 4000.0}
        delta = _compute_rusage_delta(before, after)
        assert delta["ru_utime"] == 0.0
        assert delta["ru_stime"] == 0.0
        assert delta["ru_maxrss"] == 0.0

    def test_peak_rss_is_high_water_mark_not_cumulative(self):
        """ru_maxrss is a peak, so after > before gives the child's peak."""
        before = {"ru_utime": 0.0, "ru_stime": 0.0, "ru_maxrss": 1000.0}
        after = {"ru_utime": 0.5, "ru_stime": 0.1, "ru_maxrss": 50000.0}
        delta = _compute_rusage_delta(before, after)
        # 49000 = 50000 - 1000 (previous high water mark)
        assert delta["ru_maxrss"] == 49000.0


# ── _build_process_lifecycle_evidence with rusage_delta ─────────────────────────


class TestRusageDeltaInLifecycleEvidence:
    def test_fields_present_when_rusage_delta_provided(self):
        """cpu_user_s, cpu_system_s, peak_rss_bytes appear when rusage_delta given."""
        result = _build_process_lifecycle_evidence(
            proc=None,
            command=["echo"],
            launch_monotonic=0.0,
            launch_wall_clock=1700000000.0,
            exit_code=0,
            rusage_delta={
                "ru_utime": 1.5,
                "ru_stime": 0.3,
                "ru_maxrss": 52428800,  # 50 MB in bytes
            },
        )
        assert result["cpu_user_s"] == 1.5
        assert result["cpu_system_s"] == 0.3
        assert result["peak_rss_bytes"] == 52428800

    def test_fields_absent_when_rusage_delta_none(self):
        """cpu_user_s etc. are absent when rusage_delta is None (backward compat)."""
        result = _build_process_lifecycle_evidence(
            proc=None,
            command=["echo"],
            launch_monotonic=0.0,
            launch_wall_clock=1700000000.0,
            exit_code=0,
        )
        assert "cpu_user_s" not in result
        assert "cpu_system_s" not in result
        assert "peak_rss_bytes" not in result

    def test_rusage_delta_zero_values(self):
        """Zero rusage delta produces zero fields (not omitted)."""
        result = _build_process_lifecycle_evidence(
            proc=None,
            command=["echo"],
            launch_monotonic=0.0,
            launch_wall_clock=1700000000.0,
            exit_code=0,
            rusage_delta={"ru_utime": 0.0, "ru_stime": 0.0, "ru_maxrss": 0.0},
        )
        assert result["cpu_user_s"] == 0.0
        assert result["cpu_system_s"] == 0.0
        assert result["peak_rss_bytes"] == 0

    def test_rusage_delta_rounded_to_6_decimals(self):
        result = _build_process_lifecycle_evidence(
            proc=None,
            command=["echo"],
            launch_monotonic=0.0,
            launch_wall_clock=1700000000.0,
            exit_code=0,
            rusage_delta={
                "ru_utime": 1.123456789,
                "ru_stime": 0.987654321,
                "ru_maxrss": 1000,
            },
        )
        assert result["cpu_user_s"] == 1.123457
        assert result["cpu_system_s"] == 0.987654

    def test_peak_rss_is_int(self):
        result = _build_process_lifecycle_evidence(
            proc=None,
            command=["echo"],
            launch_monotonic=0.0,
            launch_wall_clock=1700000000.0,
            exit_code=0,
            rusage_delta={
                "ru_utime": 0.1,
                "ru_stime": 0.0,
                "ru_maxrss": 99.7,
            },
        )
        assert isinstance(result["peak_rss_bytes"], int)
        assert result["peak_rss_bytes"] == 99


# ── _format_bytes ───────────────────────────────────────────────────────────────


class TestFormatBytes:
    def test_bytes(self):
        assert _format_bytes(0) == "0 B"
        assert _format_bytes(512) == "512 B"
        assert _format_bytes(1023) == "1023 B"

    def test_kilobytes(self):
        assert _format_bytes(1024) == "1.0 KB"
        assert _format_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        mb = 10 * 1024 * 1024
        assert _format_bytes(mb) == "10.0 MB"

    def test_gigabytes(self):
        gb = int(2.5 * 1024 * 1024 * 1024)
        assert _format_bytes(gb) == "2.50 GB"


# ── format_summary: cpu and peak rss lines ──────────────────────────────────────


@dataclass
class MockResult:
    """Minimal stand-in for GovernanceRunResult for summary tests."""
    exit_code: int = 0
    session_id: str = "test-session"
    mission_id: str = "test-mission"
    adapter: str = "test"
    via: str = "env"
    summary: dict[str, Any] = field(default_factory=lambda: {"scope_compliance": "full", "elapsed_s": 0.1})
    permits: int = 1
    denials: int = 0
    total_events: int = 1
    attestation_digest: str = "abc123"
    receipts_path: str = "/dev/null"
    receipt_count: int = 0
    correlation: dict[str, Any] = field(default_factory=lambda: {"reason": "test"})
    kernel_policy: dict[str, Any] = field(default_factory=lambda: {"reason": "test"})
    process_lifecycle: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


class TestSummaryCpuRssLines:
    def test_cpu_line_appears_when_lifecycle_has_rusage(self):
        result = MockResult(process_lifecycle={
            "root_pid": 1234,
            "wall_clock_s": 5.0,
            "exit_code": 0,
            "capture_tier": "host-observer",
            "cpu_user_s": 1.5,
            "cpu_system_s": 0.3,
            "peak_rss_bytes": 52428800,  # 50 MB
        })
        summary = format_summary(result)
        assert "cpu" in summary
        assert "1.800s" in summary  # 1.5 + 0.3
        assert "user 1.500s" in summary
        assert "sys 0.300s" in summary

    def test_peak_rss_line_appears_when_nonzero(self):
        result = MockResult(process_lifecycle={
            "root_pid": 1234,
            "wall_clock_s": 5.0,
            "exit_code": 0,
            "capture_tier": "host-observer",
            "cpu_user_s": 0.1,
            "cpu_system_s": 0.0,
            "peak_rss_bytes": 104857600,  # 100 MB
        })
        summary = format_summary(result)
        assert "peak rss" in summary
        assert "100.0 MB" in summary

    def test_cpu_line_absent_when_no_rusage_fields(self):
        result = MockResult(process_lifecycle={
            "root_pid": 1234,
            "wall_clock_s": 5.0,
            "exit_code": 0,
            "capture_tier": "host-observer",
        })
        summary = format_summary(result)
        assert "cpu          " not in summary
        assert "peak rss" not in summary

    def test_cpu_line_absent_when_lifecycle_empty(self):
        result = MockResult()
        summary = format_summary(result)
        assert "cpu          " not in summary
        assert "peak rss" not in summary

    def test_cpu_line_with_zero_values(self):
        """Even with zero CPU, the line should appear if the fields are present."""
        result = MockResult(process_lifecycle={
            "root_pid": 1234,
            "wall_clock_s": 0.01,
            "exit_code": 0,
            "capture_tier": "host-observer",
            "cpu_user_s": 0.0,
            "cpu_system_s": 0.0,
            "peak_rss_bytes": 0,
        })
        summary = format_summary(result)
        assert "cpu" in summary
        assert "0.000s" in summary
        # peak_rss=0 should NOT produce a peak rss line
        assert "peak rss" not in summary

    def test_cpu_and_rss_appear_after_descendants(self):
        """Summary ordering: process → descendants → cpu → peak rss → delegations."""
        result = MockResult(process_lifecycle={
            "root_pid": 1234,
            "wall_clock_s": 5.0,
            "exit_code": 0,
            "capture_tier": "host-observer",
            "children": [{"pid": 1235, "depth": 0, "command": ["child"]}],
            "cpu_user_s": 1.0,
            "cpu_system_s": 0.2,
            "peak_rss_bytes": 52428800,
        })
        summary = format_summary(result)
        lines = summary.split("\n")
        cpu_idx = next(i for i, line in enumerate(lines) if "cpu          " in line)
        rss_idx = next(i for i, line in enumerate(lines) if "peak rss" in line)
        desc_idx = next(i for i, line in enumerate(lines) if "descendants" in line)
        assert desc_idx < cpu_idx < rss_idx


# ── Integration: real rusage from a child process ──────────────────────────────


class TestRealRusageIntegration:
    def test_real_child_process_produces_nonzero_cpu(self):
        """Launch a real CPU-burning child and verify rusage captures it.

        CPU time (ru_utime/ru_stime) is cumulative across waited-for children,
        so the delta is always positive for a process that burns CPU.

        ru_maxrss is a **high-water mark** (not cumulative): it tracks the
        maximum RSS of any single waited-for child, not the sum. When this test
        runs after other tests that spawned child processes with higher RSS
        (common in CI with hundreds of prior test-subprocess calls), the
        high-water mark was already set by an earlier child and the delta is
        legitimately 0. We therefore assert non-negativity, not positivity.
        On Linux, ru_maxrss is reported in KB, so a small child may also round
        to the same KB value as a prior one.
        """
        import subprocess

        before = _get_child_rusage()
        proc = subprocess.Popen(
            [sys.executable, "-c", "x = sum(i**2 for i in range(500000))"],
        )
        proc.wait()
        after = _get_child_rusage()
        delta = _compute_rusage_delta(before, after)

        assert delta["ru_utime"] > 0.0
        assert delta["ru_maxrss"] >= 0.0

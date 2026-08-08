"""Tests for kernel line suppression in format_summary.

When kernel correlation is not available (the common case — no daemon running),
the summary should suppress `kernel link` and `kernel policy` lines to reduce
noise. When correlation IS available (or kernel policy was actively applied),
those lines should appear.
"""

from vibap.run_bridge import format_summary, GovernanceRunResult


def _make_result(
    *,
    correlation_available: bool = False,
    correlation_reason: str = "kernel correlation disabled by caller",
    policy_tier=None,
    policy_wrapped=False,
    policy_reason="kernel policy not applied: kernel correlation disabled by caller",
    process_lifecycle=None,
) -> GovernanceRunResult:
    """Build a minimal GovernanceRunResult for summary testing."""
    corr = {"available": correlation_available, "reason": correlation_reason}
    pol = {"reason": policy_reason, "tier": policy_tier, "wrapped": policy_wrapped}
    return GovernanceRunResult(
        session_id="test-session",
        mission_id="test-mission",
        adapter="claude-code",
        via="hook",
        total_events=5,
        permits=3,
        denials=2,
        summary={},
        receipt_count=5,
        receipts_path="/tmp/test.jsonl",
        attestation_digest="sha256:abc",
        correlation=corr,
        kernel_policy=pol,
        exit_code=0,
        process_lifecycle=process_lifecycle,
        notes=[],
        agent_id="test-agent",
        proxy_url="http://127.0.0.1:8080",
        home="/tmp/test-home",
        passport_path="/tmp/test-passport",
        attestation_token="test-token",
    )


class TestKernelSuppressionNoCorrelation:
    """When kernel correlation is unavailable, kernel lines should be absent."""

    def test_no_kernel_lines_when_unavailable(self):
        result = _make_result(correlation_available=False)
        summary = format_summary(result)
        assert "kernel link" not in summary
        assert "kernel policy" not in summary

    def test_no_kernel_lines_default_reason(self):
        result = _make_result(
            correlation_available=False,
            correlation_reason="kernel correlation disabled by caller",
        )
        summary = format_summary(result)
        assert "kernel link" not in summary
        assert "kernel policy" not in summary

    def test_no_kernel_lines_no_daemon_socket(self):
        result = _make_result(
            correlation_available=False,
            correlation_reason="daemon socket not found",
        )
        summary = format_summary(result)
        assert "kernel link" not in summary


class TestKernelShownWhenAvailable:
    """When kernel correlation IS available, kernel link line should appear."""

    def test_kernel_link_shown_when_available(self):
        result = _make_result(
            correlation_available=True,
            correlation_reason="daemon connected, cgroup matched",
        )
        summary = format_summary(result)
        assert "kernel link" in summary
        assert "daemon connected" in summary

    def test_kernel_policy_shown_with_tier(self):
        result = _make_result(
            correlation_available=True,
            correlation_reason="cgroup matched",
            policy_tier="seccomp-notify",
            policy_reason="seccomp-notify active",
        )
        summary = format_summary(result)
        assert "kernel policy" in summary
        assert "seccomp-notify active" in summary

    def test_kernel_policy_shown_when_wrapped(self):
        result = _make_result(
            correlation_available=False,
            policy_tier=None,
            policy_wrapped=True,
            policy_reason="wrapped with seccomp profile",
        )
        summary = format_summary(result)
        assert "kernel policy" in summary
        assert "wrapped" in summary

    def test_kernel_policy_shown_when_available_with_reason(self):
        result = _make_result(
            correlation_available=True,
            correlation_reason="cgroup matched",
            policy_reason="policy applied: tier=ebpf",
        )
        summary = format_summary(result)
        assert "kernel policy" in summary
        assert "policy applied" in summary


class TestKernelSuppressionWithProcessLifecycle:
    """Kernel line suppression should work alongside other lifecycle lines."""

    def test_summary_clean_without_kernel(self):
        pl = {
            "root_pid": 12345,
            "wall_clock_s": 2.5,
            "exit_code": 0,
            "capture_tier": "host-observer",
            "cpu_user_s": 0.1,
            "cpu_system_s": 0.05,
            "peak_rss_bytes": 10485760,
        }
        result = _make_result(
            correlation_available=False,
            process_lifecycle=pl,
        )
        summary = format_summary(result)
        assert "kernel link" not in summary
        assert "kernel policy" not in summary
        assert "process" in summary
        assert "cpu" in summary
        assert "peak rss" in summary

    def test_summary_with_kernel_and_lifecycle(self):
        pl = {
            "root_pid": 12345,
            "wall_clock_s": 2.5,
            "exit_code": 0,
            "capture_tier": "ebpf-daemon",
        }
        result = _make_result(
            correlation_available=True,
            correlation_reason="cgroup matched",
            policy_tier="ebpf",
            policy_reason="policy applied",
            process_lifecycle=pl,
        )
        summary = format_summary(result)
        assert "kernel link" in summary
        assert "kernel policy" in summary
        assert "process" in summary


class TestKernelLineContent:
    """Verify the actual content of kernel lines when shown."""

    def test_kernel_link_uses_correlation_reason(self):
        result = _make_result(
            correlation_available=True,
            correlation_reason="cgroup=/foo matched",
        )
        summary = format_summary(result)
        assert "cgroup=/foo matched" in summary

    def test_kernel_link_uses_available_fallback(self):
        """When available=True but no reason, show 'available'."""
        result = _make_result(
            correlation_available=True,
            correlation_reason="",
        )
        summary = format_summary(result)
        assert "available" in summary

    def test_kernel_policy_uses_policy_reason(self):
        result = _make_result(
            correlation_available=True,
            correlation_reason="ok",
            policy_tier="ebpf",
            policy_reason="active: ebpf guard",
        )
        summary = format_summary(result)
        assert "active: ebpf guard" in summary


class TestNonKernelFieldsUnchanged:
    """Non-kernel summary fields should not be affected."""

    def test_session_line_present(self):
        result = _make_result()
        summary = format_summary(result)
        assert "session       test-session" in summary

    def test_tool_calls_line_present(self):
        result = _make_result()
        summary = format_summary(result)
        assert "tool calls    5 evaluated (3 permit / 2 deny)" in summary

    def test_exit_line_present(self):
        result = _make_result()
        summary = format_summary(result)
        assert "agent exit    0" in summary

    def test_attestation_line_present(self):
        result = _make_result()
        summary = format_summary(result)
        assert "sha256:abc" in summary

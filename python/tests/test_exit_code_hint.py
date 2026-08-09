"""Tests for the exit-code hint annotation in ``format_summary``.

When ``result.exit_code`` is non-zero, the ``agent exit`` summary line
should include a parenthesised hint:

* POSIX signal exit (128 + signum) → ``"killed by SIGKILL"`` etc.
* Other non-zero → ``"non-zero exit"``
* Zero or ``None`` → no hint (bare exit code)

This makes the summary self-explanatory for users who see ``exit 137``
without knowing the POSIX signal convention.
"""

from __future__ import annotations

import signal

from vibap.run_bridge import format_summary, GovernanceRunResult, _exit_code_hint


# -- _exit_code_hint unit tests --------------------------------------------


class TestExitCodeHintZero:
    def test_zero_returns_empty(self) -> None:
        assert _exit_code_hint(0) == ""

    def test_none_returns_empty(self) -> None:
        assert _exit_code_hint(None) == ""


class TestExitCodeHintSignal:
    def test_sigkill_137(self) -> None:
        assert _exit_code_hint(137) == f"killed by {signal.SIGKILL.name}"

    def test_sigterm_143(self) -> None:
        assert _exit_code_hint(143) == f"killed by {signal.SIGTERM.name}"

    def test_sigint_130(self) -> None:
        assert _exit_code_hint(130) == f"killed by {signal.SIGINT.name}"

    def test_sigsegv_139(self) -> None:
        assert _exit_code_hint(139) == f"killed by {signal.SIGSEGV.name}"

    def test_unknown_high_signal(self) -> None:
        """A signal number with no stdlib name still gets a numeric hint."""
        # 255 = 128 + 127, no named signal
        hint = _exit_code_hint(255)
        assert "signal 127" in hint


class TestExitCodeHintNonSignal:
    def test_one(self) -> None:
        assert _exit_code_hint(1) == "non-zero exit"

    def test_two(self) -> None:
        assert _exit_code_hint(2) == "non-zero exit"

    def test_127(self) -> None:
        """127 is 'command not found', not a signal exit (128+ would be)."""
        assert _exit_code_hint(127) == "non-zero exit"

    def test_128_exactly(self) -> None:
        """128 itself is not a signal exit (128+1=129 would be SIGHUP)."""
        assert _exit_code_hint(128) == "non-zero exit"

    def test_negative(self) -> None:
        """Negative codes (pre-normalisation) are treated as non-zero."""
        assert _exit_code_hint(-9) == "non-zero exit"


# -- format_summary integration tests --------------------------------------


def _make_result(exit_code: int) -> GovernanceRunResult:
    """Build a minimal GovernanceRunResult for summary testing."""
    return GovernanceRunResult(
        exit_code=exit_code,
        session_id="test-session",
        mission_id="test-mission",
        agent_id="test-agent",
        adapter="claude",
        via="auto",
        proxy_url="http://127.0.0.1:0",
        home="/tmp/test-home",
        passport_path="/tmp/test-passport.json",
        summary={},
        permits=0,
        denials=0,
        total_events=0,
        attestation_token="",
        attestation_digest="",
        receipts_path="/tmp/test-receipts",
        receipt_count=0,
        correlation={},
        kernel_policy={},
        process_lifecycle={},
    )


class TestAgentExitLineFormatting:
    def test_zero_exit_no_hint(self) -> None:
        result = _make_result(0)
        summary = format_summary(result)
        assert "agent exit    0" in summary
        # No parenthesised hint after the zero
        line = [l for l in summary.splitlines() if "agent exit" in l][0]
        assert "(" not in line

    def test_sigkill_exit_shows_hint(self) -> None:
        result = _make_result(137)
        summary = format_summary(result)
        line = [l for l in summary.splitlines() if "agent exit" in l][0]
        assert "137" in line
        assert "killed by SIGKILL" in line

    def test_sigterm_exit_shows_hint(self) -> None:
        result = _make_result(143)
        summary = format_summary(result)
        line = [l for l in summary.splitlines() if "agent exit" in l][0]
        assert "143" in line
        assert "killed by SIGTERM" in line

    def test_generic_nonzero_shows_hint(self) -> None:
        result = _make_result(1)
        summary = format_summary(result)
        line = [l for l in summary.splitlines() if "agent exit" in l][0]
        assert "1" in line
        assert "non-zero exit" in line

    def test_command_not_found_no_signal_hint(self) -> None:
        """Exit 127 should show 'non-zero exit', not a signal name."""
        result = _make_result(127)
        summary = format_summary(result)
        line = [l for l in summary.splitlines() if "agent exit" in l][0]
        assert "127" in line
        assert "non-zero exit" in line
        assert "killed by" not in line

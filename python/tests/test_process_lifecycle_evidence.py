"""Tests for host-observer process-lifecycle evidence capture in ``ardur run``.

These tests verify the zero-privilege host-observer capture tier: when an
arbitrary CLI is launched under ``ardur run``, the root process's lifecycle
(PID, timestamps, wall-clock duration, exit code, signal) is captured into
``GovernanceRunResult.process_lifecycle`` and surfaced in both the JSON result
(``--json``) and the human-readable summary.

This is the *host-observer* tier — it works with any CLI on macOS/Linux
without any plugin API dependency. It is structurally weaker than eBPF daemon
correlation (which captures process-tree *interior* events) and the boundary
is encoded honestly in ``capture_tier``.
"""

from __future__ import annotations

import json
import sys
import time

import pytest

from vibap.run_bridge import (
    GovernanceRunResult,
    _build_process_lifecycle_evidence,
    _signal_name,
    format_summary,
)


# ── _build_process_lifecycle_evidence unit tests ──────────────────────────────


class _FakeProc:
    """Minimal stand-in for subprocess.Popen with just .pid."""

    def __init__(self, pid: int) -> None:
        self.pid = pid


class TestBuildProcessLifecycleEvidence:
    """Unit tests for the lifecycle-evidence builder."""

    def test_captures_root_pid_and_command(self) -> None:
        proc = _FakeProc(12345)
        result = _build_process_lifecycle_evidence(
            proc=proc,  # type: ignore[arg-type]
            command=["echo", "hello"],
            launch_monotonic=time.monotonic() - 0.1,
            launch_wall_clock=time.time() - 0.1,
            exit_code=0,
        )
        assert result["root_pid"] == 12345
        assert result["command"] == ["echo", "hello"]

    def test_captures_exit_code_zero(self) -> None:
        proc = _FakeProc(999)
        result = _build_process_lifecycle_evidence(
            proc=proc,  # type: ignore[arg-type]
            command=["true"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        assert result["exit_code"] == 0
        assert result["exit_signal"] is None

    def test_captures_nonzero_exit_code(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["false"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=1,
        )
        assert result["exit_code"] == 1
        assert result["exit_signal"] is None

    def test_captures_signal_termination(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["sleep", "100"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=-9,
        )
        assert result["exit_code"] == -9
        assert result["exit_signal"] is not None
        assert "KILL" in result["exit_signal"] or "9" in result["exit_signal"]

    def test_started_at_is_iso_format(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        ts = result["started_at"]
        assert ts.endswith("Z")
        assert "T" in ts
        assert len(ts) >= 20

    def test_started_at_uses_wall_clock_not_monotonic(self) -> None:
        """Regression: started_at must be a sane epoch date, not 1970.

        ``time.monotonic()`` returns boot-relative seconds, not Unix epoch
        seconds. If the launch timestamp is accidentally derived from the
        monotonic clock, ``started_at`` jumps back to ~1970.
        """
        now_epoch = time.time()
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=now_epoch,
            exit_code=0,
        )
        ts = result["started_at"]
        # Parse the year from "YYYY-MM-DDTHH:MM:SS.ffffffZ"
        year = int(ts.split("-")[0])
        assert year >= 2024, (
            f"started_at year={year} is implausible; "
            f"expected >= 2024 (epoch time), got {ts}. "
            "This indicates monotonic clock was used instead of wall clock."
        )

    def test_started_at_matches_provided_wall_clock(self) -> None:
        """started_at should be the ISO rendering of the given epoch timestamp."""
        fixed_epoch = 1722878400.0  # 2024-08-05T16:00:00Z — deterministic
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=fixed_epoch,
            exit_code=0,
        )
        # The ISO timestamp should start with 2024-08-05
        assert result["started_at"].startswith("2024-08-05"), (
            f"Expected 2024-08-05 from fixed epoch, got {result['started_at']}"
        )

    def test_wall_clock_s_is_positive_float(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo"],
            launch_monotonic=time.monotonic() - 0.05,
            launch_wall_clock=time.time() - 0.05,
            exit_code=0,
        )
        assert isinstance(result["wall_clock_s"], float)
        assert result["wall_clock_s"] > 0

    def test_capture_tier_is_host_observer(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        assert result["capture_tier"] == "host-observer"

    def test_capture_boundary_is_documented(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        boundary = result["capture_boundary"]
        assert "root-process lifecycle only" in boundary
        assert "eBPF daemon" in boundary

    def test_proc_none_yields_null_pid(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=None,
            command=["echo"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=127,
        )
        assert result["root_pid"] is None
        assert result["exit_code"] == 127


# ── _signal_name tests ────────────────────────────────────────────────────────


class TestSignalName:
    def test_sigkill(self) -> None:
        assert "KILL" in _signal_name(-9)

    def test_sigterm(self) -> None:
        assert "TERM" in _signal_name(-15)

    def test_unknown_signal_fallback(self) -> None:
        # Very high signal number that won't be in the enum
        name = _signal_name(-999)
        assert "999" in name


# ── GovernanceRunResult.to_result_dict tests ──────────────────────────────────


class TestResultDictLifecycle:
    def test_process_lifecycle_in_result_dict(self) -> None:
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home="/tmp/x",
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": ["echo", "hi"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        d = result.to_result_dict()
        assert "process_lifecycle" in d
        assert d["process_lifecycle"]["root_pid"] == 4242
        assert d["process_lifecycle"]["capture_tier"] == "host-observer"

    def test_process_lifecycle_defaults_empty(self) -> None:
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home="/tmp/x",
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
        )
        d = result.to_result_dict()
        assert d["process_lifecycle"] == {}

    def test_redact_paths_redacts_command_elements(self) -> None:
        """W1 regression: process_lifecycle.command must be redacted."""
        import os
        import tempfile

        home = os.path.expanduser("~")
        tmp_dir = tempfile.gettempdir()
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home=home,
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": [
                    "node",
                    f"{home}/secret/project/script.js",
                    f"{tmp_dir}/config.json",
                ],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        d = result.to_result_dict(redact_paths=True)
        cmd = d["process_lifecycle"]["command"]
        # The binary name (no path) should survive.
        assert cmd[0] == "node"
        # Local paths must be replaced with placeholders.
        assert home not in cmd[1], (
            f"Home path leaked in redacted command: {cmd[1]}"
        )
        assert "<home>" in cmd[1], f"Expected <home> placeholder, got {cmd[1]}"
        assert tmp_dir not in cmd[2], (
            f"Temp path leaked in redacted command: {cmd[2]}"
        )

    def test_redact_paths_off_preserves_command(self) -> None:
        """Without redact_paths, command is returned verbatim."""
        import os

        home = os.path.expanduser("~")
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home=home,
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": ["node", f"{home}/script.js"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        d = result.to_result_dict(redact_paths=False)
        cmd = d["process_lifecycle"]["command"]
        assert cmd[1] == f"{home}/script.js"


class TestRunCommandEvidence:
    """Tests for the run_command field (adapter-wrapped argv)."""

    def test_run_command_absent_when_identical_to_command(self) -> None:
        """When run_command is the same as command, it is not included."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo", "hi"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
            run_command=["echo", "hi"],
        )
        assert "run_command" not in result
    def test_run_command_absent_when_omitted(self) -> None:
        """Backward compat: run_command defaults to None and is not included."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo", "hi"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        assert "run_command" not in result

    def test_run_command_present_when_differs(self) -> None:
        """When run_command differs from command, it is included."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["claude"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
            run_command=["claude", "--plugin-dir", "/tmp/plugin"],
        )
        assert result["run_command"] == ["claude", "--plugin-dir", "/tmp/plugin"]
        assert result["command"] == ["claude"]

    def test_run_command_redacted_in_result_dict(self) -> None:
        """run_command with local paths is redacted when redact_paths=True."""
        import os

        home = os.path.expanduser("~")
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="claude-code",
            via="claude-code",
            proxy_url="http://127.0.0.1:1",
            home=home,
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": ["claude"],
                "run_command": [
                    "claude",
                    "--plugin-dir",
                    f"{home}/.local/share/ardur/plugin",
                ],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        d = result.to_result_dict(redact_paths=True)
        rc = d["process_lifecycle"]["run_command"]
        assert home not in rc[2], f"Home path leaked in run_command: {rc[2]}"
        assert "<home>" in rc[2], f"Expected <home> placeholder, got {rc[2]}"

    def test_run_command_preserved_when_redact_off(self) -> None:
        """run_command is returned verbatim when redact_paths=False."""
        import os

        home = os.path.expanduser("~")
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="claude-code",
            via="claude-code",
            proxy_url="http://127.0.0.1:1",
            home=home,
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": ["claude"],
                "run_command": ["claude", "--plugin-dir", f"{home}/plugin"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        d = result.to_result_dict(redact_paths=False)
        rc = d["process_lifecycle"]["run_command"]
        assert rc[2] == f"{home}/plugin"


# ── cwd evidence tests ────────────────────────────────────────────────────────


class TestCwdEvidence:
    """Tests for the cwd field in process-lifecycle evidence."""

    def test_cwd_absent_when_omitted(self) -> None:
        """Backward compat: cwd defaults to None and is not included."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo", "hi"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        assert "cwd" not in result

    def test_cwd_present_when_provided(self) -> None:
        """When cwd is explicitly provided, it is captured."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo", "hi"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
            cwd="/home/user/project",
        )
        assert result["cwd"] == "/home/user/project"

    def test_cwd_is_string_type(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
            cwd="/tmp/work",
        )
        assert isinstance(result["cwd"], str)

    def test_cwd_preserved_with_none_command_difference(self) -> None:
        """cwd is independent of run_command presence."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["claude"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
            run_command=["claude", "--plugin-dir", "/tmp/p"],
            cwd="/home/user/work",
        )
        assert "run_command" in result
        assert result["cwd"] == "/home/user/work"


class TestCwdRedaction:
    """Tests for cwd path redaction in to_result_dict."""

    def test_cwd_redacted_when_redact_paths_true(self) -> None:
        """W3: cwd with local path must be redacted."""
        import os

        home = os.path.expanduser("~")
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home=home,
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": ["node", "script.js"],
                "cwd": f"{home}/secret/project",
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        d = result.to_result_dict(redact_paths=True)
        redacted_cwd = d["process_lifecycle"]["cwd"]
        assert home not in redacted_cwd, (
            f"Home path leaked in redacted cwd: {redacted_cwd}"
        )
        assert "<home>" in redacted_cwd, (
            f"Expected <home> placeholder, got {redacted_cwd}"
        )

    def test_cwd_preserved_when_redact_paths_false(self) -> None:
        """Without redact_paths, cwd is returned verbatim."""
        import os

        home = os.path.expanduser("~")
        original_cwd = f"{home}/project"
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home=home,
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": ["node", "script.js"],
                "cwd": original_cwd,
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        d = result.to_result_dict(redact_paths=False)
        assert d["process_lifecycle"]["cwd"] == original_cwd

    def test_cwd_absent_does_not_crash_redaction(self) -> None:
        """When process_lifecycle has no cwd key, redaction should not fail."""
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home="/tmp/x",
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": ["echo", "hi"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        d = result.to_result_dict(redact_paths=True)
        assert "cwd" not in d["process_lifecycle"]


# ── format_summary tests ──────────────────────────────────────────────────────


class TestFormatSummaryLifecycle:
    def test_summary_includes_process_line_when_lifecycle_present(self) -> None:
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home="/tmp/x",
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
            process_lifecycle={
                "root_pid": 4242,
                "command": ["echo"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.5,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
            },
        )
        text = format_summary(result)
        assert "process" in text
        assert "4242" in text
        assert "host-observer" in text

    def test_summary_omits_process_line_when_lifecycle_empty(self) -> None:
        result = GovernanceRunResult(
            exit_code=0,
            session_id="s1",
            mission_id="m1",
            agent_id="a1",
            adapter="env",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home="/tmp/x",
            passport_path="/tmp/x/p.jwt",
            summary={},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="t",
            attestation_digest="d",
            receipts_path="/tmp/r.jsonl",
            receipt_count=0,
            correlation={},
            kernel_policy={},
        )
        text = format_summary(result)
        assert "process" not in text


# ── Integration: run_governed with a real command ─────────────────────────────


class TestRunGovernedLifecycleIntegration:
    """End-to-end: ``run_governed`` with a real ``echo`` command."""

    def test_echo_command_produces_lifecycle_evidence(self) -> None:
        from vibap.run_bridge import run_governed

        result = run_governed(
            command=["echo", "hello"],
            mission="test mission",
            allowed_tools=[],
            forbidden_tools=[],
            via="env",
            max_duration_s=10,
        )
        pl = result.process_lifecycle
        assert pl["root_pid"] is not None
        assert pl["root_pid"] > 0
        assert pl["command"] == ["echo", "hello"]
        assert pl["exit_code"] == 0
        assert pl["exit_signal"] is None
        assert pl["capture_tier"] == "host-observer"
        assert pl["wall_clock_s"] > 0
        assert "root-process lifecycle only" in pl["capture_boundary"]

    def test_failing_command_captures_nonzero_exit(self) -> None:
        from vibap.run_bridge import run_governed

        result = run_governed(
            command=["sh", "-c", "exit 3"],
            mission="test",
            allowed_tools=[],
            forbidden_tools=[],
            via="env",
            max_duration_s=10,
        )
        pl = result.process_lifecycle
        assert pl["exit_code"] == 3
        assert pl["exit_signal"] is None

    def test_lifecycle_in_json_result_dict(self) -> None:
        from vibap.run_bridge import run_governed

        result = run_governed(
            command=["echo", "json-test"],
            mission="test",
            allowed_tools=[],
            forbidden_tools=[],
            via="env",
            max_duration_s=10,
        )
        d = result.to_result_dict()
        assert "process_lifecycle" in d
        pl = d["process_lifecycle"]
        assert pl["root_pid"] is not None
        assert pl["capture_tier"] == "host-observer"
        # Ensure the JSON is serializable
        json.dumps(d)

    def test_started_at_has_sane_year(self) -> None:
        """Integration regression: started_at must not be a 1970 date."""
        from vibap.run_bridge import run_governed

        result = run_governed(
            command=["echo", "year-check"],
            mission="test",
            allowed_tools=[],
            forbidden_tools=[],
            via="env",
            max_duration_s=10,
        )
        pl = result.process_lifecycle
        ts = pl["started_at"]
        year = int(ts.split("-")[0])
        assert year >= 2024, (
            f"Integration started_at year={year} is implausible; got {ts}. "
            "Monotonic clock may have been used instead of wall clock."
        )

    def test_run_command_absent_for_env_adapter(self) -> None:
        """via=env: command == run_command, so run_command is not included."""
        from vibap.run_bridge import run_governed

        result = run_governed(
            command=["echo", "env-check"],
            mission="test",
            allowed_tools=[],
            forbidden_tools=[],
            via="env",
            max_duration_s=10,
        )
        pl = result.process_lifecycle
        assert pl["command"] == ["echo", "env-check"]
        assert "run_command" not in pl, (
            "run_command should not appear when identical to command "
            f"(via=env), got keys: {sorted(pl)}"
        )

    def test_cwd_captured_in_lifecycle_evidence(self) -> None:
        """Integration: run_governed captures the resolved cwd."""
        from vibap.run_bridge import run_governed

        result = run_governed(
            command=["echo", "cwd-check"],
            mission="test",
            allowed_tools=[],
            forbidden_tools=[],
            via="env",
            max_duration_s=10,
        )
        pl = result.process_lifecycle
        assert "cwd" in pl, (
            f"cwd should be in process_lifecycle, got keys: {sorted(pl)}"
        )
        assert isinstance(pl["cwd"], str)
        assert len(pl["cwd"]) > 0

    def test_cwd_captures_explicit_workdir(self) -> None:
        """Integration: explicit cwd parameter is reflected in lifecycle evidence."""
        import tempfile

        from pathlib import Path

        from vibap.run_bridge import run_governed

        explicit_cwd = Path(tempfile.mkdtemp(prefix="ardur-cwd-test-"))
        try:
            result = run_governed(
                command=["echo", "explicit-cwd"],
                mission="test",
                allowed_tools=[],
                forbidden_tools=[],
                via="env",
                max_duration_s=10,
                cwd=explicit_cwd,
            )
            pl = result.process_lifecycle
            assert pl["cwd"] == str(explicit_cwd.resolve())
        finally:
            import shutil

            shutil.rmtree(str(explicit_cwd), ignore_errors=True)

    def test_cwd_redacted_with_redact_paths(self) -> None:
        """Integration: cwd is redacted when redact_paths=True."""
        import os

        from vibap.run_bridge import run_governed

        result = run_governed(
            command=["echo", "redact-cwd"],
            mission="test",
            allowed_tools=[],
            forbidden_tools=[],
            via="env",
            max_duration_s=10,
        )
        d = result.to_result_dict(redact_paths=True)
        pl = d["process_lifecycle"]
        assert "cwd" in pl
        home = os.path.expanduser("~")
        assert home not in pl["cwd"], (
            f"Home path leaked in redacted cwd: {pl['cwd']}"
        )

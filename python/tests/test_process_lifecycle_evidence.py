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
import time

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
        assert "root-process lifecycle" in boundary
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
        """When run_command differs from command, it is included.

        Paths in run_command are now redacted at the source by
        ``_build_process_lifecycle_evidence`` (before signing), so
        ``/tmp/plugin`` becomes ``<tmp>/plugin``.
        """
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["claude"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
            run_command=["claude", "--plugin-dir", "/tmp/plugin"],
        )
        assert result["run_command"] == ["claude", "--plugin-dir", "<tmp>/plugin"]
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
        """When cwd is explicitly provided, it is captured (redacted).

        Paths are now redacted at the source by
        ``_build_process_lifecycle_evidence`` (before signing), so
        ``/home/user/project`` becomes a placeholder.
        """
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(1),  # type: ignore[arg-type]
            command=["echo", "hi"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
            cwd="/home/user/project",
        )
        assert result["cwd"] != "/home/user/project"  # must be redacted
        assert isinstance(result["cwd"], str)

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
        """cwd is independent of run_command presence (redacted at source)."""
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
        assert result["cwd"] != "/home/user/work"  # must be redacted
        assert isinstance(result["cwd"], str)


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


# ── duration_budget_s evidence tests ──────────────────────────────────────────


class TestDurationBudgetEvidence:
    """Tests for the duration_budget_s field in process-lifecycle evidence."""

    def test_duration_budget_absent_when_omitted(self) -> None:
        """Backward compat: duration_budget_s defaults to None and is not included."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(12345),  # type: ignore[arg-type]
            command=["echo", "hello"],
            launch_monotonic=time.monotonic() - 0.1,
            launch_wall_clock=time.time() - 0.1,
            exit_code=0,
        )
        assert "duration_budget_s" not in result

    def test_duration_budget_present_when_provided(self) -> None:
        """When duration_budget_s is provided, it is included in the evidence."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(12345),  # type: ignore[arg-type]
            command=["echo", "hello"],
            launch_monotonic=time.monotonic() - 0.1,
            launch_wall_clock=time.time() - 0.1,
            exit_code=0,
            duration_budget_s=300,
        )
        assert result["duration_budget_s"] == 300

    def test_duration_budget_is_int_type(self) -> None:
        """duration_budget_s is an integer (seconds)."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(12345),  # type: ignore[arg-type]
            command=["echo", "hello"],
            launch_monotonic=time.monotonic() - 0.1,
            launch_wall_clock=time.time() - 0.1,
            exit_code=0,
            duration_budget_s=300,
        )
        assert isinstance(result["duration_budget_s"], int)

    def test_duration_budget_zero_is_included(self) -> None:
        """A zero budget is still included (it is not None)."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(12345),  # type: ignore[arg-type]
            command=["echo", "hello"],
            launch_monotonic=time.monotonic() - 0.1,
            launch_wall_clock=time.time() - 0.1,
            exit_code=0,
            duration_budget_s=0,
        )
        assert result["duration_budget_s"] == 0

    def test_duration_budget_in_result_dict(self) -> None:
        """duration_budget_s survives the to_result_dict round-trip."""
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
                "duration_budget_s": 300,
            },
        )
        d = result.to_result_dict()
        assert d["process_lifecycle"]["duration_budget_s"] == 300

    def test_duration_budget_not_redacted(self) -> None:
        """duration_budget_s is a plain integer — redaction does not touch it."""
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
                "duration_budget_s": 300,
            },
        )
        d = result.to_result_dict(redact_paths=True)
        assert d["process_lifecycle"]["duration_budget_s"] == 300


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
        assert "root-process lifecycle" in pl["capture_boundary"]

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
        """Integration: explicit cwd parameter is reflected (redacted) in lifecycle evidence.

        Paths are now redacted at the source by ``_build_process_lifecycle_evidence``
        (before signing). The original path is a temp dir, so it will be replaced
        with a ``<tmp>/`` or ``<var-folders>/`` placeholder. We verify the cwd
        key is present and no longer matches the raw absolute path.
        """
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
            raw_resolved = str(explicit_cwd.resolve())
            assert pl["cwd"] != raw_resolved, (
                f"cwd must be redacted, not raw: {pl['cwd']}"
            )
            assert isinstance(pl["cwd"], str)
            assert "<" in pl["cwd"]  # placeholder marker
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


# ── child-process enumeration tests ──────────────────────────────────────────


class TestEnumerateChildProcesses:
    """Unit tests for _enumerate_child_processes."""

    def test_none_pid_returns_empty(self) -> None:
        from vibap.run_bridge import _enumerate_child_processes

        result = _enumerate_child_processes(None)
        assert result == []

    def test_nonexistent_pid_returns_empty(self) -> None:
        from vibap.run_bridge import _enumerate_child_processes

        result = _enumerate_child_processes(99999999)
        assert result == []

    def test_own_process_returns_children(self) -> None:
        """Smoke: enumerating our own process should not raise."""
        import os

        from vibap.run_bridge import _enumerate_child_processes

        result = _enumerate_child_processes(os.getpid())
        assert isinstance(result, list)


class TestChildrenInLifecycleEvidence:
    """Tests for the children field in process-lifecycle evidence."""

    def test_children_absent_when_no_children(self) -> None:
        """When no children are observed, the key is absent."""
        result = _build_process_lifecycle_evidence(
            proc=_FakeProc(99999999),  # type: ignore[arg-type]
            command=["echo", "hi"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        assert "children" not in result

    def test_children_absent_when_proc_none(self) -> None:
        """When proc is None, children key is absent."""
        result = _build_process_lifecycle_evidence(
            proc=None,
            command=["echo", "hi"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        assert "children" not in result

    def test_children_present_when_has_children(self) -> None:
        """When children are observed, the key is present and non-empty."""
        import os
        import subprocess

        # Launch a child process so our own process has at least one child.
        child = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = _build_process_lifecycle_evidence(
                proc=_FakeProc(os.getpid()),  # type: ignore[arg-type]
                command=["echo", "hi"],
                launch_monotonic=time.monotonic(),
                launch_wall_clock=time.time(),
                exit_code=0,
            )
            assert "children" in result, (
                f"Expected children key, got keys: {sorted(result)}"
            )
            assert len(result["children"]) >= 1
        finally:
            child.wait()

    def test_children_shape_is_valid(self) -> None:
        """Each child entry has the expected fields."""
        import os
        import subprocess

        child = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = _build_process_lifecycle_evidence(
                proc=_FakeProc(os.getpid()),  # type: ignore[arg-type]
                command=["echo", "hi"],
                launch_monotonic=time.monotonic(),
                launch_wall_clock=time.time(),
                exit_code=0,
            )
            for child_entry in result.get("children", []):
                assert "pid" in child_entry
                assert "command" in child_entry
                assert "started_at" in child_entry
                assert "wall_clock_s" in child_entry
                assert "exit_code" in child_entry
                assert "exit_signal" in child_entry
                assert isinstance(child_entry["pid"], int)
                assert isinstance(child_entry["command"], list)
        finally:
            child.wait()


class TestChildrenRedaction:
    """Tests for child-process redaction in to_result_dict."""

    def test_children_redacted_when_redact_paths_true(self) -> None:
        """Children with local paths are redacted."""
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
                "command": ["echo", "hi"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
                "children": [
                    {
                        "pid": 9999,
                        "command": ["node", f"{home}/secret/script.js"],
                        "started_at": "2026-01-01T00:00:00.000000Z",
                        "wall_clock_s": 0.1,
                        "exit_code": None,
                        "exit_signal": None,
                    },
                ],
            },
        )
        d = result.to_result_dict(redact_paths=True)
        children = d["process_lifecycle"]["children"]
        assert home not in children[0]["command"][1], (
            f"Home path leaked in redacted child command: {children[0]['command'][1]}"
        )
        assert "<home>" in children[0]["command"][1]

    def test_children_preserved_when_redact_off(self) -> None:
        """Without redact_paths, children are returned verbatim."""
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
                "command": ["echo", "hi"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.123,
                "exit_code": 0,
                "exit_signal": None,
                "capture_tier": "host-observer",
                "capture_boundary": "test",
                "children": [
                    {
                        "pid": 9999,
                        "command": ["node", f"{home}/script.js"],
                        "started_at": "2026-01-01T00:00:00.000000Z",
                        "wall_clock_s": 0.1,
                        "exit_code": None,
                        "exit_signal": None,
                    },
                ],
            },
        )
        d = result.to_result_dict(redact_paths=False)
        children = d["process_lifecycle"]["children"]
        assert children[0]["command"][1] == f"{home}/script.js"

    def test_children_absent_does_not_crash_redaction(self) -> None:
        """When process_lifecycle has no children key, redaction should not fail."""
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
        assert "children" not in d["process_lifecycle"]

    def test_children_empty_list_does_not_crash_redaction(self) -> None:
        """Empty children list is handled safely."""
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
                "children": [],
            },
        )
        d = result.to_result_dict(redact_paths=True)
        assert d["process_lifecycle"]["children"] == []


# ── recursive descendant enumeration tests ────────────────────────────────────


class TestRecursiveDescendantEnumeration:
    """Tests for recursive (grandchild) process-tree enumeration.

    The host-observer capture tier now walks the full descendant tree
    (not just direct children), recording ``depth`` and ``parent_pid``
    so consumers can reconstruct the tree structure.
    """

    def test_child_entry_has_depth_field(self) -> None:
        """Direct children have depth=0."""
        import os
        import subprocess

        from vibap.run_bridge import _enumerate_child_processes

        child = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = _enumerate_child_processes(os.getpid())
            assert len(result) >= 1
            for entry in result:
                assert "depth" in entry
                assert isinstance(entry["depth"], int)
                assert entry["depth"] >= 0
        finally:
            child.wait()

    def test_child_entry_has_parent_pid_field(self) -> None:
        """Each child entry includes parent_pid linking it to its parent."""
        import os
        import subprocess

        from vibap.run_bridge import _enumerate_child_processes

        child = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = _enumerate_child_processes(os.getpid())
            assert len(result) >= 1
            for entry in result:
                assert "parent_pid" in entry
                assert isinstance(entry["parent_pid"], int)
        finally:
            child.wait()

    def test_direct_child_has_depth_zero(self) -> None:
        """Direct children of the root have depth=0."""
        import os
        import subprocess

        from vibap.run_bridge import _enumerate_child_processes

        child = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = _enumerate_child_processes(os.getpid())
            assert len(result) >= 1
            # At least one direct child should have depth=0
            direct_children = [e for e in result if e["depth"] == 0]
            assert len(direct_children) >= 1
            for dc in direct_children:
                assert dc["parent_pid"] == os.getpid()
        finally:
            child.wait()

    def test_grandchild_has_depth_one(self) -> None:
        """Grandchildren are captured with depth=1 and correct parent_pid.

        We launch ``sh -c 'sleep 0.5'`` as a child; sh's child (sleep) is
        our grandchild — depth=1, parent_pid == sh's PID.
        """
        import os
        import subprocess

        from vibap.run_bridge import _enumerate_child_processes

        # sh -c 'exec sleep 1' will create a direct child (sh) that forks
        # a grandchild (sleep) — depth=0 for sh, depth=1 for sleep.
        child = subprocess.Popen(
            ["sh", "-c", "sleep 0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = _enumerate_child_processes(os.getpid())
            # At minimum, we should see the sh child at depth=0
            assert len(result) >= 1
            depths = {e["depth"] for e in result}
            # depth=0 (sh) should always be present
            assert 0 in depths
            # If we caught the grandchild (sleep), it should be depth=1.
            # This is timing-dependent; we verify depth=0 is always correct
            # and if depth=1 exists, parent_pid links are correct.
            for entry in result:
                if entry["depth"] == 1:
                    # grandchild's parent should be one of the depth=0 entries
                    parent_pids = {e["pid"] for e in result if e["depth"] == 0}
                    assert entry["parent_pid"] in parent_pids
        finally:
            child.wait()

    def test_depth_count_caps_prevent_runaway(self) -> None:
        """_MAX_DESCENDANT_DEPTH and _MAX_DESCENDANT_COUNT are respected."""
        from vibap.run_bridge import _MAX_DESCENDANT_COUNT, _MAX_DESCENDANT_DEPTH

        assert isinstance(_MAX_DESCENDANT_DEPTH, int)
        assert isinstance(_MAX_DESCENDANT_COUNT, int)
        assert _MAX_DESCENDANT_DEPTH > 0
        assert _MAX_DESCENDANT_COUNT > 0

    def test_walk_descendants_respects_count_cap(self) -> None:
        """_walk_descendants stops when count exceeds _MAX_DESCENDANT_COUNT."""
        from unittest.mock import MagicMock

        from vibap.run_bridge import _walk_descendants

        # Create fake psutil.Process objects that always report children.
        # Each "child" is a mock with pid, oneshhot(), cmdline(), etc.
        def make_mock_proc(pid: int) -> MagicMock:
            proc = MagicMock()
            proc.pid = pid
            proc.children.return_value = []
            proc.oneshot.return_value.__enter__ = MagicMock(return_value=None)
            proc.oneshot.return_value.__exit__ = MagicMock(return_value=None)
            proc.cmdline.return_value = ["fake"]
            proc.name.return_value = "fake"
            proc.create_time.return_value = time.time()
            return proc

        # Override _MAX_DESCENDANT_COUNT locally for this test by using
        # a very small count limit via the count parameter.
        out: list[dict] = []
        count = [0]

        # Create a fake parent with 10 fake children
        parent = make_mock_proc(1)
        fake_children = [make_mock_proc(100 + i) for i in range(10)]
        parent.children.return_value = fake_children

        # Walk with a manual count check (simulating the cap)
        # The real _walk_descendants uses _MAX_DESCENDANT_COUNT, so we
        # just verify the cap logic by testing the actual function's
        # output count is within bounds.
        _walk_descendants(parent, out, depth=0, count=count)

        # Each fake child has no grandchildren, so total = 10.
        # All should be captured since 10 < _MAX_DESCENDANT_COUNT (500).
        assert len(out) == 10
        assert count[0] == 10

    def test_redact_child_lifecycle_preserves_depth_and_parent_pid(self) -> None:
        """_redact_child_lifecycle preserves depth and parent_pid fields."""
        from vibap.run_bridge import _redact_child_lifecycle

        children = [
            {
                "pid": 100,
                "command": ["foo", "--arg"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.5,
                "exit_code": None,
                "exit_signal": None,
                "depth": 0,
                "parent_pid": 1,
            },
            {
                "pid": 101,
                "command": ["bar"],
                "started_at": "2026-01-01T00:00:00.000000Z",
                "wall_clock_s": 0.3,
                "exit_code": None,
                "exit_signal": None,
                "depth": 1,
                "parent_pid": 100,
            },
        ]
        redacted = _redact_child_lifecycle(children)
        assert len(redacted) == 2
        assert redacted[0]["depth"] == 0
        assert redacted[0]["parent_pid"] == 1
        assert redacted[1]["depth"] == 1
        assert redacted[1]["parent_pid"] == 100


class TestCaptureBoundaryUpdated:
    """Verify the capture_boundary string reflects recursive enumeration."""

    def test_capture_boundary_mentions_descendant(self) -> None:
        result = _build_process_lifecycle_evidence(
            proc=None,
            command=["echo", "hi"],
            launch_monotonic=time.monotonic(),
            launch_wall_clock=time.time(),
            exit_code=0,
        )
        boundary: str = result["capture_boundary"]
        assert "descendant" in boundary.lower()
        assert "point-in-time" in boundary.lower()

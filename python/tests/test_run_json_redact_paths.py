"""Tests for ``ardur run --json --redact-paths`` local path redaction.

The ``--json`` output of ``ardur run`` includes local absolute paths
(``home``, ``receipts_path``, ``passport_path``, and paths inside
``correlation``).  When ``--redact-paths`` is set, these are replaced
with stable placeholders so the JSON is safe to share in CI artifacts
or bug reports without leaking the user's filesystem layout.
"""

from __future__ import annotations

import os
import tempfile
from argparse import Namespace

import pytest
from vibap.run_bridge import (
    GovernanceRunResult,
    _redact_local_path,
    run_governed_cli,
)


def _make_result(**overrides) -> GovernanceRunResult:
    """Build a minimal GovernanceRunResult for testing."""
    defaults: dict[str, object] = {
        "exit_code": 0,
        "session_id": "test-session-id",
        "mission_id": "test-mission-id",
        "agent_id": "test-agent",
        "adapter": "env-proxy",
        "via": "auto",
        "proxy_url": "http://127.0.0.1:9999",
        "home": "/tmp/ardur-home",
        "passport_path": "/tmp/ardur-home/active_mission.jwt",
        "summary": {},
        "permits": 0,
        "denials": 0,
        "total_events": 0,
        "attestation_token": "dummy-token",
        "attestation_digest": "sha-256:abc123",
        "receipts_path": "/tmp/ardur-home/receipts.jsonl",
        "receipt_count": 0,
        "correlation": {},
        "kernel_policy": {},
    }
    defaults.update(overrides)
    return GovernanceRunResult(**defaults)


# ── _redact_local_path unit tests ─────────────────────────────────────────────


class TestRedactLocalPath:
    def test_none_returns_none(self):
        assert _redact_local_path(None) is None

    def test_empty_string_passthrough(self):
        assert _redact_local_path("") == ""

    def test_relative_path_passthrough(self):
        assert _redact_local_path("relative/path") == "relative/path"

    def test_tmp_dir_redacted(self):
        tmp = tempfile.gettempdir()
        result = _redact_local_path(f"{tmp}/ardur-home/receipts.jsonl")
        assert tmp not in result
        assert "<tmp>" in result
        assert result.endswith("/ardur-home/receipts.jsonl")

    def test_home_dir_redacted(self):
        home = os.path.expanduser("~")
        result = _redact_local_path(f"{home}/.ardur/receipts.jsonl")
        assert home not in result
        assert "<home>" in result

    def test_private_var_folders_redacted(self):
        result = _redact_local_path(
            "/private/var/folders/abc/def/com.example.ardur/receipts.jsonl"
        )
        assert "/private/var/folders/" not in result
        assert "<var-folders>/" in result

    def test_run_ardur_redacted(self):
        result = _redact_local_path("/run/ardur/kernelcapture/control.sock")
        assert result == "<run-ardur>/kernelcapture/control.sock"

    def test_private_tmp_redacted(self):
        """macOS resolves /tmp → /private/tmp."""
        result = _redact_local_path("/private/tmp/ardur-home/receipts.jsonl")
        assert "/private/tmp/" not in result
        assert "<tmp>/" in result

    def test_bare_tmp_redacted(self):
        result = _redact_local_path("/tmp/ardur-home/receipts.jsonl")
        assert "/tmp/" not in result
        assert "<tmp>/" in result

    def test_cgroup_path_redacted(self):
        result = _redact_local_path("/sys/fs/cgroup/ardur/session-abc")
        assert result == "<cgroup>/ardur/session-abc"

    def test_unknown_absolute_path_passthrough(self):
        """Paths under non-standard roots are not redacted."""
        result = _redact_local_path("/opt/ardur/receipts.jsonl")
        assert result == "/opt/ardur/receipts.jsonl"


# ── GovernanceRunResult.to_result_dict(redact_paths=...) tests ─────────────────


class TestToResultDictRedaction:
    def test_default_no_redaction(self):
        """Without redact_paths, absolute paths pass through unchanged."""
        result = _make_result(
            home="/tmp/ardur-home",
            passport_path="/tmp/ardur-home/active_mission.jwt",
            receipts_path="/tmp/ardur-home/receipts.jsonl",
        )
        d = result.to_result_dict()
        assert d["home"] == "/tmp/ardur-home"
        assert d["passport_path"] == "/tmp/ardur-home/active_mission.jwt"
        assert d["receipts_path"] == "/tmp/ardur-home/receipts.jsonl"

    def test_redact_paths_replaces_home_receipts_passport(self):
        """With redact_paths=True, local paths become placeholders."""
        tmp = tempfile.gettempdir()
        result = _make_result(
            home=f"{tmp}/ardur-home",
            passport_path=f"{tmp}/ardur-home/active_mission.jwt",
            receipts_path=f"{tmp}/ardur-home/receipts.jsonl",
        )
        d = result.to_result_dict(redact_paths=True)
        assert tmp not in d["home"]
        assert tmp not in d["passport_path"]
        assert tmp not in d["receipts_path"]
        assert "<tmp>" in d["home"]
        assert "<tmp>" in d["passport_path"]
        assert "<tmp>" in d["receipts_path"]

    def test_redact_paths_replaces_correlation_daemon_socket(self):
        """daemon_socket inside correlation is redacted when set."""
        tmp = tempfile.gettempdir()
        result = _make_result(
            correlation={
                "available": False,
                "daemon_socket": f"{tmp}/ardur-daemon/control.sock",
                "cgroup_path": None,
            }
        )
        d = result.to_result_dict(redact_paths=True)
        assert tmp not in d["correlation"]["daemon_socket"]
        assert "<tmp>" in d["correlation"]["daemon_socket"]

    def test_redact_paths_replaces_correlation_cgroup_path(self):
        """cgroup_path inside correlation is redacted when set."""
        result = _make_result(
            correlation={
                "available": True,
                "cgroup_path": "/sys/fs/cgroup/ardur/session-123",
                "daemon_socket": "/run/ardur/control.sock",
            }
        )
        d = result.to_result_dict(redact_paths=True)
        assert "/sys/fs/cgroup/" not in d["correlation"]["cgroup_path"]
        assert "<run-ardur>/" in d["correlation"]["daemon_socket"]

    def test_redact_paths_preserves_none_correlation_fields(self):
        """None values in correlation are left as None after redaction."""
        result = _make_result(
            correlation={
                "available": False,
                "daemon_socket": "/run/ardur/control.sock",
                "cgroup_path": None,
            }
        )
        d = result.to_result_dict(redact_paths=True)
        assert d["correlation"]["cgroup_path"] is None
        assert "<run-ardur>/" in d["correlation"]["daemon_socket"]

    def test_redact_paths_preserves_non_path_fields(self):
        """Non-path fields are unchanged by redaction."""
        result = _make_result()
        d = result.to_result_dict(redact_paths=True)
        assert d["ok"] is True
        assert d["exit_code"] == 0
        assert d["session_id"] == "test-session-id"
        assert d["mission_id"] == "test-mission-id"
        assert d["agent_id"] == "test-agent"
        assert d["adapter"] == "env-proxy"
        assert d["via"] == "auto"
        assert d["permits"] == 0
        assert d["denials"] == 0
        assert d["receipt_count"] == 0
        assert d["attestation_digest"] == "sha-256:abc123"

    def test_redact_paths_does_not_mutate_original_result(self):
        """Redaction should not mutate the original GovernanceRunResult fields."""
        tmp = tempfile.gettempdir()
        result = _make_result(
            home=f"{tmp}/ardur-home",
            receipts_path=f"{tmp}/ardur-home/receipts.jsonl",
        )
        # Before redaction.
        assert result.home == f"{tmp}/ardur-home"
        # Redacted output.
        d_redacted = result.to_result_dict(redact_paths=True)
        assert tmp not in d_redacted["home"]
        # Original is untouched.
        assert result.home == f"{tmp}/ardur-home"
        # Non-redacted output is still correct.
        d_plain = result.to_result_dict()
        assert d_plain["home"] == f"{tmp}/ardur-home"

    def test_redact_with_empty_correlation(self):
        """Empty correlation dict does not cause errors during redaction."""
        result = _make_result(correlation={})
        d = result.to_result_dict(redact_paths=True)
        assert d["correlation"] == {}

    def test_redact_does_not_touch_kernel_policy(self):
        """kernel_policy is not redacted (it contains no local paths)."""
        kernel = {"applied": False, "reason": "cgroup unavailable", "tier2_ops": []}
        result = _make_result(kernel_policy=kernel)
        d = result.to_result_dict(redact_paths=True)
        assert d["kernel_policy"] == kernel

    def test_no_local_path_leak_in_redacted_output(self):
        """Comprehensive check: no temp, home, or var/folders root leaks."""
        tmp = tempfile.gettempdir()
        home = os.path.expanduser("~")
        result = _make_result(
            home=f"{tmp}/ardur-home",
            passport_path=f"{tmp}/ardur-home/active_mission.jwt",
            receipts_path=f"{tmp}/ardur-home/receipts.jsonl",
            correlation={
                "daemon_socket": f"{tmp}/ardur/control.sock",
                "cgroup_path": None,
            },
        )
        d = result.to_result_dict(redact_paths=True)
        # Serialize to JSON and check no raw local root appears.
        import json

        raw = json.dumps(d)
        assert tmp not in raw
        assert home not in raw
        assert "/private/var/folders/" not in raw


# ── run_governed_cli --redact-paths without --json warning tests ──────────────


def _base_args(**overrides: object) -> Namespace:
    """Build a minimal Namespace accepted by run_governed_cli."""
    defaults: dict[str, object] = {
        "command": ["echo", "hello"],
        "mission": "test mission",
        "allowed_tools": None,
        "forbidden_tools": None,
        "max_tool_calls": None,
        "max_duration_s": 10,
        "home": None,
        "via": "auto",
        "no_kernel_correlation": False,
        "enforce": False,
        "resource_scope": None,
        "no_resource_scope": False,
        "json": False,
        "redact_paths": False,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


class TestRedactPathsWithoutJsonWarning:
    """``--redact-paths`` without ``--json`` must warn on stderr."""

    def test_warning_fires_when_redact_paths_without_json(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Passing --redact-paths without --json emits the warning on stderr."""
        fake_result = _make_result()

        def fake_run_governed(**kwargs: object) -> GovernanceRunResult:
            return fake_result

        monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

        args = _base_args(redact_paths=True, json=False)
        exit_code = run_governed_cli(args)
        assert exit_code == 0

        captured = capsys.readouterr()
        # Warning must appear on stderr, not stdout.
        assert "--redact-paths has no effect without --json" in captured.err
        assert captured.out == ""

    def test_no_warning_when_both_redact_paths_and_json(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--json --redact-paths must NOT emit the no-effect warning."""
        fake_result = _make_result()

        def fake_run_governed(**kwargs: object) -> GovernanceRunResult:
            return fake_result

        monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

        args = _base_args(redact_paths=True, json=True)
        exit_code = run_governed_cli(args)
        assert exit_code == 0

        captured = capsys.readouterr()
        assert "--redact-paths has no effect without --json" not in captured.err
        assert captured.out == ""

    def test_no_warning_when_neither_flag(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Plain ``ardur run`` (no --redact-paths) must NOT emit the warning."""
        fake_result = _make_result()

        def fake_run_governed(**kwargs: object) -> GovernanceRunResult:
            return fake_result

        monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

        args = _base_args(redact_paths=False, json=False)
        exit_code = run_governed_cli(args)
        assert exit_code == 0

        captured = capsys.readouterr()
        assert "--redact-paths has no effect without --json" not in captured.err

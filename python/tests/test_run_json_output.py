"""Tests for ``ardur run --json`` machine-readable governance output.

The ``--json`` flag emits the :class:`~vibap.run_bridge.GovernanceRunResult`
as structured JSON on **stderr** so CI pipelines and programmatic consumers can
consume governance results (session id, permits/denials, attestation digest,
receipt paths) without parsing human-readable summary text. stdout is reserved
for the child process's own output so pipe chains like
``ardur run --json -- pytest 2>governance.json`` work cleanly.
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest
from vibap.run_bridge import (
    GovernanceRunResult,
    run_governed_cli,
)


def _make_result(**overrides: object) -> GovernanceRunResult:
    """Build a minimal GovernanceRunResult with sensible defaults."""
    defaults: dict[str, object] = {
        "exit_code": 0,
        "session_id": "test-session-id",
        "mission_id": "mission:local-user:ardur-run:test",
        "agent_id": "local-user:ardur-run",
        "adapter": "env-proxy",
        "via": "auto",
        "proxy_url": "http://127.0.0.1:9999",
        "home": "/tmp/ardur-run-test",
        "passport_path": "/tmp/ardur-run-test/active_mission.jwt",
        "summary": {"permits": 1, "denials": 0, "total_events": 1},
        "permits": 1,
        "denials": 0,
        "total_events": 1,
        "attestation_token": "eyJ0.zzz.dummy",
        "attestation_digest": "sha-256:abcd1234",
        "receipts_path": "/tmp/ardur-run-test/receipts.jsonl",
        "receipt_count": 1,
        "correlation": {"available": False, "reason": "test"},
        "kernel_policy": {"applied": False, "reason": "test"},
        "notes": ["test note"],
    }
    defaults.update(overrides)
    return GovernanceRunResult(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# to_result_dict unit tests
# ---------------------------------------------------------------------------


class TestToResultDict:
    """Unit tests for ``GovernanceRunResult.to_result_dict()``."""

    def test_returns_json_serialisable_dict(self) -> None:
        result = _make_result()
        d = result.to_result_dict()
        # Must be JSON-serialisable.
        json.dumps(d)

    def test_contains_all_expected_fields(self) -> None:
        result = _make_result()
        d = result.to_result_dict()
        expected_keys = {
            "ok",
            "exit_code",
            "session_id",
            "mission_id",
            "agent_id",
            "adapter",
            "via",
            "total_events",
            "permits",
            "denials",
            "receipt_count",
            "receipts_path",
            "attestation_digest",
            "home",
            "passport_path",
            "correlation",
            "kernel_policy",
            "process_lifecycle",
            "notes",
        }
        assert set(d.keys()) == expected_keys

    def test_ok_true_when_exit_code_zero(self) -> None:
        result = _make_result(exit_code=0)
        assert result.to_result_dict()["ok"] is True

    def test_ok_false_when_exit_code_nonzero(self) -> None:
        result = _make_result(exit_code=1)
        assert result.to_result_dict()["ok"] is False

    def test_ok_false_when_exit_code_is_127(self) -> None:
        result = _make_result(exit_code=127)
        assert result.to_result_dict()["ok"] is False

    def test_omits_attestation_token(self) -> None:
        """The JWT-like attestation token must not appear in JSON output."""
        result = _make_result(attestation_token="eyJsecret.token.here")
        d = result.to_result_dict()
        assert "attestation_token" not in d
        serialised = json.dumps(d)
        assert "eyJsecret" not in serialised

    def test_notes_are_copied_not_referenced(self) -> None:
        original_notes = ["note1", "note2"]
        result = _make_result(notes=original_notes)
        d = result.to_result_dict()
        assert d["notes"] == original_notes
        original_notes.append("note3")
        assert d["notes"] == ["note1", "note2"]

    def test_includes_kernel_policy_tier2_ops(self) -> None:
        """Nested dicts like kernel_policy pass through unchanged."""
        result = _make_result(
            kernel_policy={"applied": True, "tier2_ops": ["OP_NET_CONNECT"]}
        )
        d = result.to_result_dict()
        assert d["kernel_policy"]["tier2_ops"] == ["OP_NET_CONNECT"]

    def test_empty_notes_list(self) -> None:
        result = _make_result(notes=[])
        d = result.to_result_dict()
        assert d["notes"] == []

    def test_proxy_url_omitted_from_json(self) -> None:
        """proxy_url is internal and must not leak into JSON output."""
        result = _make_result(proxy_url="http://127.0.0.1:12345")
        d = result.to_result_dict()
        assert "proxy_url" not in d

    def test_summary_omitted_from_json(self) -> None:
        """The raw summary dict is internal; JSON uses its flattened fields."""
        result = _make_result(summary={"extra": "internal"})
        d = result.to_result_dict()
        assert "summary" not in d


# ---------------------------------------------------------------------------
# run_governed_cli --json integration
# ---------------------------------------------------------------------------


class TestRunGovernedCliJsonFlag:
    """Integration tests for ``run_governed_cli`` with ``--json``."""

    def test_json_flag_emits_json_to_stderr(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When --json is set, the result is JSON on stderr (stdout stays
        transparent for child process output)."""
        fake_result = _make_result(exit_code=0)

        def fake_run_governed(**kwargs: object) -> GovernanceRunResult:
            return fake_result

        monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

        args = Namespace(
            command=["echo", "hello"],
            mission="test mission",
            allowed_tools=None,
            forbidden_tools=None,
            max_tool_calls=None,
            max_duration_s=10,
            home=None,
            via="auto",
            no_kernel_correlation=False,
            enforce=False,
            resource_scope=None,
            no_resource_scope=False,
            json=True,
        )
        exit_code = run_governed_cli(args)
        assert exit_code == 0

        captured = capsys.readouterr()
        # stdout must be empty (reserved for child process output).
        assert captured.out == ""
        # stderr must contain valid JSON.
        parsed = json.loads(captured.err)
        assert parsed["ok"] is True
        assert parsed["session_id"] == "test-session-id"
        assert parsed["permits"] == 1

    def test_no_json_flag_emits_human_summary_to_stderr(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without --json, the human-readable summary goes to stderr."""
        fake_result = _make_result()

        def fake_run_governed(**kwargs: object) -> GovernanceRunResult:
            return fake_result

        monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

        args = Namespace(
            command=["echo", "hello"],
            mission="test mission",
            allowed_tools=None,
            forbidden_tools=None,
            max_tool_calls=None,
            max_duration_s=10,
            home=None,
            via="auto",
            no_kernel_correlation=False,
            enforce=False,
            resource_scope=None,
            no_resource_scope=False,
            json=False,
        )
        exit_code = run_governed_cli(args)
        assert exit_code == 0

        captured = capsys.readouterr()
        # stdout should be empty (human summary goes to stderr).
        assert captured.out == ""
        # stderr should contain the summary header.
        assert "Ardur governance summary" in captured.err

    def test_json_flag_preserves_exit_code(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit code from the result must propagate even with --json."""
        fake_result = _make_result(exit_code=42)

        def fake_run_governed(**kwargs: object) -> GovernanceRunResult:
            return fake_result

        monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

        args = Namespace(
            command=["echo", "hello"],
            mission="test mission",
            allowed_tools=None,
            forbidden_tools=None,
            max_tool_calls=None,
            max_duration_s=10,
            home=None,
            via="auto",
            no_kernel_correlation=False,
            enforce=False,
            resource_scope=None,
            no_resource_scope=False,
            json=True,
        )
        exit_code = run_governed_cli(args)
        assert exit_code == 42
        # Verify JSON is parseable on stderr even for non-zero exit codes.
        captured = capsys.readouterr()
        parsed = json.loads(captured.err)
        assert parsed["ok"] is False
        assert parsed["exit_code"] == 42

"""Tests for ardur run --json error paths on the legacy hub-streaming path.

The ``--json`` flag on ``ardur run`` was originally documented as
"governance path only", but users who pass ``--json`` without ``--mission``
hit the legacy hub-streaming path (``run_under_hub``), which emitted
human-readable error text to stderr instead of structured JSON.

These tests verify that when ``--json`` is set, all legacy hub error paths
emit structured JSON to stderr (not human text), keeping the stdout=child /
stderr=governance contract consistent across both paths.
"""

from __future__ import annotations

import argparse
import io
import json
from unittest.mock import patch

import pytest

from vibap.personal_hub import run_under_hub


def _make_args(
    *,
    command: list[str] | None = None,
    json_mode: bool = False,
    home: str | None = None,
    hub_url: str = "http://127.0.0.1:1",
    hub_token: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        command=command,
        json=json_mode,
        home=home,
        hub_url=hub_url,
        hub_token=hub_token,
    )


def _capture_stderr(args, monkeypatch) -> tuple[int, str]:
    """Run ``run_under_hub`` capturing stderr content."""
    stderr_buf = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr_buf)
    exit_code = run_under_hub(args)
    return exit_code, stderr_buf.getvalue()


class TestMissingCommandJsonError:
    """When ``--json`` is set and no command is given, emit structured JSON."""

    def test_json_mode_emits_json_error(self, monkeypatch):
        args = _make_args(json_mode=True, command=[])
        exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 2
        payload = json.loads(stderr)
        assert payload["ok"] is False
        assert payload["error"] == "missing_run_command"
        assert payload["condition"] == "missing_run_command"
        assert "next_steps" in payload
        assert isinstance(payload["next_steps"], list)
        assert len(payload["next_steps"]) > 0

    def test_non_json_mode_still_emits_human_text(self, monkeypatch):
        args = _make_args(json_mode=False, command=[])
        exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 2
        # Human-readable text, not parseable JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(stderr)
        assert "requires a command" in stderr


class TestEmptyHomeJsonError:
    """When ``--json`` is set and ``--home`` is empty, emit structured JSON."""

    def test_json_mode_emits_json_error(self, monkeypatch):
        args = _make_args(
            json_mode=True,
            command=["echo", "hi"],
            home="   ",
        )
        exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 2
        payload = json.loads(stderr)
        assert payload["ok"] is False
        assert payload["error"] == "home_arg_invalid"
        assert payload["condition"] == "home_arg_invalid"
        assert "next_steps" in payload

    def test_non_json_mode_still_emits_human_text(self, monkeypatch):
        args = _make_args(
            json_mode=False,
            command=["echo", "hi"],
            home="   ",
        )
        exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 2
        with pytest.raises(json.JSONDecodeError):
            json.loads(stderr)
        assert "non-empty" in stderr


class TestSessionStartFailureJsonError:
    """When ``--json`` is set and session start fails, emit structured JSON."""

    def test_json_mode_emits_json_error(self, monkeypatch):
        args = _make_args(
            json_mode=True,
            command=["echo", "hi"],
            hub_url="http://127.0.0.1:1",
        )
        mock_response = {"ok": False, "error": "hub_unavailable"}
        with patch("vibap.personal_hub.resolve_hub_token", return_value="fake-token"):
            with patch(
                "vibap.personal_hub.hub_request", return_value=mock_response
            ):
                exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 127
        payload = json.loads(stderr)
        assert payload["ok"] is False
        assert "error" in payload
        assert "condition" in payload
        assert "message" in payload
        assert "next_steps" in payload
        assert isinstance(payload["next_steps"], list)

    def test_non_json_mode_still_emits_human_text(self, monkeypatch):
        args = _make_args(
            json_mode=False,
            command=["echo", "hi"],
            hub_url="http://127.0.0.1:1",
        )
        mock_response = {"ok": False, "error": "hub_unavailable"}
        with patch("vibap.personal_hub.resolve_hub_token", return_value="fake-token"):
            with patch(
                "vibap.personal_hub.hub_request", return_value=mock_response
            ):
                exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 127
        with pytest.raises(json.JSONDecodeError):
            json.loads(stderr)


class TestPolicyCheckFailureJsonError:
    """When ``--json`` is set and policy check fails, emit structured JSON."""

    def test_json_mode_emits_json_error(self, monkeypatch):
        args = _make_args(
            json_mode=True,
            command=["echo", "hi"],
            hub_url="http://127.0.0.1:1",
        )
        start_ok = {"ok": True}
        check_fail = {"ok": False, "error": "hub_unavailable"}
        responses = iter([start_ok, check_fail])
        with patch("vibap.personal_hub.resolve_hub_token", return_value="fake-token"):
            with patch(
                "vibap.personal_hub.hub_request", side_effect=lambda *a, **kw: next(responses)
            ):
                exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 127
        payload = json.loads(stderr)
        assert payload["ok"] is False
        assert "error" in payload
        assert "condition" in payload
        assert "message" in payload
        assert "next_steps" in payload


class TestPolicyBlockedJsonError:
    """When ``--json`` is set and policy blocks the command, emit JSON."""

    def test_json_mode_emits_json_error(self, monkeypatch):
        args = _make_args(
            json_mode=True,
            command=["rm", "-rf", "/"],
            hub_url="http://127.0.0.1:1",
        )
        start_ok = {"ok": True}
        check_blocked = {
            "ok": True,
            "policy": {"verdict": "blocked"},
        }
        observe_ok = {"ok": True, "receipt": {"receipt_id": "abc123"}}
        responses = iter([start_ok, check_blocked, observe_ok])
        with patch("vibap.personal_hub.resolve_hub_token", return_value="fake-token"):
            with patch(
                "vibap.personal_hub.hub_request", side_effect=lambda *a, **kw: next(responses)
            ):
                exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 126
        payload = json.loads(stderr)
        assert payload["ok"] is False
        assert payload["error"] == "policy_blocked"
        assert payload["condition"] == "policy_blocked"
        assert "message" in payload
        assert payload.get("receipt", {}).get("receipt_id") == "abc123"


class TestNoCommandWithJsonDoesNotBreakNonJson:
    """Ensure the json_mode check doesn't accidentally affect non-json runs."""

    def test_non_json_missing_command_preserves_human_hint(self, monkeypatch):
        args = _make_args(json_mode=False, command=[])
        exit_code, stderr = _capture_stderr(args, monkeypatch)
        assert exit_code == 2
        assert "Next steps:" in stderr

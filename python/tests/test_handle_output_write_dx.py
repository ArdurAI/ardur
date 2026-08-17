"""Tests for enriched output-write-failed error responses from _handle_output_and_redact.

The ``_handle_output_and_redact`` helper writes JSON reports to ``--output`` files
for 9+ CLI commands (issue, anchor, attest, setup, status, doctor, uninstall,
protect-claude-code, doctor-claude-code, latency-gate-evaluate).  Previously, a
write failure produced a minimal response (``ok``, ``error``, ``detail`` only).
This test verifies the response now includes ``condition``, ``error_code``,
``message``, and ``next_steps``, matching the structured-error contract used by
the rest of the CLI (e.g. ``claude-code-report --output``).
"""

import argparse
import json
import os
import tempfile


def _make_args(output=None, json=False, redact_paths=False) -> argparse.Namespace:
    return argparse.Namespace(
        output=output,
        json=json,
        redact_paths=redact_paths,
    )


def test_output_write_failed_has_condition(capfd):
    """The error response must include a 'condition' field."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        _handle_output_and_redact(ns, {"ok": True}, command="issue")
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        assert result["ok"] is False
        assert "condition" in result
        assert result["condition"] == "issue_output_write_failed"
    finally:
        os.rmdir(d)


def test_output_write_failed_has_error_code(capfd):
    """The error response must include an 'error_code' field."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        _handle_output_and_redact(ns, {"ok": True}, command="anchor")
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        assert "error_code" in result
        assert result["error_code"] == "anchor_output_write_failed"
    finally:
        os.rmdir(d)


def test_output_write_failed_has_message(capfd):
    """The error response must include a human-readable 'message'."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        _handle_output_and_redact(ns, {"ok": True}, command="attest")
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        assert "message" in result
        assert "failed" in result["message"].lower()
    finally:
        os.rmdir(d)


def test_output_write_failed_has_next_steps(capfd):
    """The error response must include actionable 'next_steps'."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        _handle_output_and_redact(ns, {"ok": True}, command="setup")
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        assert "next_steps" in result
        assert len(result["next_steps"]) >= 1
        step = result["next_steps"][0]
        assert "action" in step
        assert "command" in step
        assert "detail" in step
        assert "ardur setup" in step["command"]
    finally:
        os.rmdir(d)


def test_output_write_failed_error_equals_condition(capfd):
    """The 'error' field must still be present and match 'condition'."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        _handle_output_and_redact(ns, {"ok": True}, command="status")
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        assert result["error"] == result["condition"]
        assert result["error"] == "status_output_write_failed"
    finally:
        os.rmdir(d)


def test_output_write_failed_for_doctor_command(capfd):
    """The enriched response must work for 'doctor' (multi-word via underscore)."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        _handle_output_and_redact(ns, {"ok": True}, command="doctor")
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        assert result["condition"] == "doctor_output_write_failed"
        # The command name in next_steps uses hyphens, not underscores.
        assert "ardur doctor" in result["next_steps"][0]["command"]
    finally:
        os.rmdir(d)


def test_output_write_failed_for_protect_claude_code(capfd):
    """The enriched response must work for 'protect_claude_code'."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        _handle_output_and_redact(
            ns, {"ok": True}, command="protect_claude_code"
        )
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        assert result["condition"] == "protect_claude_code_output_write_failed"
        # Multi-word command in next_steps uses hyphens.
        assert "ardur protect-claude-code" in result["next_steps"][0]["command"]
    finally:
        os.rmdir(d)


def test_output_write_failed_returns_exit_1():
    """The helper must return exit code 1 on write failure."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        rc = _handle_output_and_redact(ns, {"ok": True}, command="issue")
        assert rc == 1
    finally:
        os.rmdir(d)


def test_output_write_success_still_works(capfd):
    """Successful output write still returns the enriched success response."""
    from vibap.cli import _handle_output_and_redact

    tmpdir = tempfile.mkdtemp()
    out_path = os.path.join(tmpdir, "output.json")
    try:
        ns = _make_args(output=out_path)
        rc = _handle_output_and_redact(
            ns, {"ok": True, "data": "test"}, command="issue"
        )
        assert rc == 0
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        assert result["ok"] is True
        assert result["condition"] == "issue_report_written"
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)
        os.rmdir(tmpdir)


def test_output_write_failed_detail_preserves_safe_code(capfd):
    """The 'detail' field must carry the safe domain error code from ValueError."""
    from vibap.cli import _handle_output_and_redact

    d = tempfile.mkdtemp()
    try:
        ns = _make_args(output=d)
        _handle_output_and_redact(ns, {"ok": True}, command="uninstall")
        captured = capfd.readouterr()
        result = json.loads(captured.out)
        # ValueError from _write_json_report_to_file carries exc.code which is
        # a safe constant like "output_parent_invalid".
        assert "detail" in result
        assert isinstance(result["detail"], str)
    finally:
        os.rmdir(d)

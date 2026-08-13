"""Tests for --output write-failure response parity across all CLI commands.

Every CLI command that catches ValueError from _write_json_report_to_file
must emit the same enriched structured-error shape:

  error, error_code, condition, message, detail, next_steps

This file covers the commands whose --output handlers were historically
inline rather than using the shared _handle_output_and_redact:

  - verify (5 inline handlers: token, attestation-token, offline,
    attestation offline, evidence correlate receipt)
  - claude-code-report
  - gemini-cli-report
  - codex-app-server-report
  - _handle_output_and_redact itself (issue, anchor, attest, setup,
    status, doctor, uninstall, protect-claude-code, doctor-claude-code,
    latency-gate-evaluate)

The shared _output_write_error_response helper produces the canonical
shape for all of them.
"""

import inspect

from vibap.cli import _output_write_error_response


class TestOutputWriteErrorResponse:
    """Verify the canonical enriched shape from _output_write_error_response."""

    def test_has_all_required_fields(self):
        resp = _output_write_error_response("verify", ValueError("bad path"))
        for key in ("error", "error_code", "condition", "message", "detail", "next_steps"):
            assert key in resp, f"missing field: {key}"

    def test_error_equals_condition(self):
        resp = _output_write_error_response("verify", ValueError("bad path"))
        assert resp["error"] == resp["condition"]
        assert resp["error_code"] == resp["condition"]

    def test_condition_uses_command_prefix(self):
        resp = _output_write_error_response("verify", ValueError("x"))
        assert resp["condition"] == "verify_output_write_failed"

    def test_detail_preserves_safe_message(self):
        exc = ValueError("Path is an existing directory")
        resp = _output_write_error_response("verify", exc)
        assert resp["detail"] == "Path is an existing directory"

    def test_message_is_human_readable(self):
        resp = _output_write_error_response("verify", ValueError("x"))
        assert "ardur verify" in resp["message"]
        assert "failed" in resp["message"].lower()

    def test_message_replaces_underscores_with_hyphens(self):
        resp = _output_write_error_response("claude_code_report", ValueError("x"))
        assert "ardur claude-code-report" in resp["message"]

    def test_next_steps_has_action(self):
        resp = _output_write_error_response("verify", ValueError("x"))
        assert len(resp["next_steps"]) == 1
        assert resp["next_steps"][0]["action"] == "choose_writable_output_path"

    def test_next_steps_has_command_with_hyphens(self):
        resp = _output_write_error_response("gemini_cli_report", ValueError("x"))
        cmd = resp["next_steps"][0]["command"]
        assert "ardur gemini-cli-report" in cmd
        assert "--output <writable-file-path>" in cmd

    def test_next_steps_has_detail(self):
        resp = _output_write_error_response("codex_app_server_report", ValueError("x"))
        assert "writable file path" in resp["next_steps"][0]["detail"]

    def test_next_steps_does_not_carry_condition_key(self):
        """next_steps items should NOT have a top-level condition key.

        The old claude-code-report/gemini-cli-report/codex-app-server-report
        handlers had an extra 'condition' inside next_steps[] items, which
        is not present in the canonical _handle_output_and_redact shape.
        """
        for cmd in ("verify", "claude_code_report", "gemini_cli_report", "codex_app_server_report"):
            resp = _output_write_error_response(cmd, ValueError("x"))
            step = resp["next_steps"][0]
            assert "condition" not in step, f"{cmd}: next_steps item should not carry 'condition'"


class TestVerifyHandlersUseSharedHelper:
    """Confirm that verify --output handlers call the shared helper."""

    def test_no_inline_verify_output_write_failed_left(self):
        """No inline error dict should remain for verify --output write failures.

        The old pattern was:

            {"valid": False, "error": "verify_output_write_failed", "detail": str(exc)}

        After the fix, all 5 verify handlers use:

            {"valid": False, **_output_write_error_response("verify", exc)}
        """
        import vibap.cli as cli
        source = inspect.getsource(cli)
        # The old inline pattern should NOT be present
        assert '"error": "verify_output_write_failed"' not in source, \
            "inline verify_output_write_failed still present — should use shared helper"

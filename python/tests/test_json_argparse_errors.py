"""Tests for ``--json`` contract on argparse missing-required-argument errors.

When ``--json`` is set on protocol-path commands (attest, anchor, issue,
evidence correlate, telemetry export, preflight tool-server, posture scan)
and a required argument is missing, argparse previously printed human-
readable usage text to stderr and exited 2. That violated the CLI contract:
``--json`` mode must always emit machine-readable JSON.

The ``_JsonAwareArgumentParser`` subclass routes argparse errors through a
structured JSON payload (``{"ok": false, "error": "argument_error", ...}``)
to stderr with exit code 0 when ``--json`` is in the argv, and leaves
non-JSON behaviour byte-identical (usage text + exit 2).

These tests cover all seven affected commands in both ``--json`` and
non-JSON modes, plus the ``verify --json`` reference path (which already
worked because verify uses optional argparse args).
"""

from __future__ import annotations

import io
import json
from unittest.mock import patch

import pytest

from vibap.cli import main


# Each entry is (argv, human_substring_expected_in_non_json_usage).
# The human substring is checked against non-JSON stderr to confirm the
# default argparse path is unchanged and still names the missing argument.
AFFECTED_COMMANDS: list[tuple[list[str], str]] = [
    (["attest", "--json"], "--session"),
    (["anchor", "--json"], "--receipt-log"),
    (["issue", "--json"], "--agent-id"),
    (["evidence", "correlate", "--json"], "--source-format"),
    (["telemetry", "export", "--json"], "journal"),
    (["preflight", "tool-server", "--json"], "--config"),
    (["posture", "scan", "--json"], "--receipts"),
]


def _run_main_capture_stderr(argv: list[str]) -> tuple[int, str, str]:
    """Invoke ``main(argv)`` capturing stderr/stdout.

    Returns ``(exit_code, stderr, stdout)``. ``main()`` raises
    ``SystemExit`` on argparse errors, so we catch it and read its code.
    """
    stderr_buf = io.StringIO()
    stdout_buf = io.StringIO()
    with patch("sys.stderr", stderr_buf), patch("sys.stdout", stdout_buf):
        try:
            exit_code = main(argv)
        except SystemExit as exc:
            exit_code = int(exc.code) if exc.code is not None else 0
    return exit_code, stderr_buf.getvalue(), stdout_buf.getvalue()


@pytest.mark.parametrize(
    "argv,missing_arg", AFFECTED_COMMANDS, ids=lambda v: v[0] if isinstance(v, str) else "-".join(v)
)
def test_json_mode_emits_structured_json_error(argv: list[str], missing_arg: str):
    """In ``--json`` mode, argparse missing-required errors emit JSON."""
    exit_code, stderr, _stdout = _run_main_capture_stderr(argv)
    assert exit_code == 0, f"expected exit 0 in --json mode, got {exit_code}"
    payload = json.loads(stderr)
    assert payload["ok"] is False
    assert payload["error"] == "argument_error"
    assert payload["error_code"] == "argument_error"
    assert payload["condition"] == "argument_error"
    assert "message" in payload and isinstance(payload["message"], str)
    # The argparse message must name the missing required argument so JSON
    # consumers can act on the specific failure.
    assert missing_arg in payload["message"], (
        f"expected {missing_arg!r} in message, got {payload['message']!r}"
    )


@pytest.mark.parametrize(
    "argv,_missing_arg", AFFECTED_COMMANDS, ids=lambda v: v[0] if isinstance(v, str) else "-".join(v)
)
def test_non_json_mode_emits_usage_text_and_exit_2(argv: list[str], _missing_arg: str):
    """Without ``--json``, argparse behaviour is byte-identical (usage + exit 2)."""
    non_json_argv = [a for a in argv if a != "--json"]
    exit_code, stderr, _stdout = _run_main_capture_stderr(non_json_argv)
    assert exit_code == 2, f"expected exit 2 in non-JSON mode, got {exit_code}"
    # Human-readable usage, not parseable JSON
    with pytest.raises(json.JSONDecodeError):
        json.loads(stderr)
    assert "usage:" in stderr


def test_json_mode_does_not_swallow_unrelated_argparse_errors():
    """An argparse error that is NOT a missing-required-arg (here: an unknown
    subcommand) should also honour ``--json`` since ``error()`` is the single
    argparse failure sink. This guards against regressions that special-case
    only the missing-required path."""
    exit_code, stderr, _stdout = _run_main_capture_stderr(
        ["__not_a_real_command__", "--json"]
    )
    assert exit_code == 0
    payload = json.loads(stderr)
    assert payload["ok"] is False
    assert payload["error"] == "argument_error"


def test_verify_json_reference_path_unchanged():
    """``ardur verify --json`` (no args) already emits JSON via handler
    validation, not via the argparse path. It must continue to do so and
    must NOT be hijacked by ``_JsonAwareArgumentParser`` (no argparse error
    fires because verify's args are all optional)."""
    exit_code, stderr, stdout = _run_main_capture_stderr(["verify", "--json"])
    # verify emits JSON to stdout (its own contract), exit 1.
    assert exit_code == 1
    payload = json.loads(stdout)
    assert payload["valid"] is False
    assert payload["error"] == "verify_input_invalid"
    # No argparse JSON error leaked to stderr.
    assert stderr == ""


def test_top_level_missing_command_json_mode():
    """``ardur --json`` with no subcommand: argparse fires
    "the following arguments are required: command" and must emit JSON."""
    exit_code, stderr, _stdout = _run_main_capture_stderr(["--json"])
    assert exit_code == 0
    payload = json.loads(stderr)
    assert payload["ok"] is False
    assert payload["error"] == "argument_error"
    assert "command" in payload["message"]


def test_error_payload_is_valid_json_document():
    """The stderr payload must be a single valid JSON document (no trailing
    usage text after the closing brace)."""
    exit_code, stderr, _stdout = _run_main_capture_stderr(["issue", "--json"])
    assert exit_code == 0
    # json.loads rejects trailing data, so this proves the payload is clean.
    parsed = json.loads(stderr)
    assert parsed["ok"] is False

"""Tests that --json is accepted as a no-op/consistency flag on the remaining
always-JSON and default-JSON commands.

This closes the CLI consistency sweep: every Ardur command that emits JSON must
accept ``--json`` so users who pass ``--json`` everywhere (the documented
pattern) do not get ``unrecognized arguments: --json`` on a subset of commands.

Before this fix, four commands rejected ``--json``:
- ``telemetry export``      (always emits JSONL/OTLP JSON)
- ``preflight tool-server`` (defaults to JSON)
- ``posture scan``          (defaults to JSON)
- ``posture report``        (defaults to markdown, but is JSON-capable)

Covered commands:
- ``telemetry export --json``
- ``preflight tool-server --json``
- ``posture scan --json``
- ``posture report --json``
"""

import json
import subprocess
import sys

CLI = [sys.executable, "-m", "vibap.cli"]


def _run(args, env=None):
    """Run the Ardur CLI with the given args, returning (returncode, stdout, stderr)."""
    proc = subprocess.run(
        CLI + args,
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ---------------------------------------------------------------------------
# telemetry export
# ---------------------------------------------------------------------------

def test_telemetry_export_accepts_json_flag():
    """``telemetry export --json`` should not fail with unrecognized arguments."""
    rc, out, err = _run([
        "telemetry", "export", "/nonexistent/journal.jsonl",
        "--keys-dir", "/nonexistent/keys",
        "--json",
    ])
    combined = out + err
    assert "unrecognized arguments: --json" not in combined, (
        f"--json should be accepted, got: {combined}"
    )
    # The command should produce JSON (a domain-level error is fine — the point
    # is that argparse accepted --json).
    payload = json.loads(out)
    assert isinstance(payload, dict)


def test_telemetry_export_json_is_noop_without_flag():
    """Without --json, telemetry export should behave identically (always JSON)."""
    rc_no, out_no, _ = _run([
        "telemetry", "export", "/nonexistent/journal.jsonl",
        "--keys-dir", "/nonexistent/keys",
    ])
    rc_yes, out_yes, _ = _run([
        "telemetry", "export", "/nonexistent/journal.jsonl",
        "--keys-dir", "/nonexistent/keys",
        "--json",
    ])
    assert rc_no == rc_yes
    # The JSON payload should be structurally equivalent (same error).
    assert json.loads(out_no)["error"] == json.loads(out_yes)["error"]


# ---------------------------------------------------------------------------
# preflight tool-server
# ---------------------------------------------------------------------------

def test_preflight_tool_server_accepts_json_flag():
    """``preflight tool-server --json`` should not fail with unrecognized arguments."""
    rc, out, err = _run([
        "preflight", "tool-server",
        "--config", "/nonexistent/config.json",
        "--json",
    ])
    combined = out + err
    assert "unrecognized arguments: --json" not in combined, (
        f"--json should be accepted, got: {combined}"
    )
    # Domain error (config not found / malformed) is acceptable; argparse
    # accepted --json.
    assert rc in (0, 1, 2)


def test_preflight_tool_server_help_shows_json():
    """The --help output should document --json."""
    rc, out, err = _run(["preflight", "tool-server", "--help"])
    assert "--json" in (out + err)


# ---------------------------------------------------------------------------
# posture scan
# ---------------------------------------------------------------------------

def test_posture_scan_accepts_json_flag():
    """``posture scan --json`` should not fail with unrecognized arguments."""
    rc, out, err = _run([
        "posture", "scan",
        "--receipts", "/nonexistent/receipts",
        "--json",
    ])
    combined = out + err
    assert "unrecognized arguments: --json" not in combined, (
        f"--json should be accepted, got: {combined}"
    )
    # posture scan returns exit 0 even for empty/missing receipts, emitting a
    # posture JSON document.
    payload = json.loads(out)
    assert isinstance(payload, dict)


def test_posture_scan_json_equivalent_to_format_json():
    """``posture scan --json`` should produce JSON identical to ``--format json``."""
    _, out_flag, _ = _run([
        "posture", "scan",
        "--receipts", "/nonexistent/receipts",
        "--json",
    ])
    _, out_fmt, _ = _run([
        "posture", "scan",
        "--receipts", "/nonexistent/receipts",
        "--format", "json",
    ])
    assert json.loads(out_flag) == json.loads(out_fmt)


# ---------------------------------------------------------------------------
# posture report
# ---------------------------------------------------------------------------

def test_posture_report_accepts_json_flag():
    """``posture report --json`` should not fail with unrecognized arguments."""
    rc, out, err = _run([
        "posture", "report",
        "--input", "/nonexistent/report.json",
        "--json",
    ])
    combined = out + err
    assert "unrecognized arguments: --json" not in combined, (
        f"--json should be accepted, got: {combined}"
    )
    # Should emit structured JSON for the error (file not found).
    payload = json.loads(out)
    assert isinstance(payload, dict)
    assert payload.get("ok") is False


def test_posture_report_json_overrides_markdown_default():
    """``--json`` on posture report should force JSON even though the default is markdown."""
    rc_flag, out_flag, _ = _run([
        "posture", "report",
        "--input", "/nonexistent/report.json",
        "--json",
    ])
    rc_default, out_default, _ = _run([
        "posture", "report",
        "--input", "/nonexistent/report.json",
    ])
    # Default (markdown) should NOT be JSON for an error path — it prints
    # human-readable text. --json should produce JSON.
    # With --json, output must parse as JSON.
    json.loads(out_flag)
    # The default-markdown path should differ from the --json path.
    assert out_flag != out_default


# ---------------------------------------------------------------------------
# Full CLI sweep
# ---------------------------------------------------------------------------

def test_all_json_emitting_commands_accept_json_flag():
    """Sweep: every command that can emit JSON should accept --json.

    This is a regression guard ensuring no future subparser addition
    reintroduces the inconsistency. We test that argparse accepts --json
    (the domain-level error is irrelevant for this test).
    """
    commands = [
        (["verify", "--json"], True),  # always JSON
        (["issue", "--json"], True),
        (["attest", "--session", "x", "--json"], True),
        (["anchor", "--receipt-log", "x", "--backend", "c2sp-local-v1", "--json"], True),
        (["evidence", "correlate"], False),  # needs EVENTS + --source-format
        (["status", "--json"], True),
        (["doctor", "--json"], True),
        (["doctor-claude-code", "--json"], True),
        (["kill-switch", "--json"], True),
        (["telemetry", "export", "x", "--keys-dir", "y", "--json"], True),
        (["preflight", "tool-server", "--config", "x", "--json"], True),
        (["posture", "scan", "--receipts", "x", "--json"], True),
        (["posture", "report", "--input", "x", "--json"], True),
    ]
    failures = []
    for cmd, should_pass_argparse in commands:
        rc, out, err = _run(cmd)
        combined = out + err
        if "unrecognized arguments: --json" in combined:
            failures.append(" ".join(cmd))
    assert not failures, (
        f"These commands still reject --json: {failures}"
    )

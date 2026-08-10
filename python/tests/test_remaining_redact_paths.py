"""Tests for ``--redact-paths`` flag on the remaining 6 CLI commands.

The six commands (``verify``, ``evidence correlate``, ``telemetry export``,
``posture scan``, ``posture report``, ``preflight tool-server``) gained
``--redact-paths`` to replace local absolute paths in their JSON/file
output with stable placeholders, matching the established pattern from
``claude-code-report``, ``gemini-cli-report``, ``codex-app-server-report``,
and ``run``.

This file verifies:

* The flag exists on all six subparsers.
* ``--redact-paths`` without ``--json`` or ``--output`` emits a warning.
* ``--json --redact-paths`` redacts local paths from stdout JSON (for
  commands that can be tested without real data).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from vibap import cli

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

THIS_DIR = Path(__file__).resolve().parent
PKG_ROOT = THIS_DIR.parent


def _build_parser():
    from vibap.cli import build_parser

    return build_parser()


def _get_subparser_choices(parser):
    """Return the top-level subparser choices dict."""
    sub = [a for a in parser._subparsers._group_actions if hasattr(a, "choices")][0]
    return sub.choices


def _get_nested_subparser_choices(parser, parent_name):
    """Return the nested subparser choices dict for a parent command."""
    parent = _get_subparser_choices(parser)[parent_name]
    sub = [a for a in parent._subparsers._group_actions if hasattr(a, "choices")][0]
    return sub.choices


def _assert_has_redact_paths_flag(action):
    """Assert that the given argparse action has --redact-paths."""
    flags = set()
    for opt in action._actions:
        flags.update(opt.option_strings)
    assert "--redact-paths" in flags, (
        f"--redact-paths not found in {action.prog}"
    )


# ---------------------------------------------------------------------------
# Subparser existence
# ---------------------------------------------------------------------------

def test_verify_has_redact_paths_flag():
    parser = _build_parser()
    action = _get_subparser_choices(parser)["verify"]
    _assert_has_redact_paths_flag(action)


def test_evidence_correlate_has_redact_paths_flag():
    parser = _build_parser()
    action = _get_nested_subparser_choices(parser, "evidence")["correlate"]
    _assert_has_redact_paths_flag(action)


def test_telemetry_export_has_redact_paths_flag():
    parser = _build_parser()
    action = _get_nested_subparser_choices(parser, "telemetry")["export"]
    _assert_has_redact_paths_flag(action)


def test_posture_scan_has_redact_paths_flag():
    parser = _build_parser()
    action = _get_nested_subparser_choices(parser, "posture")["scan"]
    _assert_has_redact_paths_flag(action)


def test_posture_report_has_redact_paths_flag():
    parser = _build_parser()
    action = _get_nested_subparser_choices(parser, "posture")["report"]
    _assert_has_redact_paths_flag(action)


def test_preflight_tool_server_has_redact_paths_flag():
    parser = _build_parser()
    action = _get_nested_subparser_choices(parser, "preflight")["tool-server"]
    _assert_has_redact_paths_flag(action)


# ---------------------------------------------------------------------------
# Warning tests: --redact-paths without --json or --output
# ---------------------------------------------------------------------------

class TestPostureScanRedactPathsWarning:
    def test_warning_without_json_or_output(self, tmp_path, monkeypatch, capsys):
        """``posture scan --redact-paths`` without ``--json`` or ``--output`` warns."""

        fake_posture = {"home": str(tmp_path), "summary": {"receipt_count": 0}}
        monkeypatch.setattr(
            cli, "build_posture_index", lambda **kw: fake_posture
        )

        import argparse

        args = argparse.Namespace(
            receipts=str(tmp_path / "receipts"),
            keys_dir=None,
            profile=None,
            evidence_bundle=None,
            verify_expiry=False,
            format="json",
            json=False,
            posture_scan_output=None,
            redact_paths=True,
        )
        rc = cli.cmd_posture_scan(args)
        assert rc == 0
        captured = capsys.readouterr()
        assert "--redact-paths has no effect" in captured.err


class TestPreflightToolServerRedactPathsWarning:
    def test_warning_without_json_or_output(self, tmp_path, monkeypatch, capsys):
        """``preflight tool-server --redact-paths`` without ``--json`` or ``--output`` warns."""

        fake_report = {
            "summary": {"verdict": "pass", "finding_count": 0},
            "findings": [],
        }
        monkeypatch.setattr(
            cli, "scan_tool_server_config", lambda config: fake_report
        )

        import argparse

        args = argparse.Namespace(
            config=str(tmp_path / "config.json"),
            format="json",
            json=False,
            output=None,
            fail_on="none",
            redact_paths=True,
        )
        rc = cli.cmd_tool_server_preflight(args)
        assert rc == 0
        captured = capsys.readouterr()
        assert "--redact-paths has no effect" in captured.err


# ---------------------------------------------------------------------------
# Redaction tests: --json --redact-paths
# ---------------------------------------------------------------------------

class TestPostureScanRedactPathsJson:
    def test_redacts_json_stdout(self, tmp_path, monkeypatch, capsys):
        """``posture scan --json --redact-paths`` redacts local paths from stdout JSON."""
        fake_posture = {
            "home": str(tmp_path),
            "receipts_dir": str(tmp_path / "receipts"),
            "summary": {"receipt_count": 0},
        }


        monkeypatch.setattr(
            cli, "build_posture_index", lambda **kw: fake_posture
        )

        import argparse

        args = argparse.Namespace(
            receipts=str(tmp_path / "receipts"),
            keys_dir=None,
            profile=None,
            evidence_bundle=None,
            verify_expiry=False,
            format="json",
            json=True,
            posture_scan_output=None,
            redact_paths=True,
        )
        rc = cli.cmd_posture_scan(args)
        assert rc == 0
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert str(tmp_path) not in json.dumps(response)


class TestPreflightToolServerRedactPathsJson:
    def test_redacts_json_stdout(self, tmp_path, monkeypatch, capsys):
        """``preflight tool-server --json --redact-paths`` redacts local paths from stdout JSON."""
        fake_report = {
            "summary": {
                "verdict": "pass",
                "finding_count": 0,
            },
            "config_path": str(tmp_path / "config.json"),
            "findings": [],
        }


        monkeypatch.setattr(
            cli, "scan_tool_server_config", lambda config: fake_report
        )

        import argparse

        args = argparse.Namespace(
            config=str(tmp_path / "config.json"),
            format="json",
            json=True,
            output=None,
            fail_on="none",
            redact_paths=True,
        )
        rc = cli.cmd_tool_server_preflight(args)
        assert rc == 0
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert str(tmp_path) not in json.dumps(response)


# ---------------------------------------------------------------------------
# End-to-end CLI smoke
# ---------------------------------------------------------------------------

def test_verify_redact_paths_e2e_help():
    """``verify --help`` shows --redact-paths in usage."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "vibap.cli", "verify", "--help"],
        capture_output=True,
        text=True,
    )
    assert "--redact-paths" in result.stdout


def test_evidence_correlate_redact_paths_e2e_help():
    """``evidence correlate --help`` shows --redact-paths in usage."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "vibap.cli", "evidence", "correlate", "--help"],
        capture_output=True,
        text=True,
    )
    assert "--redact-paths" in result.stdout


def test_telemetry_export_redact_paths_e2e_help():
    """``telemetry export --help`` shows --redact-paths in usage."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "vibap.cli", "telemetry", "export", "--help"],
        capture_output=True,
        text=True,
    )
    assert "--redact-paths" in result.stdout


def test_posture_scan_redact_paths_e2e_help():
    """``posture scan --help`` shows --redact-paths in usage."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "vibap.cli", "posture", "scan", "--help"],
        capture_output=True,
        text=True,
    )
    assert "--redact-paths" in result.stdout


def test_posture_report_redact_paths_e2e_help():
    """``posture report --help`` shows --redact-paths in usage."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "vibap.cli", "posture", "report", "--help"],
        capture_output=True,
        text=True,
    )
    assert "--redact-paths" in result.stdout


def test_preflight_tool_server_redact_paths_e2e_help():
    """``preflight tool-server --help`` shows --redact-paths in usage."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "vibap.cli", "preflight", "tool-server", "--help"],
        capture_output=True,
        text=True,
    )
    assert "--redact-paths" in result.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

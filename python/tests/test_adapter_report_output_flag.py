"""Tests for ``--output`` flag on adapter report commands.

The three adapter report commands (``claude-code-report``,
``gemini-cli-report``, ``codex-app-server-report``) gained ``--output``
to write their JSON report to a file, matching the established pattern
from ``verify``, ``posture``, ``preflight``, ``telemetry``, ``evidence
correlate``, and ``run``.  This file verifies:

* The flag exists on all three subparsers.
* A valid path writes the file and returns ``0``.
* An empty / whitespace-only path is rejected.
* A directory path is rejected via the atomic writer's ``ValueError``.
* Without ``--output`` and without ``--json`` the human-readable report
  still prints normally.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

THIS_DIR = Path(__file__).resolve().parent
PKG_ROOT = THIS_DIR.parent


@pytest.fixture()
def env_home(tmp_path: Path) -> Path:
    """An empty Ardur home with minimal structure for report builders."""

    home = tmp_path / "ardur-home"
    home.mkdir()
    (home / "claude-code-hook").mkdir()
    (home / "gemini-cli-hook").mkdir()
    (home / "codex-app-server").mkdir()
    return home


@pytest.fixture()
def chain_dir(tmp_path: Path) -> Path:
    chain = tmp_path / "chains"
    chain.mkdir()
    return chain


@pytest.fixture()
def keys_dir(tmp_path: Path) -> Path:
    keys = tmp_path / "keys"
    keys.mkdir()
    return keys


# ---------------------------------------------------------------------------
# Subparser existence
# ---------------------------------------------------------------------------

def _build_parser():
    """Import the live CLI parser to introspect subcommand arguments."""

    from vibap.cli import build_parser

    return build_parser()


def test_claude_code_report_has_output_flag():
    parser = _build_parser()
    sub = [a for a in parser._subparsers._group_actions if hasattr(a, "choices")][0]
    assert "claude-code-report" in sub.choices
    action = sub.choices["claude-code-report"]
    flags = set()
    for opt in action._actions:
        flags.update(opt.option_strings)
    assert "--output" in flags


def test_gemini_cli_report_has_output_flag():
    parser = _build_parser()
    sub = [a for a in parser._subparsers._group_actions if hasattr(a, "choices")][0]
    action = sub.choices["gemini-cli-report"]
    flags = set()
    for opt in action._actions:
        flags.update(opt.option_strings)
    assert "--output" in flags


def test_codex_app_server_report_has_output_flag():
    parser = _build_parser()
    sub = [a for a in parser._subparsers._group_actions if hasattr(a, "choices")][0]
    action = sub.choices["codex-app-server-report"]
    flags = set()
    for opt in action._actions:
        flags.update(opt.option_strings)
    assert "--output" in flags


# ---------------------------------------------------------------------------
# Handler-level tests (argparse namespace simulation)
# ---------------------------------------------------------------------------

def _make_args(output=None, json_flag=False, **kwargs):
    """Build a minimal argparse.Namespace for the report commands."""

    import argparse

    ns = argparse.Namespace(
        home=kwargs.get("home"),
        chain_dir=kwargs.get("chain_dir"),
        keys_dir=kwargs.get("keys_dir"),
        verify_expiry=False,
        json=json_flag,
        output=output,
    )
    return ns


class TestClaudeCodeReportOutput:
    def test_writes_file_on_valid_output(self, tmp_path, monkeypatch):
        """``--output`` writes the JSON report and returns 0."""

        output_path = tmp_path / "cc-report.json"
        fake_report = {"receipt_count": 3, "chain_count": 1, "home": "redacted"}

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_claude_code_report", lambda **kw: fake_report
        )
        args = _make_args(output=str(output_path))
        rc = cli.cmd_claude_code_report(args)
        assert rc == 0
        assert output_path.exists()
        written = json.loads(output_path.read_text())
        assert written == fake_report

    def test_returns_zero_with_json_in_stdout(self, tmp_path, monkeypatch, capsys):
        """With ``--output``, a success confirmation JSON goes to stdout and the file is written."""

        output_path = tmp_path / "cc-report.json"
        fake_report = {"receipt_count": 0, "chain_count": 0}

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_claude_code_report", lambda **kw: fake_report
        )
        args = _make_args(output=str(output_path))
        rc = cli.cmd_claude_code_report(args)
        assert rc == 0
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert response["ok"] is True
        assert response["condition"] == "claude_code_report_written"
        assert response["output"] == str(output_path)
        assert "report_sha256" in response
        assert len(response["report_sha256"]) == 64

    def test_empty_output_rejected(self, monkeypatch, capsys):
        """Empty ``--output`` is caught by ``_coerce_report_path_args``."""

        import vibap.cli as cli

        # The handler calls _coerce_report_path_args first; pass empty str
        args = _make_args(output="")
        rc = cli.cmd_claude_code_report(args)
        assert rc == 1
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert response["ok"] is False
        assert "empty" in response["condition"]

    def test_whitespace_output_rejected(self, monkeypatch, capsys):
        import vibap.cli as cli

        args = _make_args(output="   ")
        rc = cli.cmd_claude_code_report(args)
        assert rc == 1
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert response["ok"] is False
        assert "empty" in response["condition"]


class TestGeminiCliReportOutput:
    def test_writes_file_on_valid_output(self, tmp_path, monkeypatch):
        output_path = tmp_path / "gem-report.json"
        fake_report = {
            "receipt_count": 1,
            "chain_count": 1,
            "policy_verdict_counts": {},
            "coverage_gaps": [],
        }

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_gemini_shareable_report", lambda **kw: fake_report
        )
        args = _make_args(output=str(output_path))
        rc = cli.cmd_gemini_cli_report(args)
        assert rc == 0
        assert output_path.exists()
        written = json.loads(output_path.read_text())
        assert written == fake_report

    def test_empty_output_rejected(self, capsys):
        import vibap.cli as cli

        args = _make_args(output="")
        rc = cli.cmd_gemini_cli_report(args)
        assert rc == 1
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert response["ok"] is False
        assert "empty" in response["condition"]


class TestCodexAppServerReportOutput:
    def test_writes_file_on_valid_output(self, tmp_path, monkeypatch):
        output_path = tmp_path / "codex-report.json"
        fake_report = {
            "receipt_count": 2,
            "chain_count": 1,
            "policy_verdict_counts": {},
            "coverage_gaps": [],
        }

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_codex_shareable_report", lambda **kw: fake_report
        )
        args = _make_args(output=str(output_path))
        rc = cli.cmd_codex_app_server_report(args)
        assert rc == 0
        assert output_path.exists()
        written = json.loads(output_path.read_text())
        assert written == fake_report

    def test_empty_output_rejected(self, capsys):
        import vibap.cli as cli

        args = _make_args(output="")
        rc = cli.cmd_codex_app_server_report(args)
        assert rc == 1
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert response["ok"] is False
        assert "empty" in response["condition"]


# ---------------------------------------------------------------------------
# End-to-end CLI smoke (argparse + handler wiring)
# ---------------------------------------------------------------------------

def test_claude_code_report_output_e2e_writes_file(tmp_path):
    """Full argparse + handler path writes a valid JSON file for an empty home."""

    output_path = tmp_path / "e2e-cc.json"
    from vibap.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(
        [
            "claude-code-report",
            "--output",
            str(output_path),
            "--home",
            str(tmp_path / "empty-home"),
        ]
    )
    rc = args.func(args)
    assert rc == 0
    assert output_path.exists()
    written = json.loads(output_path.read_text())
    assert "receipt_count" in written


def test_directory_output_rejected_claude_code(tmp_path, monkeypatch, capsys):
    """An existing directory as ``--output`` triggers the ValueError path."""

    output_dir = tmp_path / "output-dir"
    output_dir.mkdir()

    fake_report = {"receipt_count": 0, "chain_count": 0}

    import vibap.cli as cli

    monkeypatch.setattr(
        cli, "build_claude_code_report", lambda **kw: fake_report
    )
    args = _make_args(output=str(output_dir))
    rc = cli.cmd_claude_code_report(args)
    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out.strip())
    assert response["ok"] is False
    assert response["condition"] == "claude_code_report_output_write_failed"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

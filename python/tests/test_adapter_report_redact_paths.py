"""Tests for ``--redact-paths`` flag on adapter report commands.

The three adapter report commands (``claude-code-report``,
``gemini-cli-report``, ``codex-app-server-report``) gained
``--redact-paths`` to replace local absolute paths in their JSON
output (both ``--json`` to stdout and ``--output`` to file) with
stable placeholders, matching the established pattern from ``run``,
``status``, ``doctor``, and ``protect claude-code``.

This file verifies:

* The flag exists on all three subparsers.
* ``--json --redact-paths`` redacts local paths from stdout JSON.
* ``--output --redact-paths`` redacts local paths from the written file.
* ``--redact-paths`` without ``--json`` or ``--output`` emits a warning.
* The warning is suppressed when ``--json`` or ``--output`` is present.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

THIS_DIR = Path(__file__).resolve().parent
PKG_ROOT = THIS_DIR.parent


def _build_parser():
    from vibap.cli import build_parser

    return build_parser()


def _make_args(*, output=None, json_flag=False, redact_paths=False, **kwargs):
    import argparse

    ns = argparse.Namespace(
        home=kwargs.get("home"),
        chain_dir=kwargs.get("chain_dir"),
        keys_dir=kwargs.get("keys_dir"),
        verify_expiry=False,
        json=json_flag,
        output=output,
        redact_paths=redact_paths,
    )
    return ns


# ---------------------------------------------------------------------------
# Subparser existence
# ---------------------------------------------------------------------------

def test_claude_code_report_has_redact_paths_flag():
    parser = _build_parser()
    sub = [a for a in parser._subparsers._group_actions if hasattr(a, "choices")][0]
    action = sub.choices["claude-code-report"]
    flags = set()
    for opt in action._actions:
        flags.update(opt.option_strings)
    assert "--redact-paths" in flags


def test_gemini_cli_report_has_redact_paths_flag():
    parser = _build_parser()
    sub = [a for a in parser._subparsers._group_actions if hasattr(a, "choices")][0]
    action = sub.choices["gemini-cli-report"]
    flags = set()
    for opt in action._actions:
        flags.update(opt.option_strings)
    assert "--redact-paths" in flags


def test_codex_app_server_report_has_redact_paths_flag():
    parser = _build_parser()
    sub = [a for a in parser._subparsers._group_actions if hasattr(a, "choices")][0]
    action = sub.choices["codex-app-server-report"]
    flags = set()
    for opt in action._actions:
        flags.update(opt.option_strings)
    assert "--redact-paths" in flags


# ---------------------------------------------------------------------------
# Handler-level redaction tests
# ---------------------------------------------------------------------------

class TestClaudeCodeReportRedactPaths:
    def test_redacts_json_stdout(self, tmp_path, monkeypatch, capsys):
        """``--json --redact-paths`` redacts local paths from stdout JSON."""

        fake_report = {
            "receipt_count": 1,
            "chain_count": 1,
            "home": str(tmp_path),
            "chain_dir": str(tmp_path / "chains"),
            "totals": {"tools": 0, "verdicts": {}, "side_effect_classes": []},
        }

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_claude_code_report", lambda **kw: fake_report
        )
        args = _make_args(json_flag=True, redact_paths=True)
        rc = cli.cmd_claude_code_report(args)
        assert rc == 0
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        # Local paths should be redacted (not equal to original)
        assert response["home"] != str(tmp_path)
        assert str(tmp_path) not in json.dumps(response)

    def test_redacts_output_file(self, tmp_path, monkeypatch):
        """``--output --redact-paths`` redacts local paths from written file."""

        output_path = tmp_path / "cc-redacted.json"
        fake_report = {
            "receipt_count": 2,
            "chain_count": 1,
            "home": str(tmp_path),
            "chain_dir": str(tmp_path / "chains"),
            "totals": {"tools": 0, "verdicts": {}, "side_effect_classes": []},
        }

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_claude_code_report", lambda **kw: fake_report
        )
        args = _make_args(output=str(output_path), redact_paths=True)
        rc = cli.cmd_claude_code_report(args)
        assert rc == 0
        assert output_path.exists()
        written = output_path.read_text()
        assert str(tmp_path) not in written

    def test_warning_without_json_or_output(self, tmp_path, capsys):
        """``--redact-paths`` without ``--json`` or ``--output`` warns on stderr."""

        import subprocess

        home = tmp_path / "empty-home"
        home.mkdir()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vibap.cli",
                "claude-code-report",
                "--redact-paths",
                "--home",
                str(home),
            ],
            capture_output=True,
            text=True,
        )
        assert "--redact-paths has no effect" in result.stderr

    def test_no_warning_with_json(self, monkeypatch, capsys):
        """``--redact-paths --json`` does NOT warn on stderr."""

        fake_report = {"receipt_count": 0, "chain_count": 0}

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_claude_code_report", lambda **kw: fake_report
        )
        args = _make_args(json_flag=True, redact_paths=True)
        rc = cli.cmd_claude_code_report(args)
        assert rc == 0
        captured = capsys.readouterr()
        assert "--redact-paths has no effect" not in captured.err


class TestGeminiCliReportRedactPaths:
    def test_redacts_json_stdout(self, tmp_path, monkeypatch, capsys):
        fake_report = {
            "receipt_count": 1,
            "chain_count": 1,
            "home": str(tmp_path),
            "policy_verdict_counts": {},
            "coverage_gaps": [],
        }

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_gemini_shareable_report", lambda **kw: fake_report
        )
        args = _make_args(json_flag=True, redact_paths=True)
        rc = cli.cmd_gemini_cli_report(args)
        assert rc == 0
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert str(tmp_path) not in json.dumps(response)

    def test_redacts_output_file(self, tmp_path, monkeypatch):
        output_path = tmp_path / "gem-redacted.json"
        fake_report = {
            "receipt_count": 1,
            "chain_count": 1,
            "home": str(tmp_path),
            "policy_verdict_counts": {},
            "coverage_gaps": [],
        }

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_gemini_shareable_report", lambda **kw: fake_report
        )
        args = _make_args(output=str(output_path), redact_paths=True)
        rc = cli.cmd_gemini_cli_report(args)
        assert rc == 0
        assert output_path.exists()
        written = output_path.read_text()
        assert str(tmp_path) not in written


class TestCodexAppServerReportRedactPaths:
    def test_redacts_json_stdout(self, tmp_path, monkeypatch, capsys):
        fake_report = {
            "receipt_count": 1,
            "chain_count": 1,
            "home": str(tmp_path),
            "policy_verdict_counts": {},
            "coverage_gaps": [],
        }

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_codex_shareable_report", lambda **kw: fake_report
        )
        args = _make_args(json_flag=True, redact_paths=True)
        rc = cli.cmd_codex_app_server_report(args)
        assert rc == 0
        captured = capsys.readouterr()
        response = json.loads(captured.out.strip())
        assert str(tmp_path) not in json.dumps(response)

    def test_redacts_output_file(self, tmp_path, monkeypatch):
        output_path = tmp_path / "codex-redacted.json"
        fake_report = {
            "receipt_count": 1,
            "chain_count": 1,
            "home": str(tmp_path),
            "policy_verdict_counts": {},
            "coverage_gaps": [],
        }

        import vibap.cli as cli

        monkeypatch.setattr(
            cli, "build_codex_shareable_report", lambda **kw: fake_report
        )
        args = _make_args(output=str(output_path), redact_paths=True)
        rc = cli.cmd_codex_app_server_report(args)
        assert rc == 0
        assert output_path.exists()
        written = output_path.read_text()
        assert str(tmp_path) not in written


# ---------------------------------------------------------------------------
# End-to-end CLI smoke
# ---------------------------------------------------------------------------

def test_claude_code_report_redact_paths_e2e_json(tmp_path, capsys):
    """Full argparse + handler path: ``--json --redact-paths`` produces redacted JSON."""

    from vibap.cli import build_parser

    home = tmp_path / "empty-home"
    home.mkdir()
    parser = build_parser()
    args = parser.parse_args(
        [
            "claude-code-report",
            "--json",
            "--redact-paths",
            "--home",
            str(home),
        ]
    )
    rc = args.func(args)
    assert rc == 0
    captured = capsys.readouterr()
    response = json.loads(captured.out.strip())
    assert str(home) not in json.dumps(response)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

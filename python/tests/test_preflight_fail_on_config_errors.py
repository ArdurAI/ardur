"""Tests for preflight tool-server --fail-on exit code semantics (F9 DX fix).

When --fail-on is set to a severity other than 'none', config parse errors
(ToolPreflightError/RuntimeEvidenceError) should exit 2, matching the user's
intent of "exit 2 on failures." When --fail-on is 'none' (default), config
errors preserve the current exit 1 behavior.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from vibap.cli import cmd_tool_server_preflight


def _make_args(
    config: str,
    fail_on: str = "none",
    format: str = "json",
    output: str | None = None,
    json_flag: bool = False,
) -> argparse.Namespace:
    """Build a Namespace matching tool_server_preflight subparser output."""
    ns = argparse.Namespace()
    ns.config = config
    ns.fail_on = fail_on
    ns.format = format
    ns.output = output
    ns.json = json_flag
    return ns


# ---------------------------------------------------------------------------
# Config parse errors with --fail-on set
# ---------------------------------------------------------------------------


def test_empty_servers_with_fail_on_exits_2(tmp_path: Path, capsys):
    """Empty mcpServers with --fail-on low should exit 2 (config parse error)."""
    config = tmp_path / "config.json"
    config.write_text('{"mcpServers":{}}')
    args = _make_args(config=str(config), fail_on="low")
    rc = cmd_tool_server_preflight(args)
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert rc == 2
    assert result["ok"] is False
    assert result["condition"] == "server_collection_empty"


def test_empty_servers_without_fail_on_exits_1(tmp_path: Path, capsys):
    """Empty mcpServers without --fail-on (default none) preserves exit 1."""
    config = tmp_path / "config.json"
    config.write_text('{"mcpServers":{}}')
    args = _make_args(config=str(config), fail_on="none")
    rc = cmd_tool_server_preflight(args)
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert rc == 1
    assert result["ok"] is False


def test_empty_servers_fail_on_critical_exits_2(tmp_path: Path, capsys):
    """Empty mcpServers with --fail-on critical should exit 2."""
    config = tmp_path / "config.json"
    config.write_text('{"mcpServers":{}}')
    args = _make_args(config=str(config), fail_on="critical")
    rc = cmd_tool_server_preflight(args)
    assert rc == 2


def test_malformed_json_with_fail_on_exits_2(tmp_path: Path, capsys):
    """Malformed JSON with --fail-on low should exit 2."""
    config = tmp_path / "config.json"
    config.write_text("{invalid json")
    args = _make_args(config=str(config), fail_on="low")
    rc = cmd_tool_server_preflight(args)
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert rc == 2
    assert result["ok"] is False
    assert result["condition"] == "config_malformed"


def test_malformed_json_without_fail_on_exits_1(tmp_path: Path, capsys):
    """Malformed JSON without --fail-on (default none) preserves exit 1."""
    config = tmp_path / "config.json"
    config.write_text("{invalid json")
    args = _make_args(config=str(config), fail_on="none")
    rc = cmd_tool_server_preflight(args)
    assert rc == 1


# ---------------------------------------------------------------------------
# Valid config with findings — threshold semantics unchanged
# ---------------------------------------------------------------------------


def test_valid_config_critical_finding_with_fail_on_critical_exits_2(
    tmp_path: Path, capsys
):
    """Valid config producing critical findings with --fail-on critical exits 2."""
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"risky": {"command": "bash", "args": ["-c", "echo hi"]}}}
        )
    )
    args = _make_args(config=str(config), fail_on="critical")
    rc = cmd_tool_server_preflight(args)
    assert rc == 2


def test_valid_config_without_fail_on_exits_0(tmp_path: Path, capsys):
    """Valid config with findings but --fail-on none exits 0."""
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"risky": {"command": "bash", "args": ["-c", "echo hi"]}}}
        )
    )
    args = _make_args(config=str(config), fail_on="none")
    rc = cmd_tool_server_preflight(args)
    assert rc == 0


# ---------------------------------------------------------------------------
# Markdown format — config errors still respect --fail-on
# ---------------------------------------------------------------------------


def test_empty_servers_fail_on_low_markdown_exits_2(tmp_path: Path, capsys):
    """Empty mcpServers with --fail-on low in markdown format exits 2."""
    config = tmp_path / "config.json"
    config.write_text('{"mcpServers":{}}')
    args = _make_args(config=str(config), fail_on="low", format="markdown")
    rc = cmd_tool_server_preflight(args)
    captured = capsys.readouterr()
    assert rc == 2
    assert "server_collection_empty" in captured.out


# ---------------------------------------------------------------------------
# All --fail-on severity levels trigger exit 2 on config errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
def test_config_error_all_fail_on_levels_exit_2(
    tmp_path: Path, capsys, severity: str
):
    """Config parse error exits 2 for every non-none --fail-on level."""
    config = tmp_path / "config.json"
    config.write_text('{"mcpServers":{}}')
    args = _make_args(config=str(config), fail_on=severity)
    rc = cmd_tool_server_preflight(args)
    assert rc == 2

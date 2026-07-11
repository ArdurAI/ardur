from __future__ import annotations

import json

import pytest

from vibap.cli import main


@pytest.mark.parametrize(
    ("option", "value", "condition"),
    [
        ("--home", "", "claude_code_report_home_empty"),
        ("--home", "   ", "claude_code_report_home_empty"),
        ("--chain-dir", "", "claude_code_report_chain_dir_empty"),
        ("--chain-dir", "   ", "claude_code_report_chain_dir_empty"),
        ("--keys-dir", "", "claude_code_report_keys_dir_empty"),
        ("--keys-dir", "   ", "claude_code_report_keys_dir_empty"),
    ],
)
def test_claude_code_report_rejects_empty_or_whitespace_path_args(
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: str,
    condition: str,
) -> None:
    """Report paths must fail before argparse can normalize empty input to CWD."""

    rc = main(["claude-code-report", "--json", option, value])

    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err == ""
    payload = json.loads(captured.out)
    rendered = json.dumps(payload, sort_keys=True)
    assert payload["ok"] is False
    assert payload["error"] == condition
    assert payload["error_code"] == condition
    assert payload["condition"] == condition
    assert "empty" in payload["message"].lower()
    assert "Traceback" not in rendered
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])

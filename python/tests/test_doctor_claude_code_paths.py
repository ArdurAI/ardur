from __future__ import annotations

import json
from unittest import mock

import pytest

from vibap.cli import main


@pytest.mark.parametrize(
    ("option", "value", "condition"),
    [
        ("--home", "", "doctor_claude_code_home_empty"),
        ("--home", "   ", "doctor_claude_code_home_empty"),
        ("--home", "\t\n  ", "doctor_claude_code_home_empty"),
        ("--plugin-dir", "", "doctor_claude_code_plugin_dir_empty"),
        ("--plugin-dir", "   ", "doctor_claude_code_plugin_dir_empty"),
        ("--plugin-dir", "\t\n  ", "doctor_claude_code_plugin_dir_empty"),
    ],
)
def test_doctor_claude_code_rejects_empty_or_whitespace_path_args(
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: str,
    condition: str,
) -> None:
    """Empty/whitespace --home or --plugin-dir must fail before diagnostics.

    Previously both args were ``type=Path`` and argparse normalized ``""`` to
    ``PosixPath('.')`` (the CWD), which silently produced misleading diagnostic
    output with corrupted path fragments. Both args are now ``type=str`` and a
    pre-validation guard rejects empty/whitespace-only input with structured
    JSON before any diagnostic check runs.
    """

    rc = main(["doctor-claude-code", option, value])

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
    # No raw input value is echoed and no local absolute path leaks.
    assert value.strip() == ""  # sanity: the input really was whitespace-only
    assert "Traceback" not in rendered
    # next_steps use placeholder commands, never the raw input.
    assert all(
        "<" in step["command"] and ">" in step["command"]
        for step in payload["next_steps"]
    )


def test_doctor_claude_code_omitted_home_omitted_plugin_dir_proceeds(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Omitting both flags must reach diagnostics normally (defaults apply)."""

    fake_response = {"ok": True, "checks": []}
    with mock.patch("vibap.cli.claude_code_doctor", return_value=fake_response) as patched:
        rc = main(["doctor-claude-code"])
    assert rc == 0
    assert patched.called
    # home defaults to None; plugin_dir defaults to the stringified default.
    kwargs = patched.call_args.kwargs
    assert kwargs["home"] is None
    assert kwargs["plugin_dir"] is not None


def test_doctor_claude_code_valid_home_and_plugin_dir_proceeds(
    capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    """Valid explicit paths must reach diagnostics and be coerced to Path."""

    fake_response = {"ok": True, "checks": []}
    with mock.patch("vibap.cli.claude_code_doctor", return_value=fake_response) as patched:
        rc = main(
            [
                "doctor-claude-code",
                "--home",
                str(tmp_path),
                "--plugin-dir",
                str(tmp_path),
            ]
        )
    captured = capsys.readouterr()
    assert rc == 0
    assert patched.called
    kwargs = patched.call_args.kwargs
    # After validation, _coerce_report_path_args converts non-empty strings to Path.
    assert hasattr(kwargs["home"], "expanduser")
    assert hasattr(kwargs["plugin_dir"], "expanduser")
    # No local absolute path leaks into the JSON output (fake response has none).
    assert str(tmp_path) not in captured.out


def test_doctor_claude_code_explicit_dot_home_proceeds(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An explicit ``--home .`` (CWD) must remain valid — only empty is rejected."""

    fake_response = {"ok": True, "checks": []}
    with mock.patch("vibap.cli.claude_code_doctor", return_value=fake_response) as patched:
        rc = main(["doctor-claude-code", "--home", "."])
    assert rc == 0
    assert patched.called

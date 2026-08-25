"""Regression tests for empty/whitespace path validation on
``protect claude-code`` policy input arguments ``--forbid-rules`` and
``--cedar-policy``.

Companion to the sibling sweeps landed in 86cab36 (fixture/report path args),
aca1c34 (report path args), and fd33fd5 (--cedar-entities). These two arguments
were the remaining bare ``type=Path`` arguments on the ``protect claude-code``
subcommand. With ``type=Path``, an empty string silently normalized to
``PosixPath('.')`` and produced a confusing downstream file-read error against
the current working directory.

The fix parses the arguments as ``str`` and rejects empty/whitespace input
inside ``_resolve_protect_policies`` before any ``Path()`` conversion or file
read, raising ``_ProtectPolicyInputError`` with stable condition names.
"""

from __future__ import annotations

import json

import pytest

from vibap import cli


def _protect_args(tmp_path, **overrides):
    """Build parsed args for ``ardur protect claude-code``."""
    argv = [
        "protect",
        "claude-code",
        "--scope",
        str(tmp_path / "project"),
        "--home",
        str(tmp_path / "home"),
        "--plugin-dir",
        str(tmp_path),
        "--json",
    ]
    for key, value in overrides.items():
        flag = "--" + key.replace("_", "-")
        if value is None:
            continue
        argv.extend([flag, str(value)])
    parser = cli.build_parser()
    return parser.parse_args(argv)


def _patch_protect_success_except_policies(monkeypatch):
    """Mock heavy dependencies so the empty-path check is what fires.

    Identical to ``_patch_protect_success_keep_policy_resolution`` in
    ``test_cli_protect.py`` except ``_resolve_protect_policies`` is left
    UNPATCHED so the real empty/whitespace validation runs and raises
    ``_ProtectPolicyInputError``.
    """
    monkeypatch.setattr(cli, "load_ardur_profile", lambda path: None)
    monkeypatch.setattr(cli, "generate_keypair", lambda keys_dir=None: ("pk", "pub"))
    monkeypatch.setattr(cli, "issue_passport", lambda *a, **kw: "token")
    monkeypatch.setattr(cli, "verify_passport", lambda *a, **kw: {})
    monkeypatch.setattr(cli, "_write_private_text", lambda path, text: None)
    monkeypatch.setattr(
        cli, "install_native_pre_tool_use_command", lambda home=None: None
    )
    monkeypatch.setattr(
        cli, "resolve_native_pre_tool_use_command_path", lambda home=None: None
    )
    monkeypatch.setattr(
        cli, "_claude_code_plugin_checks", lambda plugin_dir: [{"ok": True}]
    )
    monkeypatch.setattr(cli, "_claude_code_plugin_content_checks", lambda plugin_dir: [])


def _assert_empty_failure(capsys, exit_code, condition, option):
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    assert "Traceback" not in captured.out
    payload = json.loads(captured.out)
    rendered = json.dumps(payload, sort_keys=True)
    assert payload["ok"] is False
    assert payload["condition"] == condition
    assert payload["error"] == "protect_policy_input_invalid"
    assert payload["policy_input"] == option
    assert "empty" in payload["detail"].lower()
    # next_steps must be present and use placeholder-only commands (no real paths)
    assert payload["next_steps"]
    for step in payload["next_steps"]:
        assert step["condition"] == condition
        assert "<" in step["command"] and ">" in step["command"]
    assert "Traceback" not in rendered


@pytest.mark.parametrize(
    ("option", "attr", "value", "condition"),
    [
        ("--forbid-rules", "forbid_rules", "", "protect_forbid_rules_empty"),
        ("--forbid-rules", "forbid_rules", "   ", "protect_forbid_rules_empty"),
        ("--cedar-policy", "cedar_policy", "", "protect_cedar_policy_empty"),
        ("--cedar-policy", "cedar_policy", "   ", "protect_cedar_policy_empty"),
    ],
)
def test_protect_claude_code_rejects_empty_or_whitespace_policy_path_args(
    monkeypatch,
    capsys,
    tmp_path,
    option,
    attr,
    value,
    condition,
) -> None:
    """Empty/whitespace policy path args must fail before Path() normalization.

    Previously ``type=Path`` normalized ``""`` to ``PosixPath('.')`` so an empty
    ``--forbid-rules``/``--cedar-policy`` produced a confusing file-read error.
    The args now parse as ``str`` and ``_resolve_protect_policies`` rejects
    empty/whitespace before any file read, raising a structured
    ``_ProtectPolicyInputError``.
    """
    _patch_protect_success_except_policies(monkeypatch)
    args = _protect_args(tmp_path, **{attr: value})
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_empty_failure(capsys, exit_code, condition, option)


@pytest.mark.parametrize(
    ("option", "attr"),
    [
        ("--forbid-rules", "forbid_rules"),
        ("--cedar-policy", "cedar_policy"),
    ],
)
def test_protect_claude_code_omitted_policy_args_succeed(
    monkeypatch, capsys, tmp_path, option, attr
) -> None:
    """Omitting a policy arg (None) must continue to succeed unchanged."""
    _patch_protect_success_except_policies(monkeypatch)
    # Also stub _resolve_protect_policies for the success path so no real file
    # IO happens for the omitted-args case.
    monkeypatch.setattr(cli, "_resolve_protect_policies", lambda *a, **kw: [])
    args = _protect_args(tmp_path)
    exit_code = cli.cmd_protect_claude_code(args)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Traceback" not in captured.out

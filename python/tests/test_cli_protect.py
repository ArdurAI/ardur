from __future__ import annotations

import json

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


def _assert_protect_failure(capsys, exit_code, condition):
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    assert "Traceback" not in captured.out
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["condition"] == condition
    assert payload["next_steps"]
    # next_steps must use placeholder-only commands (no real paths)
    rendered = json.dumps(payload["next_steps"], sort_keys=True)
    assert "<" in rendered


def _patch_protect_success(monkeypatch):
    """Mock heavy dependencies so ``protect_claude_code`` can succeed."""
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
    monkeypatch.setattr(cli, "_resolve_protect_policies", lambda *a, **kw: {})


def test_protect_profile_empty_rejected(capsys, tmp_path):
    """``--profile \"\"`` must return structured failure, no traceback."""
    args = _protect_args(tmp_path, profile="")
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_profile_invalid")


def test_protect_profile_whitespace_rejected(capsys, tmp_path):
    """``--profile \"   \"`` must return structured failure, no traceback."""
    args = _protect_args(tmp_path, profile="   ")
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_profile_invalid")


def test_protect_profile_nonexistent_rejected(capsys, tmp_path):
    """``--profile /tmp/nonexistent`` must return ``profile_missing``."""
    args = _protect_args(tmp_path, profile="/tmp/nonexistent-ardur-profile-md")
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "profile_missing")


def test_protect_profile_directory_rejected(capsys, tmp_path):
    """``--profile .`` (CWD, a directory) must be rejected."""
    args = _protect_args(tmp_path, profile=".")
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_profile_invalid")


def test_protect_profile_omitted_succeeds(monkeypatch, tmp_path, capsys):
    """``--profile`` omitted (None) must succeed with mode defaults."""
    _patch_protect_success(monkeypatch)
    args = _protect_args(tmp_path)
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out


def test_protect_profile_valid_succeeds(monkeypatch, tmp_path, capsys):
    """``--profile <valid-file>`` must succeed."""
    _patch_protect_success(monkeypatch)
    profile_file = tmp_path / "ARDUR.md"
    profile_file.write_text("# Test Profile\nmode: safe-coding\n", encoding="utf-8")
    args = _protect_args(tmp_path, profile=str(profile_file))
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out

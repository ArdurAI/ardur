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


def _patch_protect_success_keep_policy_resolution(monkeypatch):
    """Like ``_patch_protect_success`` but leaves ``_resolve_protect_policies`` live.

    Used by tests that exercise the real policy-input validation path
    (empty/whitespace pre-checks, cedar syntax/entity validators).
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


# ---------------------------------------------------------------------------
# --cedar-entities empty/whitespace validation (conditionally-guarded arg)
#
# ``--cedar-entities`` is only read inside the ``if cedar_policy is not None:``
# block in ``_resolve_protect_policies``. When passed WITHOUT ``--cedar-policy``
# an empty/whitespace-only value was previously silently ignored (exit 0,
# "protection configured"). These tests verify the up-front validation that
# surfaces the empty/whitespace defect as a structured error in both the
# standalone and paired cases.
# ---------------------------------------------------------------------------


def test_protect_cedar_entities_empty_standalone_rejected(monkeypatch, tmp_path, capsys):
    """``--cedar-entities ""`` (standalone, no ``--cedar-policy``) must fail."""
    _patch_protect_success_keep_policy_resolution(monkeypatch)
    args = _protect_args(tmp_path, cedar_entities="")
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_cedar_entities_empty")


def test_protect_cedar_entities_whitespace_standalone_rejected(monkeypatch, tmp_path, capsys):
    """``--cedar-entities "   "`` (standalone, no ``--cedar-policy``) must fail."""
    _patch_protect_success_keep_policy_resolution(monkeypatch)
    args = _protect_args(tmp_path, cedar_entities="   ")
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_cedar_entities_empty")


def test_protect_cedar_entities_whitespace_with_policy_still_rejected(monkeypatch, tmp_path, capsys):
    """``--cedar-entities "   "`` paired with a valid ``--cedar-policy`` must still fail.

    The pre-validation must fire BEFORE the ``if cedar_policy is not None:``
    conditional block so the empty/whitespace defect is caught regardless of
    whether ``--cedar-policy`` is present.
    """
    _patch_protect_success_keep_policy_resolution(monkeypatch)
    policy_file = tmp_path / "policy.cedar"
    policy_file.write_text('permit (principal, action, resource);\n', encoding="utf-8")
    args = _protect_args(tmp_path, cedar_policy=str(policy_file), cedar_entities="   ")
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_cedar_entities_empty")


def test_protect_cedar_entities_valid_with_policy_succeeds(monkeypatch, tmp_path, capsys):
    """``--cedar-entities <valid-json>`` with ``--cedar-policy`` must succeed (regression).

    A valid entities JSON file (``[]``) paired with a syntactically valid Cedar
    policy must configure protection normally. This guards against the
    pre-validation accidentally rejecting legitimate non-empty paths.
    """
    _patch_protect_success_keep_policy_resolution(monkeypatch)
    policy_file = tmp_path / "policy.cedar"
    policy_file.write_text('permit (principal, action, resource);\n', encoding="utf-8")
    entities_file = tmp_path / "entities.json"
    entities_file.write_text("[]", encoding="utf-8")
    args = _protect_args(
        tmp_path,
        cedar_policy=str(policy_file),
        cedar_entities=str(entities_file),
    )
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out

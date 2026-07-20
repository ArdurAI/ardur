"""Reject dangling-symlink ``--keys-dir`` on ``ardur protect claude-code``.

Smoke-verified 2026-07-18: ``Path.exists()`` returns False for a dangling
symlink (symlink whose target does not exist), so the previous
``keys_dir_path.exists() and keys_dir_path.is_file()`` check let dangling
symlinks pass through.  Ardur then resolved the keys-dir to a non-existent
target and proceeded with key generation against a directory that does
not exist.

This is the same ``path-prevalidation-symlink-parent-trap`` pattern that
affected ``--scope`` (closed in commit b48ac0b).  The fix adds an explicit
``keys_dir_path.is_symlink() and not keys_dir_path.exists()`` branch
BEFORE the regular-file check, returning the existing structured
``protect_keys_dir_invalid`` JSON response before any key generation or
artifact write.

Cases covered (matching task acceptance criteria):
  1. dangling symlink        -> exit 1, ``protect_keys_dir_invalid`` JSON, no key write
  2. valid existing dir      -> proceeds (exit 0 under mocked success path)
  3. regular file            -> rejected (preserves existing behaviour)
  4. CWD (``.``)             -> proceeds (preserves existing behaviour)
  5. nonexistent non-symlink -> proceeds (Ardur creates the keys dir during protection)
  6. symlink-to-existing-dir -> proceeds (``Path.exists()`` follows the link and is True)
"""
from __future__ import annotations

import json
import os

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


# ---------------------------------------------------------------------------
# Acceptance case 1: dangling symlink rejected before key generation
# ---------------------------------------------------------------------------


def test_protect_keys_dir_dangling_symlink_rejected(capsys, tmp_path):
    """``--keys-dir <dangling-symlink>`` must return structured failure, no key write.

    The validation must fire BEFORE any key generation, Mission Passport JWT
    issuance, or artifact creation.  We assert that ``generate_keypair`` is
    never called by NOT patching it: if the pre-validation fails to fire,
    the real ``generate_keypair`` will run and either create real keys or
    raise, both of which would surface as test failure.
    """
    dangling = tmp_path / "dangling-keys-dir"
    os.symlink(tmp_path / "does-not-exist", dangling)
    args = _protect_args(tmp_path, keys_dir=str(dangling))
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_keys_dir_invalid")
    # No keys written: the dangling target must not have materialized.
    assert not (tmp_path / "does-not-exist").exists(), (
        "keys target created under dangling-symlink keys-dir despite early-reject"
    )


# ---------------------------------------------------------------------------
# Acceptance case 2: valid existing dir proceeds
# ---------------------------------------------------------------------------


def test_protect_keys_dir_valid_existing_dir_proceeds(monkeypatch, tmp_path, capsys):
    """``--keys-dir <valid-existing-dir>`` must succeed (regression guard)."""
    _patch_protect_success(monkeypatch)
    real_keys_dir = tmp_path / "real-keys-dir"
    real_keys_dir.mkdir()
    args = _protect_args(tmp_path, keys_dir=str(real_keys_dir))
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out


# ---------------------------------------------------------------------------
# Acceptance case 3: regular file still rejected (existing behaviour preserved)
# ---------------------------------------------------------------------------


def test_protect_keys_dir_regular_file_rejected(capsys, tmp_path):
    """``--keys-dir <regular-file>`` must remain rejected."""
    regular = tmp_path / "regular-file-keys-dir"
    regular.write_text("not a dir\n", encoding="utf-8")
    args = _protect_args(tmp_path, keys_dir=str(regular))
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_keys_dir_invalid")


# ---------------------------------------------------------------------------
# Acceptance case 4: CWD (``.``) still valid
# ---------------------------------------------------------------------------


def test_protect_keys_dir_cwd_valid(monkeypatch, tmp_path, capsys):
    """``--keys-dir .`` (CWD) must remain valid."""
    _patch_protect_success(monkeypatch)
    args = _protect_args(tmp_path, keys_dir=".")
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out


# ---------------------------------------------------------------------------
# Acceptance case 5: nonexistent non-symlink path proceeds
# ---------------------------------------------------------------------------


def test_protect_keys_dir_nonexistent_nonsymlink_proceeds(monkeypatch, tmp_path, capsys):
    """``--keys-dir <nonexistent-path>`` (not a symlink) must proceed.

    Ardur creates the keys directory during protection, so a plain missing
    path is legitimate.  Only dangling symlinks are rejected because they
    look like they point somewhere but resolve to a missing target.
    """
    _patch_protect_success(monkeypatch)
    nonexistent = tmp_path / "does-not-exist-yet-keys-dir"
    args = _protect_args(tmp_path, keys_dir=str(nonexistent))
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out


# ---------------------------------------------------------------------------
# Acceptance case 6: symlink-to-existing-dir proceeds
# ---------------------------------------------------------------------------


def test_protect_keys_dir_symlink_to_existing_dir_proceeds(monkeypatch, tmp_path, capsys):
    """``--keys-dir <symlink-to-existing-dir>`` must proceed.

    ``Path.exists()`` follows the symlink and returns True when the target
    exists, so the dangling-symlink guard correctly does NOT fire here.
    """
    _patch_protect_success(monkeypatch)
    real_target = tmp_path / "real-target-keys-dir"
    real_target.mkdir()
    link = tmp_path / "keys-dir-link"
    os.symlink(real_target, link)
    args = _protect_args(tmp_path, keys_dir=str(link))
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out

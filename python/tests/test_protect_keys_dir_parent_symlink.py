"""Reject dangling-parent-symlink ``--keys-dir`` on ``ardur protect claude-code``.

Companion to ``test_protect_keys_dir_dangling_symlink.py`` (leaf-level dangling
symlink) and mirrors the parent-component walk added for ``--home`` in ad96e40.

The leaf-only ``keys_dir_path.is_symlink() and not keys_dir_path.exists()``
check from commit b48ac0b inspects only the final path component.  A
``--keys-dir <dangling-parent>/keys`` argument is invisible to that check:

* ``Path(<dangling>/keys).is_symlink()`` returns False (``keys`` is the leaf,
  not the symlink).
* ``Path(<dangling>/keys).resolve()`` follows the parent symlink and returns
  the missing-target path ``/missing/keys``.
* ``resolve_keys_dir()`` calls ``mkdir(parents=True)`` which silently
  materialises the missing target and writes the Ed25519 private key
  (``passport_private.pem``) at a location the user did not type.

The fix adds a parent-component walk for ``--keys-dir`` that mirrors the
``validate_personal_home_path_components`` helper from ad96e40: walk each
parent of the un-resolved expanded ``--keys-dir`` path and reject if any
parent is a dangling symlink or an existing non-directory, BEFORE any
``Path.resolve()`` / ``mkdir(parents=True)`` / key generation.

Cases covered:
  1. dangling parent symlink        -> reject, no key write at resolved target
  2. regular-file parent            -> reject, no key write
  3. symlink-to-existing-dir parent -> proceeds (parent resolves to real dir)
  4. plain nonexistent parent       -> proceeds (Ardur creates the chain)
  5. valid existing keys dir        -> proceeds (regression guard)
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
# Case 1: dangling parent symlink rejected before key generation
# ---------------------------------------------------------------------------


def test_protect_keys_dir_dangling_parent_symlink_rejected(capsys, tmp_path):
    """``--keys-dir <dangling-parent>/keys`` must fail, no key at resolved target.

    The validation must fire BEFORE any key generation or mkdir.  We do NOT
    patch ``generate_keypair``: if the parent walk fails to fire, the real
    ``generate_keypair`` will either create keys at the wrong location or
    raise, both of which surface as test failure.
    """
    missing = tmp_path / "nonexistent-keys-target"
    dangling_parent = tmp_path / "dangling-keys-parent"
    os.symlink(missing, dangling_parent)
    keys_dir = dangling_parent / "keys"

    args = _protect_args(tmp_path, keys_dir=str(keys_dir))
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_keys_dir_invalid")

    # The resolved target must NOT have been materialised by mkdir(parents=True).
    assert not missing.exists(), (
        "keys target materialised under dangling-parent symlink despite early reject"
    )
    assert not (missing / "keys").exists()


# ---------------------------------------------------------------------------
# Case 2: regular-file parent rejected
# ---------------------------------------------------------------------------


def test_protect_keys_dir_regular_file_parent_rejected(capsys, tmp_path):
    """``--keys-dir <regular-file>/keys`` must fail.

    A parent that is a regular file cannot contain a keys directory.  The
    parent walk must reject this before mkdir(parents=True) raises a
    confusing ``NotADirectoryError`` traceback.
    """
    regular_parent = tmp_path / "regular-file-parent"
    regular_parent.write_text("not a dir\n", encoding="utf-8")
    keys_dir = regular_parent / "keys"

    args = _protect_args(tmp_path, keys_dir=str(keys_dir))
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_keys_dir_invalid")


# ---------------------------------------------------------------------------
# Case 3: symlink-to-existing-dir parent proceeds
# ---------------------------------------------------------------------------


def test_protect_keys_dir_symlink_parent_to_existing_dir_proceeds(
    monkeypatch, tmp_path, capsys
):
    """``--keys-dir <symlink-to-real-dir>/keys`` must proceed.

    A parent symlink whose target IS an existing directory must pass: the
    walk sees ``parent.is_symlink() and parent.exists()`` → True, and
    ``parent.is_dir()`` → True, so neither guard fires.
    """
    _patch_protect_success(monkeypatch)
    real_parent = tmp_path / "real-parent-dir"
    real_parent.mkdir()
    link_parent = tmp_path / "link-parent"
    os.symlink(real_parent, link_parent)
    keys_dir = link_parent / "keys"

    args = _protect_args(tmp_path, keys_dir=str(keys_dir))
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out


# ---------------------------------------------------------------------------
# Case 4: plain nonexistent parent proceeds
# ---------------------------------------------------------------------------


def test_protect_keys_dir_nonexistent_parent_proceeds(
    monkeypatch, tmp_path, capsys
):
    """``--keys-dir <nonexistent-parent>/keys`` must proceed.

    A parent chain that simply does not exist yet is legitimate: Ardur
    creates the full chain via ``mkdir(parents=True)``.  Only dangling
    symlinks and existing non-directory parents are rejected.
    """
    _patch_protect_success(monkeypatch)
    keys_dir = tmp_path / "does-not-exist-yet" / "nested" / "keys"

    args = _protect_args(tmp_path, keys_dir=str(keys_dir))
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out


# ---------------------------------------------------------------------------
# Case 5: valid existing keys dir proceeds (regression guard)
# ---------------------------------------------------------------------------


def test_protect_keys_dir_existing_dir_proceeds(monkeypatch, tmp_path, capsys):
    """``--keys-dir <valid-existing-dir>`` must still succeed."""
    _patch_protect_success(monkeypatch)
    real_keys_dir = tmp_path / "real-keys-dir"
    real_keys_dir.mkdir()

    args = _protect_args(tmp_path, keys_dir=str(real_keys_dir))
    exit_code = cli.cmd_protect_claude_code(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Traceback" not in captured.out

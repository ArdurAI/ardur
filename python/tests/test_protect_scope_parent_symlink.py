"""Regression tests for ``--scope`` dangling-parent-symlink rejection.

These verify that ``ardur protect claude-code --scope <dangling-parent>/cedar``
is rejected with a structured JSON error before any key generation, JWT
issuance, or plugin/hook artifact creation.  The parent-component walk
mirrors the ``--home`` and ``--keys-dir`` fixes from ad96e40 and f167304.

A dangling parent symlink (e.g. ``--scope <dangling>/cedar``) is invisible
to the leaf-only checks: ``Path(<dangling>/cedar)`` is not itself a symlink,
and ``Path.resolve()`` follows the symlink chain to the missing target
before the check can see it.  Without the walk, Ardur silently resolves the
scope through the dangling parent and bakes the resolved path into the JWT
``resource_scope``.
"""

from __future__ import annotations

import os
from pathlib import Path

from vibap import cli


def _protect_args(tmp_path: Path, **overrides) -> "cli.argparse.Namespace":
    """Build parsed args for ``ardur protect claude-code``."""
    argv = [
        "protect",
        "claude-code",
        "--scope",
        str(tmp_path / "project"),
        "--home",
        str(tmp_path / "home"),
        "--keys-dir",
        str(tmp_path / "keys"),
        "--json",
    ]
    for key, value in overrides.items():
        flag = "--" + key.replace("_", "-")
        if value is None:
            continue
        argv.extend([flag, str(value)])
    parser = cli.build_parser()
    return parser.parse_args(argv)


def _result_dict(result):
    """Normalize the protect_claude_code return value to a dict."""
    if isinstance(result, dict):
        return result
    if isinstance(result, int):
        # exit code path — should not happen with --json, but handle it
        return {"ok": result == 0, "_exit_code": result}
    return {"_raw": str(result)}


def test_scope_dangling_parent_symlink_rejected(tmp_path: Path) -> None:
    """``--scope <dangling-parent-symlink>/cedar`` must be rejected."""
    dangling = tmp_path / "dangling-link"
    target = tmp_path / "nonexistent-target"
    os.symlink(target, dangling)
    scope = dangling / "cedar"

    args = _protect_args(tmp_path, scope=scope)
    result = _result_dict(cli.protect_claude_code(args))

    assert result["ok"] is False
    assert result["condition"] == "protect_scope_invalid"

    # Confirm no key material was generated at the dangling target
    assert not target.exists(), "Dangling parent target should not be materialized"


def test_scope_regular_file_parent_rejected(tmp_path: Path) -> None:
    """``--scope <existing-regular-file>/cedar`` must be rejected."""
    regular_file = tmp_path / "regular.txt"
    regular_file.write_text("test")
    scope = regular_file / "cedar"

    args = _protect_args(tmp_path, scope=scope)
    result = _result_dict(cli.protect_claude_code(args))

    assert result["ok"] is False
    assert result["condition"] == "protect_scope_invalid"


def test_scope_symlink_parent_to_existing_dir_proceeds(tmp_path: Path) -> None:
    """``--scope <valid-symlink-to-dir>/cedar`` must not be rejected for scope."""
    real_dir = tmp_path / "real-dir"
    real_dir.mkdir()
    valid_link = tmp_path / "valid-link"
    os.symlink(real_dir, valid_link)
    scope = valid_link / "cedar"

    args = _protect_args(tmp_path, scope=scope)
    result = _result_dict(cli.protect_claude_code(args))

    # May fail for other reasons, but should NOT be scope_invalid
    condition = result.get("condition", result.get("error", ""))
    assert condition != "protect_scope_invalid", \
        f"Valid symlink-to-dir parent should not be rejected as scope_invalid: {result}"


def test_scope_nonexistent_parent_proceeds(tmp_path: Path) -> None:
    """``--scope <nonexistent-dir>/cedar`` must not be rejected for scope."""
    scope = tmp_path / "nonexistent" / "cedar"

    args = _protect_args(tmp_path, scope=scope)
    result = _result_dict(cli.protect_claude_code(args))

    condition = result.get("condition", result.get("error", ""))
    assert condition != "protect_scope_invalid", \
        f"Nonexistent non-symlink parent should not be rejected: {result}"


def test_scope_existing_dir_proceeds(tmp_path: Path) -> None:
    """``--scope <existing-dir>/cedar`` must not be rejected for scope."""
    existing_dir = tmp_path / "project"
    existing_dir.mkdir()
    scope = existing_dir / "cedar"

    args = _protect_args(tmp_path, scope=scope)
    result = _result_dict(cli.protect_claude_code(args))

    condition = result.get("condition", result.get("error", ""))
    assert condition != "protect_scope_invalid", \
        f"Existing dir parent should not be rejected: {result}"

"""Reject ``--home <dangling-symlink>/child`` on ``ardur run``, ``setup``,
and ``protect claude-code`` (parent-component path-confusion).

Regression coverage for the defect documented in
``CONTINUOUS_DEV_PROBE_20260727T2245CDT_DANGLING_PARENT_SYMLINK_HOME_PATH_LEAK_6D1CD7E.md``.
Mirrors the 2026-06-28 ``ardur start --state-dir`` / ``--log-path`` fix
extended to the personal-hub ``--home`` surface.

Why a parent walk is needed (and the leaf-only checks are not enough):

  ``--home <dangling-symlink>/child``

  * ``Path(...).expanduser().is_symlink()`` inspects only the LEAF (``child``),
    which is a plain nonexistent path, so ``is_symlink()`` returns False.
  * ``Path(...).expanduser().resolve()`` FOLLOWS the symlink and returns the
    missing-target path ``/missing/child``.
  * ``resolved.exists()`` returns False (the target does not exist).
  * ``home.mkdir(parents=True, exist_ok=True)`` then silently materialises
    the missing target and Ardur writes the Ed25519 private key,
    ``active_mission.jwt``, state, and governance log there.

The fix walks each parent component of the UN-RESOLVED expanded path and
rejects when any parent is a dangling symlink or an existing non-directory,
BEFORE any ``Path.resolve()`` / ``mkdir(parents=True)`` runs.

Cases covered (matching the task acceptance criteria):

  run (stderr + exit 2 contract):
    1. dangling-symlink parent        -> exit 2, structured stderr, no artifacts
    2. regular-file parent            -> exit 2, structured stderr, no artifacts
    3. valid new path                 -> proceeds (regression guard)
    4. real directory                 -> proceeds (regression guard)
    5. symlink-to-existing-dir parent -> proceeds (regression guard)

  setup / protect claude-code (structured JSON + exit 1 contract):
    6. dangling-symlink parent        -> exit 1, ``home_dangling_symlink_parent``
    7. regular-file parent            -> exit 1, ``home_parent_not_directory``
    8. direct dangling symlink leaf   -> preserved (protect_home_invalid / setup)
    9. valid new path                 -> proceeds
   10. real directory                 -> proceeds

  shared helper:
   11. validate_personal_home_path_components unit cases (dangling parent,
       regular-file parent, direct dangling leaf passes through, valid path
       passes through).
"""
from __future__ import annotations

import json
import os

import pytest

from vibap import cli, personal_hub, run_bridge


# ---------------------------------------------------------------------------
# Shared helper unit cases
# ---------------------------------------------------------------------------


def test_validate_personal_home_path_components_dangling_parent(tmp_path):
    """A dangling symlink in the parent chain raises the parent-dangling
    HubError, BEFORE any resolve/mkdir follows the link."""
    missing = tmp_path / "missing-target"
    dangle = tmp_path / "dangle-link"
    os.symlink(missing, dangle)
    with pytest.raises(personal_hub.HubError) as exc_info:
        personal_hub.validate_personal_home_path_components(str(dangle / "child"))
    assert exc_info.value.code == personal_hub.HOME_DANGLING_SYMLINK_PARENT_CONDITION


def test_validate_personal_home_path_components_regular_file_parent(tmp_path):
    """A regular file in the parent chain raises the parent-not-directory
    HubError."""
    regular = tmp_path / "regular-file"
    regular.write_text("not a dir\n", encoding="utf-8")
    with pytest.raises(personal_hub.HubError) as exc_info:
        personal_hub.validate_personal_home_path_components(str(regular / "child"))
    assert exc_info.value.code == personal_hub.HOME_PARENT_NOT_DIRECTORY_CONDITION


def test_validate_personal_home_path_components_valid_path_passes(tmp_path):
    """A plain nonexistent path and a real directory both pass through
    (regression guard)."""
    # Should not raise.
    personal_hub.validate_personal_home_path_components(str(tmp_path / "fresh-home"))
    real_dir = tmp_path / "real-dir"
    real_dir.mkdir()
    personal_hub.validate_personal_home_path_components(str(real_dir))


def test_validate_personal_home_path_components_symlink_to_dir_passes(tmp_path):
    """A symlink whose target is an existing directory passes through
    (the dangling check is ``is_symlink() and not exists()``, which is
    False when the target exists)."""
    real = tmp_path / "real-target"
    real.mkdir()
    link = tmp_path / "good-link"
    os.symlink(real, link)
    # Should not raise.
    personal_hub.validate_personal_home_path_components(str(link / "child"))


# ---------------------------------------------------------------------------
# ardur run: dangling-symlink parent
# ---------------------------------------------------------------------------


def _run_args(tmp_path, **overrides):
    """Build a Namespace for ``run_governed_cli`` with a dangling-parent home."""
    from argparse import Namespace

    base = dict(
        command=["echo", "hi"],
        mission="example-mission-placeholder",
        allowed_tools=["Read"],
        forbidden_tools=None,
        max_tool_calls=5,
        max_duration_s=60,
        home=None,
        via="env",
        no_kernel_correlation=True,
    )
    base.update(overrides)
    return Namespace(**base)


def _patch_run_governed_to_assert_not_called(monkeypatch):
    """If the pre-validation fails to fire, the real run_governed runs and
    either creates real keys or raises — both surface as test failure."""

    def fail(**_kwargs):
        raise AssertionError(
            "dangling-parent home must be rejected before governed launch"
        )

    monkeypatch.setattr("vibap.run_bridge.run_governed", fail)


def test_run_governed_cli_dangling_symlink_parent_rejected_before_artifacts(
    tmp_path, capsys, monkeypatch
):
    """``--home <dangling-symlink>/child`` must be rejected with exit 2,
    structured stderr, no artifacts, no resolved-path leak."""
    missing_target = tmp_path / "nonexistent-target"
    dangle = tmp_path / "dangling-parent-link"
    os.symlink(missing_target, dangle)
    _patch_run_governed_to_assert_not_called(monkeypatch)

    exit_code = run_bridge.run_governed_cli(
        _run_args(tmp_path, home=str(dangle / "child"))
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Traceback" not in captured.err
    # Placeholder-only contract: no raw path leak.
    assert str(dangle) not in captured.err
    assert str(missing_target) not in captured.err
    assert "parent component that is a dangling symlink" in captured.err
    assert "Next steps:" in captured.err
    # The dangling symlink must still be a dangling symlink (unchanged).
    assert dangle.is_symlink()
    assert not missing_target.exists()
    # No Ardur artifacts created at either requested or resolved path.
    assert not (dangle / "child" / "keys").exists()
    assert not (dangle / "child" / "active_mission.jwt").exists()
    assert not (missing_target / "child").exists()


def test_run_governed_cli_regular_file_parent_rejected_before_artifacts(
    tmp_path, capsys, monkeypatch
):
    """``--home <regular-file>/child`` must be rejected with exit 2 and
    structured stderr."""
    regular = tmp_path / "regular-parent-file"
    regular.write_text("not a dir\n", encoding="utf-8")
    _patch_run_governed_to_assert_not_called(monkeypatch)

    exit_code = run_bridge.run_governed_cli(
        _run_args(tmp_path, home=str(regular / "child"))
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert str(regular) not in captured.err
    assert "parent component that is an existing non-directory" in captured.err
    assert "Next steps:" in captured.err


def test_run_governed_cli_symlink_to_existing_dir_parent_proceeds(
    tmp_path, monkeypatch
):
    """``--home <symlink-to-existing-dir>/child`` must proceed normally.

    Regression guard against an over-broad fix that would reject legitimate
    symlinks-to-real-directories in the parent chain.
    """
    real_target = tmp_path / "real-target-home"
    real_target.mkdir()
    link = tmp_path / "good-parent-link"
    os.symlink(real_target, link)

    from vibap.run_bridge import GovernanceRunResult

    def stub(**_kwargs):
        return GovernanceRunResult(
            exit_code=0,
            session_id="stub-session",
            mission_id="stub-mission",
            agent_id="stub-agent",
            adapter="stub-adapter",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home=str(link / "child"),
            passport_path=str(tmp_path / "passport.jwt"),
            summary={"ok": True},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="stub-token",
            attestation_digest="sha-256:" + "0" * 64,
            receipts_path=str(tmp_path / "receipts.jsonl"),
            receipt_count=0,
            correlation={},
            kernel_policy={},
        )

    monkeypatch.setattr("vibap.run_bridge.run_governed", stub)
    exit_code = run_bridge.run_governed_cli(
        _run_args(tmp_path, home=str(link / "child"))
    )
    assert exit_code == 0


def test_run_governed_home_dangling_symlink_parent_next_steps_are_deterministic():
    """The next_steps list for run_home_dangling_symlink_parent must use
    placeholder-only commands and the documented condition."""
    steps = run_bridge.run_governed_home_dangling_symlink_parent_next_steps()
    assert steps
    for step in steps:
        assert step["condition"] == "run_home_dangling_symlink_parent"
        assert "<" in step["command"]  # placeholder-only


def test_run_governed_home_parent_not_directory_next_steps_are_deterministic():
    steps = run_bridge.run_governed_home_parent_not_directory_next_steps()
    assert steps
    for step in steps:
        assert step["condition"] == "run_home_parent_not_directory"
        assert "<" in step["command"]


# ---------------------------------------------------------------------------
# ardur setup: dangling-symlink parent + regular-file parent
# ---------------------------------------------------------------------------


def _setup_args(tmp_path, **overrides):
    argv = ["setup", "--home", str(tmp_path / "home")]
    for key, value in overrides.items():
        flag = "--" + key.replace("_", "-")
        if value is None:
            continue
        argv.extend([flag, str(value)])
    parser = cli.build_parser()
    return parser.parse_args(argv)


def test_cmd_setup_dangling_symlink_parent_rejected(tmp_path, capsys):
    """``ardur setup --home <dangling-symlink>/child`` must return structured
    JSON ``home_dangling_symlink_parent``, exit 1, no artifacts."""
    missing = tmp_path / "missing-target"
    dangle = tmp_path / "dangle-parent"
    os.symlink(missing, dangle)
    args = _setup_args(tmp_path, home=str(dangle / "child"))
    exit_code = cli.cmd_setup(args)
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    assert "Traceback" not in captured.out
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["condition"] == "home_dangling_symlink_parent"
    assert payload["next_steps"]
    # No artifacts materialised at either requested or resolved path.
    assert not (dangle / "child").exists()
    assert not (missing / "child").exists()


def test_cmd_setup_regular_file_parent_rejected(tmp_path, capsys):
    """``ardur setup --home <regular-file>/child`` must return structured JSON
    ``home_parent_not_directory``."""
    regular = tmp_path / "regular-parent"
    regular.write_text("x\n", encoding="utf-8")
    args = _setup_args(tmp_path, home=str(regular / "child"))
    exit_code = cli.cmd_setup(args)
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    assert "Traceback" not in captured.out
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["condition"] == "home_parent_not_directory"
    assert payload["next_steps"]


def test_cmd_setup_valid_new_path_proceeds(tmp_path, capsys, monkeypatch):
    """``ardur setup --home <fresh-path>`` must still succeed (regression)."""
    # Stub the launch-agent plist write so the test does not touch ~/Library.
    monkeypatch.setattr(
        personal_hub,
        "_write_launch_agent",
        lambda paths, host, port: paths.home / "fake.plist",
    )
    args = _setup_args(tmp_path, home=str(tmp_path / "fresh-valid-home"))
    exit_code = cli.cmd_setup(args)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Traceback" not in captured.out


def test_cmd_setup_real_directory_proceeds(tmp_path, capsys, monkeypatch):
    """``ardur setup --home <real-dir>`` must still succeed (regression)."""
    monkeypatch.setattr(
        personal_hub,
        "_write_launch_agent",
        lambda paths, host, port: paths.home / "fake.plist",
    )
    real_dir = tmp_path / "real-home"
    real_dir.mkdir()
    args = _setup_args(tmp_path, home=str(real_dir))
    exit_code = cli.cmd_setup(args)
    assert exit_code == 0


# ---------------------------------------------------------------------------
# ardur protect claude-code: dangling-symlink parent + regular-file parent
# ---------------------------------------------------------------------------


def _protect_args(tmp_path, **overrides):
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


def _patch_protect_success(monkeypatch):
    """Mock heavy dependencies so protect_claude_code can succeed."""
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


def _assert_protect_failure(capsys, exit_code, condition):
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    assert "Traceback" not in captured.out
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["condition"] == condition
    assert payload["next_steps"]


def test_protect_claude_code_dangling_symlink_parent_rejected(tmp_path, capsys):
    """``ardur protect claude-code --home <dangling-symlink>/child`` must
    return structured JSON ``home_dangling_symlink_parent``, no artifacts."""
    missing = tmp_path / "missing-target"
    dangle = tmp_path / "dangle-parent-link"
    os.symlink(missing, dangle)
    args = _protect_args(tmp_path, home=str(dangle / "child"))
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "home_dangling_symlink_parent")
    # No artifacts.
    assert not (dangle / "child" / "keys").exists()
    assert not (dangle / "child" / "active_mission.jwt").exists()
    assert not (missing / "child").exists()


def test_protect_claude_code_regular_file_parent_rejected(tmp_path, capsys):
    """``ardur protect claude-code --home <regular-file>/child`` must return
    structured JSON ``home_parent_not_directory``."""
    regular = tmp_path / "regular-parent"
    regular.write_text("x\n", encoding="utf-8")
    args = _protect_args(tmp_path, home=str(regular / "child"))
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "home_parent_not_directory")


def test_protect_claude_code_direct_dangling_leaf_still_rejected(tmp_path, capsys):
    """Regression: a DIRECT dangling symlink leaf must still be rejected by the
    existing ``protect_home_invalid`` path (not the new parent-walk)."""
    missing = tmp_path / "missing"
    dangle = tmp_path / "direct-dangle"
    os.symlink(missing, dangle)
    args = _protect_args(tmp_path, home=str(dangle))
    exit_code = cli.cmd_protect_claude_code(args)
    _assert_protect_failure(capsys, exit_code, "protect_home_invalid")


def test_protect_claude_code_symlink_to_existing_dir_parent_proceeds(
    tmp_path, capsys, monkeypatch
):
    """Regression: ``--home <symlink-to-existing-dir>/child`` must proceed."""
    _patch_protect_success(monkeypatch)
    real = tmp_path / "real-target"
    real.mkdir()
    link = tmp_path / "good-parent-link"
    os.symlink(real, link)
    args = _protect_args(tmp_path, home=str(link / "child"))
    exit_code = cli.cmd_protect_claude_code(args)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Traceback" not in captured.out


def test_protect_claude_code_valid_new_path_proceeds(
    tmp_path, capsys, monkeypatch
):
    """Regression: ``--home <fresh-path>`` must proceed."""
    _patch_protect_success(monkeypatch)
    args = _protect_args(tmp_path, home=str(tmp_path / "fresh-protect-home"))
    exit_code = cli.cmd_protect_claude_code(args)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Traceback" not in captured.out

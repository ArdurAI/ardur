from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from vibap.ardur_profile import load_ardur_profile
from vibap.cli import (
    claude_code_doctor,
    cmd_profile_init,
    cmd_protect_claude_code,
    protect_claude_code,
)
from vibap.passport import load_public_key, verify_passport


REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_CODE_PLUGIN_DIR = REPO_ROOT / "plugins" / "claude-code"


def _copy_claude_code_plugin(tmp_path, name="claude-code-plugin"):
    plugin_dir = tmp_path / name
    shutil.copytree(CLAUDE_CODE_PLUGIN_DIR, plugin_dir)
    return plugin_dir


def _assert_no_protect_setup_artifacts(home, keys_dir):
    assert not (home / "active_mission.jwt").exists()
    assert not (home / "keys").exists()
    assert not keys_dir.exists()
    assert not (home / "claude-code-hook-python").exists()
    assert not (home / "claude-code-pre_tool_use").exists()
    assert not (home / "claude-code-pre_tool_use.sha256").exists()
    assert not (home / "policies").exists()


def _protect_args(**overrides):
    values = {
        "scope": None,
        "profile": None,
        "mode": None,
        "json": True,
        "home": None,
        "plugin_dir": CLAUDE_CODE_PLUGIN_DIR,
        "keys_dir": None,
        "agent_id": "test:claude-code",
        "mission": None,
        "max_tool_calls": 250,
        "max_duration_s": 86400,
        "ttl_s": None,
        "forbid_rules": None,
        "cedar_policy": None,
        "cedar_entities": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_protect_claude_code_missing_profile_json_has_next_steps(tmp_path, capsys):
    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            profile=tmp_path / "missing-profile.md",
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            plugin_dir=tmp_path / "missing-plugin-is-not-checked-before-profile",
        )
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "profile_missing"
    assert response["condition"] == "profile_missing"
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur profile init --template safe-coding --path <profile-file>" in commands
    assert "ardur protect claude-code --profile <profile-file>" in commands
    assert "ardur protect claude-code --scope <your-project>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_missing_profile_human_has_next_steps(tmp_path, capsys):
    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=False,
            profile=tmp_path / "missing-profile.md",
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            plugin_dir=tmp_path / "missing-plugin-is-not-checked-before-profile",
        )
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Ardur Claude Code protection was not configured." in captured.out
    assert "Ardur profile file could not be loaded." in captured.out
    assert "Next steps:" in captured.out
    assert "ardur profile init --template safe-coding --path <profile-file>" in captured.out
    assert "ardur protect claude-code --profile <profile-file>" in captured.out
    assert "ardur protect claude-code --scope <your-project>" in captured.out
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_missing_scope_json_has_next_steps(tmp_path, capsys):
    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            plugin_dir=tmp_path / "missing-plugin-is-not-checked-before-scope",
        )
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "missing_scope"
    assert response["condition"] == "missing_scope"
    assert "next_steps" in response
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur protect claude-code --scope <your-project>" in commands
    assert "ardur profile init --template safe-coding --path ARDUR.md" in commands
    assert "ardur protect claude-code --profile ARDUR.md" in commands
    assert str(tmp_path) not in captured.out


def test_protect_claude_code_missing_scope_human_has_next_steps(tmp_path, capsys):
    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=False,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            plugin_dir=tmp_path / "missing-plugin-is-not-checked-before-scope",
        )
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Next steps:" in captured.out
    assert "ardur protect claude-code --scope <your-project>" in captured.out
    assert "ardur profile init --template safe-coding --path ARDUR.md" in captured.out
    assert "ardur protect claude-code --profile ARDUR.md" in captured.out
    assert str(tmp_path) not in captured.out


def test_protect_claude_code_profile_missing_scope_json_has_next_steps(tmp_path, capsys):
    profile = tmp_path / "ARDUR.md"
    profile.write_text(
        """# Ardur Guardrails
Mode: safe coding
Mission: Missing scope regression.
""",
        encoding="utf-8",
    )

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            profile=profile,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            plugin_dir=tmp_path / "missing-plugin-is-not-checked-before-scope",
        )
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Traceback" not in captured.err
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["condition"] == "missing_scope"
    assert response["detail"] == "The selected profile does not define `Protect folder:`."
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur protect claude-code --scope <your-project>" in commands
    assert "ardur protect claude-code --profile ARDUR.md" in commands
    assert str(tmp_path) not in captured.out


def test_get_started_claude_code_snippet_uses_profile_after_init():
    """Keep the get-started copy/paste path aligned with profile init output."""

    get_started = REPO_ROOT / "site" / "content" / "get-started.md"
    lines = get_started.read_text(encoding="utf-8").splitlines()

    assert "PYTHONPATH=python python -m vibap.cli profile init" in lines
    assert "PYTHONPATH=python python -m vibap.cli protect claude-code --profile ARDUR.md" in lines
    assert "PYTHONPATH=python python -m vibap.cli protect claude-code" not in lines


def test_profile_parses_friendly_markdown_rules(tmp_path):
    profile = tmp_path / "ARDUR.md"
    profile.write_text(
        """# Ardur Guardrails
Mode: read only
Mission: Review this project without changing it.
Protect folder: ./project
Max tool calls: 12
Duration: 2h

## Allow
- Read files
- Search files

## Block
- Run shell commands
- Write files
""",
        encoding="utf-8",
    )

    parsed = load_ardur_profile(profile)

    assert parsed.mode == "read only"
    assert parsed.mission == "Review this project without changing it."
    assert parsed.scope == "./project"
    assert parsed.max_tool_calls == 12
    assert parsed.max_duration_s == 7200
    assert parsed.allowed_tools == ["Read", "Glob", "Grep"]
    assert parsed.forbidden_tools == ["Bash", "Write"]


def test_protect_claude_code_from_profile_writes_verifiable_passport(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    profile = tmp_path / "ARDUR.md"
    profile.write_text(
        """# Ardur Guardrails
Mode: read only
Mission: Read-only review for a non-technical user.
Protect folder: ./project

## Allow
- Read files
- Search files

## Block
- Run shell commands
- Edit files
- Write files
""",
        encoding="utf-8",
    )
    home = tmp_path / "home"
    keys_dir = tmp_path / "keys"

    result = protect_claude_code(
        _protect_args(profile=profile, home=home, keys_dir=keys_dir)
    )

    active_passport = Path(str(result["active_passport"]))
    assert active_passport == home.resolve() / "active_mission.jwt"
    assert active_passport.exists()
    claims = verify_passport(active_passport.read_text().strip(), load_public_key(keys_dir))
    assert claims["mission"] == "Read-only review for a non-technical user."
    assert claims["allowed_tools"] == ["Read", "Glob", "Grep"]
    assert claims["forbidden_tools"] == ["Bash", "Edit", "MultiEdit", "Write"]
    assert claims["cwd"] == str(project.resolve())
    assert claims["resource_scope"] == [str(project.resolve()), f"{project.resolve()}/*"]
    assert shlex.split(result["run_command"]) == [
        f"VIBAP_HOME={home.resolve()}",
        "claude",
        "--plugin-dir",
        str(CLAUDE_CODE_PLUGIN_DIR.resolve()),
    ]
    assert stat.S_IMODE(active_passport.stat().st_mode) == 0o600
    hook_python = Path(str(result["hook_python"]))
    assert hook_python == home.resolve() / "claude-code-hook-python"
    assert hook_python.read_text(encoding="utf-8").strip() == sys.executable
    assert stat.S_IMODE(hook_python.stat().st_mode) == 0o600


def test_protect_claude_code_preserves_flag_based_safe_coding(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = protect_claude_code(
        _protect_args(scope=project, mode="safe-coding", home=tmp_path / "home", keys_dir=tmp_path / "keys")
    )

    assert result["mode"] == "safe-coding"
    assert result["allowed_tools"] == ["Read", "Glob", "Grep", "Edit", "MultiEdit", "Write"]
    assert result["forbidden_tools"] == ["Bash"]


def test_profile_explicit_allowlist_can_leave_forbidden_tools_empty(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    profile = tmp_path / "ARDUR.md"
    profile.write_text(
        """# Ardur Guardrails
Mode: safe coding
Mission: Permissive observability test.
Protect folder: ./project
Allowed Tools: *
""",
        encoding="utf-8",
    )

    result = protect_claude_code(
        _protect_args(profile=profile, home=tmp_path / "home", keys_dir=tmp_path / "keys")
    )

    assert result["allowed_tools"] == ["*"]
    assert result["forbidden_tools"] == []


def test_protect_claude_code_quotes_plugin_dir_with_spaces(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    plugin_dir = tmp_path / "plugin dir with spaces"
    shutil.copytree(CLAUDE_CODE_PLUGIN_DIR, plugin_dir)
    home = tmp_path / "home dir"

    result = protect_claude_code(
        _protect_args(
            scope=project,
            mode="read-only",
            home=home,
            plugin_dir=plugin_dir,
        )
    )

    assert shlex.split(result["run_command"]) == [
        f"VIBAP_HOME={home.resolve()}",
        "claude",
        "--plugin-dir",
        str(plugin_dir.resolve()),
    ]


def test_protect_claude_code_keeps_preexisting_explicit_home_mode_when_using_default_daemon_subdir(tmp_path):
    from vibap.claude_code_daemon import resolve_daemon_socket_path

    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "explicit-home"
    home.mkdir(mode=0o755)

    result = protect_claude_code(
        _protect_args(scope=project, mode="read-only", home=home, keys_dir=tmp_path / "keys")
    )

    assert result["home"] == str(home.resolve())
    assert stat.S_IMODE(home.stat().st_mode) == 0o755
    assert resolve_daemon_socket_path(home=home.resolve()) == home.resolve() / "daemon" / "claude-code-hook-daemon.sock"



def test_hook_wrapper_uses_recorded_python_interpreter(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    protect_claude_code(
        _protect_args(scope=project, mode="read-only", home=home)
    )
    wrapper = CLAUDE_CODE_PLUGIN_DIR / "hooks" / "pre_tool_use"
    env = {
        "HOME": str(tmp_path / "user-home"),
        "PATH": os.environ.get("PATH", ""),
        "VIBAP_HOME": str(home),
        "ARDUR_CC_HOOK_DIR": str(tmp_path / "receipts"),
    }

    result = subprocess.run(
        [str(wrapper)],
        input='{"tool_name":"Read","tool_input":{"file_path":"' + str(project / "a.txt") + '"}}',
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "ModuleNotFoundError" not in result.stderr
    assert '"continue": true' in result.stdout


def test_profile_init_creates_customer_editable_markdown(tmp_path):
    profile = tmp_path / "ARDUR.md"

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile,
            force=False,
            json=True,
        )
    )

    assert exit_code == 0
    text = profile.read_text(encoding="utf-8")
    assert "Mode: safe coding" in text
    assert "## Allow" in text
    assert "## Block" in text


def test_profile_init_existing_profile_json_has_next_steps(tmp_path, capsys):
    profile = tmp_path / "ARDUR.md"
    profile.write_text("existing profile\n", encoding="utf-8")

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile,
            force=False,
            json=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "profile_exists"
    assert response["condition"] == "profile_exists"
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur profile init --path ARDUR.md --force" in commands
    assert "ardur protect claude-code --profile ARDUR.md" in commands
    assert str(tmp_path) not in captured.out


def test_profile_init_existing_profile_human_has_next_steps(tmp_path, capsys):
    profile = tmp_path / "ARDUR.md"
    profile.write_text("existing profile\n", encoding="utf-8")

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile,
            force=False,
            json=False,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Ardur profile was not created." in captured.out
    assert "Next steps:" in captured.out
    assert "ardur profile init --path ARDUR.md --force" in captured.out
    assert "ardur protect claude-code --profile ARDUR.md" in captured.out
    assert str(tmp_path) not in captured.out


def test_profile_init_force_replaces_existing_profile_file(tmp_path, capsys):
    profile = tmp_path / "ARDUR.md"
    profile.write_text("existing profile\n", encoding="utf-8")

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile,
            force=True,
            json=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Mode: safe coding" in profile.read_text(encoding="utf-8")


def _assert_profile_init_path_unwritable_json(profile, tmp_path, capsys, *, force):
    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile,
            force=force,
            json=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "profile_path_unwritable"
    assert response["condition"] == "profile_path_unwritable"
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur profile init --path <profile-file> --force" in commands
    assert "ardur protect claude-code --profile <profile-file>" in commands
    assert str(tmp_path) not in captured.out


def test_profile_init_parent_regular_file_json_has_path_unwritable_next_steps(tmp_path, capsys):
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("do not replace\n", encoding="utf-8")
    profile = parent_file / "ARDUR.md"

    for force in (False, True):
        _assert_profile_init_path_unwritable_json(profile, tmp_path, capsys, force=force)

    assert parent_file.read_text(encoding="utf-8") == "do not replace\n"


def test_profile_init_dangling_parent_symlink_json_has_path_unwritable_next_steps(tmp_path, capsys):
    missing_parent_target = tmp_path / "missing-profile-parent"
    parent_link = tmp_path / "dangling-profile-parent"
    parent_link.symlink_to(missing_parent_target, target_is_directory=True)
    profile = parent_link / "ARDUR.md"

    for force in (False, True):
        _assert_profile_init_path_unwritable_json(profile, tmp_path, capsys, force=force)

    assert parent_link.is_symlink()
    assert not missing_parent_target.exists()


def test_profile_init_parent_symlink_to_existing_directory_succeeds(tmp_path, capsys):
    parent_target = tmp_path / "profile-parent-target"
    parent_target.mkdir()
    parent_link = tmp_path / "profile-parent-link"
    parent_link.symlink_to(parent_target, target_is_directory=True)
    profile = parent_link / "ARDUR.md"

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile,
            force=False,
            json=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is True
    assert "Mode: safe coding" in (parent_target / "ARDUR.md").read_text(encoding="utf-8")


def test_profile_init_directory_without_force_json_has_path_invalid_next_steps(tmp_path, capsys):
    profile_dir = tmp_path / "ARDUR.md"
    profile_dir.mkdir()

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile_dir,
            force=False,
            json=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "profile_path_invalid"
    assert response["condition"] == "profile_path_invalid"
    assert "directory" in response["detail"]
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur profile init --path <profile-file> --force" in commands
    assert "ardur protect claude-code --profile <profile-file>" in commands
    assert str(tmp_path) not in captured.out
    assert list(profile_dir.iterdir()) == []


def test_profile_init_forced_directory_path_json_has_next_steps(tmp_path, capsys):
    profile_dir = tmp_path / "ARDUR.md"
    profile_dir.mkdir()

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile_dir,
            force=True,
            json=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "profile_path_invalid"
    assert response["condition"] == "profile_path_invalid"
    assert "directory" in response["detail"]
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur profile init --path <profile-file> --force" in commands
    assert "ardur protect claude-code --profile <profile-file>" in commands
    assert str(tmp_path) not in captured.out
    assert list(profile_dir.iterdir()) == []


def test_profile_init_forced_directory_path_human_has_next_steps(tmp_path, capsys):
    profile_dir = tmp_path / "ARDUR.md"
    profile_dir.mkdir()

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile_dir,
            force=True,
            json=False,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Ardur profile was not created." in captured.out
    assert "Profile path is not a writable Markdown file." in captured.out
    assert "Next steps:" in captured.out
    assert "ardur profile init --path <profile-file> --force" in captured.out
    assert "ardur protect claude-code --profile <profile-file>" in captured.out
    assert str(tmp_path) not in captured.out
    assert list(profile_dir.iterdir()) == []


def test_profile_init_symlink_to_directory_json_has_path_invalid_next_steps(tmp_path, capsys):
    target_dir = tmp_path / "profile-dir-target"
    target_dir.mkdir()
    profile_link = tmp_path / "ARDUR.md"
    profile_link.symlink_to(target_dir, target_is_directory=True)

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile_link,
            force=False,
            json=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "profile_path_invalid"
    assert response["condition"] == "profile_path_invalid"
    assert "directory" in response["detail"]
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur profile init --path <profile-file> --force" in commands
    assert "ardur protect claude-code --profile <profile-file>" in commands
    assert str(tmp_path) not in captured.out
    assert list(target_dir.iterdir()) == []


def test_protect_claude_code_missing_plugin_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            plugin_dir=tmp_path / "missing-plugin",
        )
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "claude_code_plugin_incomplete"
    assert response["condition"] == "claude_code_plugin_incomplete"
    assert response["missing_checks"] == [
        "plugin_dir",
        "plugin_manifest",
        "plugin_hooks",
        "pre_tool_use",
        "post_tool_use",
        "subagent_start",
        "subagent_stop",
    ]
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur doctor-claude-code --plugin-dir <claude-code-plugin> --home <ardur-home>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_missing_plugin_human_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=False,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            plugin_dir=tmp_path / "missing-plugin",
        )
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Ardur Claude Code protection was not configured." in captured.out
    assert "Claude Code plugin directory is missing or incomplete." in captured.out
    assert "Missing Claude Code plugin checks: plugin_dir, plugin_manifest" in captured.out
    assert "Next steps:" in captured.out
    assert "ardur doctor-claude-code --plugin-dir <claude-code-plugin> --home <ardur-home>" in captured.out
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin>" in captured.out
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_invalid_plugin_manifest_json_fails_closed(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    keys_dir = tmp_path / "keys"
    plugin_dir = _copy_claude_code_plugin(tmp_path, "invalid-manifest-plugin")
    (plugin_dir / ".claude-plugin" / "plugin.json").write_text(
        "{not valid plugin json",
        encoding="utf-8",
    )

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=home,
            keys_dir=keys_dir,
            plugin_dir=plugin_dir,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "claude_code_plugin_invalid"
    assert response["condition"] == "claude_code_plugin_invalid"
    assert response["invalid_checks"] == ["plugin_manifest"]
    assert "Invalid Claude Code plugin checks: plugin_manifest" in response["detail"]
    assert "invalid JSON" in response["detail"]
    commands = [step["command"] for step in response["next_steps"]]
    assert "claude plugin validate <claude-code-plugin>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin>" in commands
    assert str(tmp_path) not in captured.out
    assert "{not valid plugin json" not in captured.out
    _assert_no_protect_setup_artifacts(home, keys_dir)


def test_protect_claude_code_invalid_plugin_hooks_human_fails_closed(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    keys_dir = tmp_path / "keys"
    plugin_dir = _copy_claude_code_plugin(tmp_path, "invalid-hooks-plugin")
    (plugin_dir / "hooks" / "hooks.json").write_text("{}", encoding="utf-8")

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=False,
            scope=project,
            home=home,
            keys_dir=keys_dir,
            plugin_dir=plugin_dir,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Ardur Claude Code protection was not configured." in captured.out
    assert "Claude Code plugin content is invalid." in captured.out
    assert "Invalid Claude Code plugin checks: plugin_hooks" in captured.out
    assert "Next steps:" in captured.out
    assert "claude plugin validate <claude-code-plugin>" in captured.out
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin>" in captured.out
    assert str(tmp_path) not in captured.out
    _assert_no_protect_setup_artifacts(home, keys_dir)


def test_protect_claude_code_valid_plugin_content_still_succeeds(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    keys_dir = tmp_path / "keys"
    plugin_dir = _copy_claude_code_plugin(tmp_path, "valid-plugin")

    result = protect_claude_code(
        _protect_args(
            scope=project,
            home=home,
            keys_dir=keys_dir,
            plugin_dir=plugin_dir,
        )
    )

    assert result["ok"] is True
    assert result["plugin_dir"] == str(plugin_dir.resolve())
    assert Path(str(result["active_passport"])).exists()
    assert keys_dir.exists()
    assert (home / "claude-code-hook-python").exists()


def test_protect_claude_code_malformed_forbid_rules_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    forbid_rules = tmp_path / "bad-forbid-rules.json"
    forbid_rules.write_text("{not valid json", encoding="utf-8")

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            forbid_rules=forbid_rules,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_malformed"
    assert response["policy_input"] == "--forbid-rules"
    assert "invalid JSON" in response["detail"]
    commands = [step["command"] for step in response["next_steps"]]
    assert "python -m json.tool <forbid-rules.json>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --forbid-rules <forbid-rules.json>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_missing_forbid_rules_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            forbid_rules=tmp_path / "missing-forbid-rules.json",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_missing"
    assert response["policy_input"] == "--forbid-rules"
    assert response["detail"] == "Could not load --forbid-rules: the file was not found."
    commands = [step["command"] for step in response["next_steps"]]
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --forbid-rules <forbid-rules.json>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_unreadable_forbid_rules_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    forbid_rules_dir = tmp_path / "forbid-rules-directory.json"
    forbid_rules_dir.mkdir()

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            forbid_rules=forbid_rules_dir,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_unreadable"
    assert response["policy_input"] == "--forbid-rules"
    assert response["detail"] == "Could not load --forbid-rules: reading the file failed with IsADirectoryError."
    commands = [step["command"] for step in response["next_steps"]]
    assert "python -m json.tool <forbid-rules.json>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_bad_cedar_entities_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy = tmp_path / "policy.cedar"
    cedar_policy.write_text("permit(principal, action, resource);\n", encoding="utf-8")
    cedar_entities = tmp_path / "bad-entities.json"
    cedar_entities.write_text("[not valid json", encoding="utf-8")

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            cedar_policy=cedar_policy,
            cedar_entities=cedar_entities,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_malformed"
    assert response["policy_input"] == "--cedar-entities"
    assert "invalid JSON" in response["detail"]
    commands = [step["command"] for step in response["next_steps"]]
    assert "python -m json.tool <cedar-entities.json>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --cedar-policy <policy.cedar> --cedar-entities <cedar-entities.json>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_invalid_cedar_entities_content_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy = tmp_path / "policy.cedar"
    cedar_policy.write_text("permit(principal, action, resource);\n", encoding="utf-8")
    invalid_cases = {
        "object": "{\"not\": \"cedar-entities-list\"}\n",
        "number": "123\n",
        "string": "\"not cedar entity json\"\n",
    }

    for name, entities_text in invalid_cases.items():
        case_root = tmp_path / name
        home = case_root / "home"
        keys = case_root / "keys"
        cedar_entities = case_root / "entities.json"
        cedar_entities.parent.mkdir(parents=True)
        cedar_entities.write_text(entities_text, encoding="utf-8")

        exit_code = cmd_protect_claude_code(
            _protect_args(
                json=True,
                scope=project,
                home=home,
                keys_dir=keys,
                cedar_policy=cedar_policy,
                cedar_entities=cedar_entities,
            )
        )

        captured = capsys.readouterr()
        assert exit_code == 1
        assert "Traceback" not in captured.err
        assert captured.err == ""
        response = json.loads(captured.out)
        assert response["ok"] is False
        assert response["error"] == "protect_policy_input_invalid"
        assert response["condition"] == "protect_policy_input_malformed"
        assert response["policy_input"] == "--cedar-entities"
        assert response["detail"] == "Could not load --cedar-entities: invalid Cedar entities content."
        commands = [step["command"] for step in response["next_steps"]]
        assert "python -m json.tool <cedar-entities.json>" in commands
        assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --cedar-policy <policy.cedar> --cedar-entities <cedar-entities.json>" in commands
        assert str(tmp_path) not in captured.out
        assert entities_text.strip() not in captured.out
        assert not (home / "active_mission.jwt").exists()
        assert not keys.exists()
        assert not (home / "policies").exists()


def test_protect_claude_code_invalid_cedar_entities_content_human_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy = tmp_path / "policy.cedar"
    cedar_policy.write_text("permit(principal, action, resource);\n", encoding="utf-8")
    cedar_entities = tmp_path / "entities.json"
    cedar_entities.write_text("\"not cedar entity json\"\n", encoding="utf-8")
    home = tmp_path / "home"
    keys = tmp_path / "keys"

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=False,
            scope=project,
            home=home,
            keys_dir=keys,
            cedar_policy=cedar_policy,
            cedar_entities=cedar_entities,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Ardur Claude Code protection was not configured." in captured.out
    assert "Policy input file could not be loaded." in captured.out
    assert "Could not load --cedar-entities: invalid Cedar entities content." in captured.out
    assert "Next steps:" in captured.out
    assert "python -m json.tool <cedar-entities.json>" in captured.out
    assert "--cedar-entities <cedar-entities.json>" in captured.out
    assert str(tmp_path) not in captured.out
    assert "not cedar entity json" not in captured.out
    assert not (home / "active_mission.jwt").exists()
    assert not keys.exists()
    assert not (home / "policies").exists()


def test_protect_claude_code_valid_empty_cedar_entities_still_succeeds(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy = tmp_path / "policy.cedar"
    cedar_policy.write_text("permit(principal, action, resource);\n", encoding="utf-8")
    cedar_entities = tmp_path / "entities.json"
    cedar_entities.write_text("[]\n", encoding="utf-8")

    no_entities_result = protect_claude_code(
        _protect_args(
            scope=project,
            home=tmp_path / "no-entities-home",
            keys_dir=tmp_path / "no-entities-keys",
            cedar_policy=cedar_policy,
        )
    )
    empty_entities_result = protect_claude_code(
        _protect_args(
            scope=project,
            home=tmp_path / "empty-entities-home",
            keys_dir=tmp_path / "empty-entities-keys",
            cedar_policy=cedar_policy,
            cedar_entities=cedar_entities,
        )
    )

    assert no_entities_result["ok"] is True
    assert empty_entities_result["ok"] is True
    assert Path(str(no_entities_result["active_passport"])).exists()
    assert Path(str(empty_entities_result["active_passport"])).exists()


def test_protect_claude_code_malformed_forbid_rules_human_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    forbid_rules = tmp_path / "bad-forbid-rules.json"
    forbid_rules.write_text("{not valid json", encoding="utf-8")

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=False,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            forbid_rules=forbid_rules,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Ardur Claude Code protection was not configured." in captured.out
    assert "Policy input file could not be loaded." in captured.out
    assert "Could not load --forbid-rules: invalid JSON" in captured.out
    assert "Next steps:" in captured.out
    assert "python -m json.tool <forbid-rules.json>" in captured.out
    assert "--forbid-rules <forbid-rules.json>" in captured.out
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_forbid_rules_object_and_list_still_succeed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    object_rules = tmp_path / "object-forbid-rules.json"
    object_rules.write_text(json.dumps({"tool": "Bash", "reason": "local baseline"}), encoding="utf-8")
    list_rules = tmp_path / "list-forbid-rules.json"
    list_rules.write_text(json.dumps([{"tool": "Write", "reason": "local baseline"}]), encoding="utf-8")

    object_result = protect_claude_code(
        _protect_args(
            scope=project,
            home=tmp_path / "object-home",
            keys_dir=tmp_path / "object-keys",
            forbid_rules=object_rules,
        )
    )
    list_result = protect_claude_code(
        _protect_args(
            scope=project,
            home=tmp_path / "list-home",
            keys_dir=tmp_path / "list-keys",
            forbid_rules=list_rules,
        )
    )

    assert object_result["ok"] is True
    assert list_result["ok"] is True
    assert Path(str(object_result["active_passport"])).exists()
    assert Path(str(list_result["active_passport"])).exists()


def test_protect_claude_code_missing_cedar_policy_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            cedar_policy=tmp_path / "missing-policy.cedar",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_missing"
    assert response["policy_input"] == "--cedar-policy"
    assert response["detail"] == "Could not load --cedar-policy: the file was not found."
    commands = [step["command"] for step in response["next_steps"]]
    assert "test -r <policy.cedar>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --cedar-policy <policy.cedar>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_unreadable_cedar_policy_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy_dir = tmp_path / "policy-directory.cedar"
    cedar_policy_dir.mkdir()

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            cedar_policy=cedar_policy_dir,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_unreadable"
    assert response["policy_input"] == "--cedar-policy"
    assert response["detail"] == "Could not load --cedar-policy: reading the file failed with IsADirectoryError."
    commands = [step["command"] for step in response["next_steps"]]
    assert "test -r <policy.cedar>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --cedar-policy <policy.cedar>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_malformed_cedar_policy_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy = tmp_path / "bad-policy.cedar"
    cedar_policy.write_text("this is not valid cedar syntax ::: {{{", encoding="utf-8")

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            cedar_policy=cedar_policy,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_malformed"
    assert response["policy_input"] == "--cedar-policy"
    assert response["detail"] == "Could not load --cedar-policy: invalid Cedar policy syntax."
    commands = [step["command"] for step in response["next_steps"]]
    assert "test -r <policy.cedar>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --cedar-policy <policy.cedar>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_malformed_cedar_policy_human_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy = tmp_path / "bad-policy.cedar"
    cedar_policy.write_text("this is not valid cedar syntax ::: {{{", encoding="utf-8")

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=False,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            cedar_policy=cedar_policy,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    assert "Ardur Claude Code protection was not configured." in captured.out
    assert "Policy input file could not be loaded." in captured.out
    assert "Could not load --cedar-policy: invalid Cedar policy syntax." in captured.out
    assert "Next steps:" in captured.out
    assert "test -r <policy.cedar>" in captured.out
    assert "--cedar-policy <policy.cedar>" in captured.out
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_missing_cedar_entities_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy = tmp_path / "policy.cedar"
    cedar_policy.write_text("permit(principal, action, resource);\n", encoding="utf-8")

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            cedar_policy=cedar_policy,
            cedar_entities=tmp_path / "missing-entities.json",
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_missing"
    assert response["policy_input"] == "--cedar-entities"
    assert response["detail"] == "Could not load --cedar-entities: the file was not found."
    commands = [step["command"] for step in response["next_steps"]]
    assert "python -m json.tool <cedar-entities.json>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --cedar-policy <policy.cedar> --cedar-entities <cedar-entities.json>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_protect_claude_code_unreadable_cedar_entities_json_has_next_steps(tmp_path, capsys):
    project = tmp_path / "project"
    project.mkdir()
    cedar_policy = tmp_path / "policy.cedar"
    cedar_policy.write_text("permit(principal, action, resource);\n", encoding="utf-8")
    cedar_entities_dir = tmp_path / "entities-directory.json"
    cedar_entities_dir.mkdir()

    exit_code = cmd_protect_claude_code(
        _protect_args(
            json=True,
            scope=project,
            home=tmp_path / "home",
            keys_dir=tmp_path / "keys",
            cedar_policy=cedar_policy,
            cedar_entities=cedar_entities_dir,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "protect_policy_input_invalid"
    assert response["condition"] == "protect_policy_input_unreadable"
    assert response["policy_input"] == "--cedar-entities"
    assert response["detail"] == "Could not load --cedar-entities: reading the file failed with IsADirectoryError."
    commands = [step["command"] for step in response["next_steps"]]
    assert "python -m json.tool <cedar-entities.json>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin> --cedar-policy <policy.cedar> --cedar-entities <cedar-entities.json>" in commands
    assert str(tmp_path) not in captured.out
    assert not (tmp_path / "home" / "active_mission.jwt").exists()


def test_claude_code_doctor_reports_missing_plugin_files(tmp_path):
    response = claude_code_doctor(plugin_dir=tmp_path / "missing", home=tmp_path / "home")

    assert response["ok"] is False
    checks = {check["name"]: check for check in response["checks"]}
    assert checks["plugin_dir"]["ok"] is False
    assert checks["plugin_manifest"]["ok"] is False
    assert "next_steps" in response
    steps = response["next_steps"]
    assert isinstance(steps, list)
    assert len(steps) > 0
    step_checks = {step["check"]: step for step in steps}
    assert "plugin_files" in step_checks
    assert step_checks["plugin_files"]["action"] == "repair_plugin_path"
    assert "ardur doctor-claude-code" in step_checks["plugin_files"]["command"]


def test_claude_code_doctor_missing_setup_uses_placeholder_only_diagnostics(tmp_path):
    private_home = tmp_path / "private-home"
    private_plugin = tmp_path / "private-plugin"

    response = claude_code_doctor(plugin_dir=private_plugin, home=private_home)

    assert response["ok"] is False
    serialized = json.dumps(response, sort_keys=True)
    for marker in (str(tmp_path), str(private_home), str(private_plugin), "/Users/", "/private/", "/tmp/"):
        assert marker not in serialized

    checks_payload = response["checks"]
    assert isinstance(checks_payload, list)
    checks = {check["name"]: check for check in checks_payload if isinstance(check, dict)}
    assert "<claude-code-plugin>" in str(checks["plugin_dir"]["detail"])
    assert "<claude-code-plugin>" in str(checks["plugin_manifest"]["detail"])
    assert "<ardur-home>" in str(checks["active_passport"]["detail"])

    steps_payload = response["next_steps"]
    assert isinstance(steps_payload, list)
    commands = [step["command"] for step in steps_payload if isinstance(step, dict)]
    assert "ardur doctor-claude-code --plugin-dir <claude-code-plugin> --home <ardur-home>" in commands
    assert "ardur protect claude-code --scope <your-project> --home <ardur-home> --plugin-dir <claude-code-plugin>" in commands


def test_claude_code_doctor_omits_next_steps_when_setup_is_healthy(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "healthy-plugin"
    plugin_dir.mkdir()
    (plugin_dir / ".claude-plugin").mkdir()
    (plugin_dir / ".claude-plugin" / "plugin.json").write_text("{}")
    hooks_dir = plugin_dir / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / "hooks.json").write_text("{}")
    for hook_name in ("pre_tool_use", "post_tool_use", "subagent_start", "subagent_stop"):
        (hooks_dir / hook_name).write_text("#!/bin/sh\ntrue\n")
        (hooks_dir / hook_name).chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    (home / "active_mission.jwt").write_text("eyJhbG...fake")

    # Make the test deterministic: fake `claude` on PATH and make
    # `claude plugin validate` succeed so the doctor reports ok=True.
    import shutil as _shutil
    _orig_which = _shutil.which

    def _fake_which(cmd, **kw):
        if cmd == "claude":
            return "/fake/claude"
        return _orig_which(cmd, **kw)

    monkeypatch.setattr(_shutil, "which", _fake_which)

    import subprocess as _sp
    _orig_run = _sp.run

    def _fake_run(cmd, **kw):
        if isinstance(cmd, list) and cmd and cmd[0] == "/fake/claude" and "validate" in cmd:
            return _orig_run(["true"], **kw)
        return _orig_run(cmd, **kw)

    monkeypatch.setattr(_sp, "run", _fake_run)

    response = claude_code_doctor(plugin_dir=plugin_dir, home=home)

    assert response["ok"] is True
    assert "next_steps" in response
    assert response["next_steps"] == []


def test_claude_code_doctor_reports_plugin_validate_failure(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "bad-plugin"
    plugin_dir.mkdir()
    (plugin_dir / ".claude-plugin").mkdir()
    (plugin_dir / ".claude-plugin" / "plugin.json").write_text("{}")
    hooks_dir = plugin_dir / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / "hooks.json").write_text("{}")
    for hook_name in ("pre_tool_use", "post_tool_use", "subagent_start", "subagent_stop"):
        (hooks_dir / hook_name).write_text("#!/bin/sh\ntrue\n")
        (hooks_dir / hook_name).chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    (home / "active_mission.jwt").write_text("eyJhbG...fake")

    # Make this failure-mode regression independent of the host machine:
    # the doctor should see Claude as installed, then report the failing
    # plugin validation as the next actionable remediation.
    import shutil as _shutil
    _orig_which = _shutil.which

    def _fake_which(cmd, **kw):
        if cmd == "claude":
            return "/fake/claude"
        return _orig_which(cmd, **kw)

    monkeypatch.setattr(_shutil, "which", _fake_which)

    import subprocess as _sp
    _orig_run = _sp.run

    def _fake_run(cmd, **kw):
        expected = ["/fake/claude", "plugin", "validate", str(plugin_dir.resolve())]
        if cmd == expected:
            return _sp.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr="deterministic plugin validation failure",
            )
        return _orig_run(cmd, **kw)

    monkeypatch.setattr(_sp, "run", _fake_run)

    response = claude_code_doctor(plugin_dir=plugin_dir, home=home)

    assert response["ok"] is False
    assert "next_steps" in response
    steps = response["next_steps"]
    step_checks = {step["check"]: step for step in steps}
    assert "plugin_validate" in step_checks
    assert step_checks["plugin_validate"]["action"] == "validate_plugin"
    assert "claude plugin validate" in step_checks["plugin_validate"]["command"]
    assert "deterministic plugin validation failure" in step_checks["plugin_validate"]["detail"]


def test_claude_code_doctor_sanitizes_plugin_validate_local_paths(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "private-plugin"
    plugin_dir.mkdir()
    manifest_dir = plugin_dir / ".claude-plugin"
    manifest_dir.mkdir()
    manifest = manifest_dir / "plugin.json"
    manifest.write_text("{}")
    hooks_dir = plugin_dir / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / "hooks.json").write_text("{}")
    for hook_name in ("pre_tool_use", "post_tool_use", "subagent_start", "subagent_stop"):
        (hooks_dir / hook_name).write_text("#!/bin/sh\ntrue\n")
        (hooks_dir / hook_name).chmod(0o755)
    home = tmp_path / "private-home"
    home.mkdir()
    (home / "active_mission.jwt").write_text("eyJhbG...fake")

    import shutil as _shutil
    _orig_which = _shutil.which

    def _fake_which(cmd, **kw):
        if cmd == "claude":
            return "/fake/claude"
        return _orig_which(cmd, **kw)

    monkeypatch.setattr(_shutil, "which", _fake_which)

    import subprocess as _sp
    _orig_run = _sp.run

    validation_output = (
        f"Validating plugin manifest: {manifest.resolve()}\n\n"
        "✘ Found 1 error:\n\n"
        "  ❯ json: Invalid JSON syntax: JSON Parse error: Expected '}'\n\n"
        "✘ Validation failed"
    )

    def _fake_run(cmd, **kw):
        expected = ["/fake/claude", "plugin", "validate", str(plugin_dir.resolve())]
        if cmd == expected:
            return _sp.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout=validation_output,
                stderr="",
            )
        return _orig_run(cmd, **kw)

    monkeypatch.setattr(_sp, "run", _fake_run)

    response = claude_code_doctor(plugin_dir=plugin_dir, home=home)

    assert response["ok"] is False
    serialized = json.dumps(response, sort_keys=True)
    for marker in (str(tmp_path), str(plugin_dir), str(manifest), "/Users/", "/private/", "/tmp/"):
        assert marker not in serialized

    checks_payload = response["checks"]
    assert isinstance(checks_payload, list)
    checks = {check["name"]: check for check in checks_payload if isinstance(check, dict)}
    detail = str(checks["plugin_validate"]["detail"])
    assert "Validating plugin manifest: <claude-code-plugin>/.claude-plugin/plugin.json" in detail
    assert "Invalid JSON syntax" in detail
    assert "Validation failed" in detail

    steps_payload = response["next_steps"]
    assert isinstance(steps_payload, list)
    step_checks = {step["check"]: step for step in steps_payload if isinstance(step, dict)}
    validate_step = step_checks["plugin_validate"]
    assert validate_step["command"] == "claude plugin validate <claude-code-plugin>"
    assert "<claude-code-plugin>/.claude-plugin/plugin.json" in validate_step["detail"]
    assert str(manifest) not in validate_step["detail"]


def _profile_init_args(path, *, template="safe-coding", force=False, json_output=True):
    return argparse.Namespace(
        template=template,
        path=Path(path) if not isinstance(path, Path) else path,
        force=force,
        json=json_output,
    )


def _assert_profile_path_invalid_json(capsys, *, exit_code, tmp_path):
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    assert "Traceback" not in captured.err
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "profile_path_invalid"
    assert response["condition"] == "profile_path_invalid"
    # next_steps must be placeholder-only, never leak local temp paths
    serialized = json.dumps(response, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "/Users/" not in serialized
    return response


def test_profile_init_whitespace_only_path_rejected_json(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = cmd_profile_init(_profile_init_args(Path("   ")))
    response = _assert_profile_path_invalid_json(capsys, exit_code=exit_code, tmp_path=tmp_path)
    commands = [step["command"] for step in response["next_steps"]]
    assert any("ardur profile init --path <profile-file>" in c for c in commands)
    # No file/dir created with whitespace name
    assert not (tmp_path / "   ").exists()
    assert not (tmp_path / ".vibap").exists()


def test_profile_init_tab_only_path_rejected_json(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = cmd_profile_init(_profile_init_args(Path("\t")))
    _assert_profile_path_invalid_json(capsys, exit_code=exit_code, tmp_path=tmp_path)
    assert not (tmp_path / "\t").exists()


def test_profile_init_leading_space_path_rejected_json(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = cmd_profile_init(_profile_init_args(Path(" foo/ARDUR.md")))
    _assert_profile_path_invalid_json(capsys, exit_code=exit_code, tmp_path=tmp_path)
    assert not (tmp_path / " foo").exists()
    assert not (tmp_path / " foo" / "ARDUR.md").exists()


def test_profile_init_trailing_space_path_rejected_json(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = cmd_profile_init(_profile_init_args(Path("ARDUR.md ")))
    _assert_profile_path_invalid_json(capsys, exit_code=exit_code, tmp_path=tmp_path)
    assert not (tmp_path / "ARDUR.md ").exists()


def test_profile_init_relative_traversal_rejected_json(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Create a sibling outside tmp_path to detect traversal-created dirs
    sibling_marker = tmp_path.parent / f"ardur-traversal-marker-{os.getpid()}"
    if sibling_marker.exists():
        shutil.rmtree(sibling_marker)
    traversal_target = sibling_marker / "passwd" / "ARDUR.md"
    try:
        exit_code = cmd_profile_init(
            _profile_init_args(Path(f"../{sibling_marker.name}/passwd/ARDUR.md"))
        )
        _assert_profile_path_invalid_json(capsys, exit_code=exit_code, tmp_path=tmp_path)
        # Critical: no directories created outside intended scope
        assert not sibling_marker.exists()
        assert not traversal_target.exists()
    finally:
        if sibling_marker.exists():
            shutil.rmtree(sibling_marker)


def test_profile_init_empty_path_rejected_json(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = cmd_profile_init(_profile_init_args(Path("")))
    _assert_profile_path_invalid_json(capsys, exit_code=exit_code, tmp_path=tmp_path)


def test_profile_init_whitespace_only_human_rejected_no_traceback(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = cmd_profile_init(_profile_init_args(Path("   "), json_output=False))
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    assert "Traceback" not in captured.err
    assert "Ardur profile was not created." in captured.out
    assert not (tmp_path / "   ").exists()


def test_profile_init_bare_filename_still_succeeds(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = cmd_profile_init(_profile_init_args(Path("ARDUR.md")))
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert (tmp_path / "ARDUR.md").exists()


def test_profile_init_existing_directory_target_rejected(tmp_path, capsys):
    target_dir = tmp_path / "existing-dir"
    target_dir.mkdir()
    exit_code = cmd_profile_init(_profile_init_args(target_dir))
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    # Directory target remains an IsADirectoryError -> profile_path_invalid
    response = json.loads(captured.out)
    assert response["condition"] == "profile_path_invalid"


def test_profile_init_existing_file_target_rejected(tmp_path, capsys):
    existing = tmp_path / "existing.md"
    existing.write_text("keep me\n", encoding="utf-8")
    exit_code = cmd_profile_init(_profile_init_args(existing))
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    response = json.loads(captured.out)
    assert response["condition"] == "profile_exists"
    assert existing.read_text(encoding="utf-8") == "keep me\n"

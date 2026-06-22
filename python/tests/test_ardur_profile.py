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


def test_profile_init_directory_without_force_json_preserves_existing_profile_response(tmp_path, capsys):
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
    assert response["error"] == "profile_exists"
    assert response["condition"] == "profile_exists"
    assert str(tmp_path) not in captured.out


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

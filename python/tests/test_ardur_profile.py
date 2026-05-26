from __future__ import annotations

import argparse
import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from vibap.ardur_profile import load_ardur_profile
from vibap.cli import claude_code_doctor, cmd_profile_init, protect_claude_code
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
    }
    values.update(overrides)
    return argparse.Namespace(**values)


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


def test_protect_claude_code_fails_when_plugin_files_are_missing(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(FileNotFoundError) as exc_info:
        protect_claude_code(
            _protect_args(
                scope=project,
                home=tmp_path / "home",
                keys_dir=tmp_path / "keys",
                plugin_dir=tmp_path / "missing-plugin",
            )
        )

    assert "Claude Code plugin is incomplete" in str(exc_info.value)


def test_claude_code_doctor_reports_missing_plugin_files(tmp_path):
    response = claude_code_doctor(plugin_dir=tmp_path / "missing", home=tmp_path / "home")

    assert response["ok"] is False
    checks = {check["name"]: check for check in response["checks"]}
    assert checks["plugin_dir"]["ok"] is False
    assert checks["plugin_manifest"]["ok"] is False

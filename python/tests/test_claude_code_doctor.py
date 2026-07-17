"""Focused regressions for Claude Code doctor validation gates."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibap.cli import claude_code_doctor


@pytest.mark.parametrize("missing_hook", ["subagent_start", "subagent_stop"])
def test_claude_code_doctor_skips_validation_when_lifecycle_hook_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_hook: str,
) -> None:
    plugin_dir = tmp_path / "incomplete-plugin"
    (plugin_dir / ".claude-plugin").mkdir(parents=True)
    (plugin_dir / ".claude-plugin" / "plugin.json").write_text("{}")
    hooks_dir = plugin_dir / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / "hooks.json").write_text("{}")
    for hook_name in (
        "pre_tool_use",
        "post_tool_use",
        "subagent_start",
        "subagent_stop",
    ):
        if hook_name != missing_hook:
            (hooks_dir / hook_name).write_text("#!/bin/sh\ntrue\n")
    home = tmp_path / "home"
    home.mkdir()
    (home / "active_mission.jwt").write_text("test")

    monkeypatch.setattr("vibap.cli.shutil.which", lambda _command: "/fake/claude")

    def _unexpected_validation(*_args: object, **_kwargs: object) -> None:
        pytest.fail("plugin validation must not run when a lifecycle hook is missing")

    monkeypatch.setattr("vibap.cli.subprocess.run", _unexpected_validation)

    response = claude_code_doctor(plugin_dir=plugin_dir, home=home)

    checks = {check["name"]: check for check in response["checks"]}
    assert checks[missing_hook]["ok"] is False
    assert checks["plugin_validate"] == {
        "name": "plugin_validate",
        "ok": False,
        "detail": "skipped; missing claude binary or plugin files",
    }

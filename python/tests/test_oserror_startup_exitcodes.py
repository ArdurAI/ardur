"""Tests for structured OSError handling and exit-code consistency in CLI startup and personal commands.

Covers:
- cmd_start: non-EADDRINUSE OSError produces structured JSON (not a bare traceback)
- cmd_hub: non-EADDRINUSE OSError produces structured JSON (not a bare traceback)
- cmd_uninstall: exit code reflects response ok field
- cmd_personal_firewall_demo: exit code reflects result ok field
"""

import errno
import json
from unittest.mock import patch

from vibap import cli


def _parse_last_json(stdout: str):
    """Parse the last JSON object from stdout (start emits session_started before errors)."""
    objects = []
    decoder = json.JSONDecoder()
    idx = 0
    s = stdout.strip()
    while idx < len(s):
        # Skip whitespace between JSON objects
        while idx < len(s) and s[idx] in " \t\n\r":
            idx += 1
        if idx >= len(s):
            break
        obj, end = decoder.raw_decode(s, idx)
        objects.append(obj)
        idx = end
    return objects[-1]


# A valid mission JSON that load_mission_file will accept.
_VALID_MISSION = {"agent_id": "test-agent", "mission": "test mission", "allowed_tools": []}


def _write_valid_mission(tmp_path) -> str:
    p = tmp_path / "mission.json"
    p.write_text(json.dumps(_VALID_MISSION))
    return str(p)


# ---------------------------------------------------------------------------
# cmd_start OSError handling
# ---------------------------------------------------------------------------


def test_start_non_eaddrinuse_oserror_returns_structured_json(capsys, tmp_path):
    """cmd_start should emit structured JSON for OSError codes other than EADDRINUSE."""
    mission_path = _write_valid_mission(tmp_path)
    error = OSError(errno.EACCES, "Permission denied")
    with patch("vibap.cli.serve_proxy", side_effect=error):
        rc = cli.main(
            [
                "start",
                "--mission",
                mission_path,
                "--keys-dir",
                str(tmp_path / "keys"),
            ]
        )
    out = capsys.readouterr().out
    data = _parse_last_json(out)
    assert rc == 1
    assert data["ok"] is False
    assert data["error"] == "start_oserror"
    assert data["error_code"] == "start_oserror"
    assert data["condition"] == "start_oserror"
    assert "EACCES" in data["detail"]
    assert "Permission denied" in data["detail"]
    assert isinstance(data["next_steps"], list)
    assert len(data["next_steps"]) >= 1


def test_start_eaddrinuse_oserror_still_uses_port_in_use_response(capsys, tmp_path):
    """cmd_start should still use the dedicated port-in-use response for EADDRINUSE."""
    mission_path = _write_valid_mission(tmp_path)
    error = OSError(errno.EADDRINUSE, "Address already in use")
    with patch("vibap.cli.serve_proxy", side_effect=error):
        rc = cli.main(
            [
                "start",
                "--mission",
                mission_path,
                "--keys-dir",
                str(tmp_path / "keys"),
            ]
        )
    out = capsys.readouterr().out
    data = _parse_last_json(out)
    assert rc == 1
    assert data["error"] == "start_port_in_use"
    assert data["error_code"] == "start_port_in_use"


# ---------------------------------------------------------------------------
# cmd_hub OSError handling
# ---------------------------------------------------------------------------


def test_hub_non_eaddrinuse_oserror_returns_structured_json(capsys):
    """cmd_hub should emit structured JSON for OSError codes other than EADDRINUSE."""
    error = OSError(errno.EACCES, "Permission denied")
    with patch("vibap.cli.serve_hub", side_effect=error):
        rc = cli.main(["hub"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 1
    assert data["ok"] is False
    assert data["error"] == "hub_oserror"
    assert data["error_code"] == "hub_oserror"
    assert data["condition"] == "hub_oserror"
    assert "EACCES" in data["detail"]
    assert "Permission denied" in data["detail"]
    assert isinstance(data["next_steps"], list)
    assert len(data["next_steps"]) >= 1


def test_hub_eaddrinuse_oserror_still_uses_port_in_use_response(capsys):
    """cmd_hub should still use the dedicated port-in-use response for EADDRINUSE."""
    error = OSError(errno.EADDRINUSE, "Address already in use")
    with patch("vibap.cli.serve_hub", side_effect=error):
        rc = cli.main(["hub"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 1
    assert data["error"] == "hub_port_in_use"
    assert data["error_code"] == "hub_port_in_use"


# ---------------------------------------------------------------------------
# cmd_uninstall exit-code consistency
# ---------------------------------------------------------------------------


def test_uninstall_returns_1_when_response_ok_is_false(capsys):
    """cmd_uninstall should return exit code 1 when response ok is False."""
    fake_response = {"ok": False, "error": "uninstall_failed"}
    with patch("vibap.cli.uninstall_personal", return_value=fake_response):
        rc = cli.main(["uninstall", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 1
    assert data["ok"] is False


def test_uninstall_returns_0_when_response_ok_is_true(capsys):
    """cmd_uninstall should return exit code 0 when response ok is True."""
    fake_response = {"ok": True, "removed_paths": ["/tmp/test"]}
    with patch("vibap.cli.uninstall_personal", return_value=fake_response):
        rc = cli.main(["uninstall", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 0
    assert data["ok"] is True


def test_uninstall_returns_0_when_ok_absent(capsys):
    """cmd_uninstall should default to success (0) when ok key is absent."""
    fake_response = {"removed_paths": ["/tmp/test"]}
    with patch("vibap.cli.uninstall_personal", return_value=fake_response):
        rc = cli.main(["uninstall", "--json"])
    assert rc == 0


# ---------------------------------------------------------------------------
# cmd_personal_firewall_demo exit-code consistency
# ---------------------------------------------------------------------------


def test_personal_firewall_demo_returns_1_when_result_ok_is_false(capsys):
    """cmd_personal_firewall_demo should return exit code 1 when result ok is False."""
    fake_result = {"ok": False, "error": "demo_internal_error"}
    with patch("vibap.cli.run_personal_firewall_demo", return_value=fake_result):
        rc = cli.main(["personal-firewall", "demo", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 1
    assert data["ok"] is False


def test_personal_firewall_demo_returns_0_when_result_ok_is_true(capsys):
    """cmd_personal_firewall_demo should return exit code 0 when result ok is True."""
    fake_result = {"ok": True, "operations": []}
    with patch("vibap.cli.run_personal_firewall_demo", return_value=fake_result):
        rc = cli.main(["personal-firewall", "demo", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 0
    assert data["ok"] is True

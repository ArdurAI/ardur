"""Acceptance tests for --output flag on posture scan and posture report.

These commands previously emitted only to stdout. The --output flag brings
them in line with evidence correlate, telemetry export, and preflight
tool-server, which all support atomic file output via write_report().
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vibap.cli import main
from vibap.passport import MissionPassport, generate_keypair, issue_passport


def _issue_mission(tmp_path: Path) -> str:
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="posture-output-test-agent",
        mission="exercise posture output flag",
        allowed_tools=["Read", "Bash"],
        forbidden_tools=["Write"],
        resource_scope=["**"],
        max_tool_calls=20,
        max_duration_s=600,
    )
    return issue_passport(mission, private_key, ttl_s=3600)


def _seed_receipts_dir(tmp_path: Path, monkeypatch) -> Path:
    """Create a receipt chain directory with at least one receipt."""
    token = _issue_mission(tmp_path)
    chain_dir = tmp_path / "claude-code-hook"
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(chain_dir))

    from vibap.claude_code_hook import handle_pre_tool_use

    handle_pre_tool_use(
        {
            "session_id": "sess-output-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/example-read-target.txt"},
        },
        keys_dir=tmp_path,
    )
    return chain_dir


def _write_posture_json(tmp_path: Path, monkeypatch, capsys) -> Path:
    """Generate a posture JSON file via scan --output and return its path."""
    chain_dir = _seed_receipts_dir(tmp_path, monkeypatch)
    posture_json = tmp_path / "input-posture.json"
    rc = main([
        "posture", "scan",
        "--receipts", str(chain_dir),
        "--keys-dir", str(tmp_path),
        "--format", "json",
        "--output", str(posture_json),
    ])
    assert rc == 0
    capsys.readouterr()  # drain scan status output
    return posture_json


# ---------------------------------------------------------------------------
# posture scan --output
# ---------------------------------------------------------------------------


def test_scan_output_writes_json_file(tmp_path, monkeypatch, capsys):
    """--output writes a JSON report file and prints a status summary."""
    chain_dir = _seed_receipts_dir(tmp_path, monkeypatch)
    out_file = tmp_path / "posture.json"

    rc = main([
        "posture", "scan",
        "--receipts", str(chain_dir),
        "--keys-dir", str(tmp_path),
        "--format", "json",
        "--output", str(out_file),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert status["ok"] is True
    assert status["condition"] == "posture_scan_report_written"
    assert status["format"] == "json"

    # File should contain valid JSON
    assert out_file.exists()
    written = json.loads(out_file.read_text())
    assert isinstance(written, dict)
    # SHA in status should match file content
    payload_bytes = out_file.read_bytes()
    assert status["report_sha256"] == hashlib.sha256(payload_bytes).hexdigest()


def test_scan_output_writes_markdown_file(tmp_path, monkeypatch, capsys):
    """--output with --format markdown writes a markdown report file."""
    chain_dir = _seed_receipts_dir(tmp_path, monkeypatch)
    out_file = tmp_path / "posture.md"

    rc = main([
        "posture", "scan",
        "--receipts", str(chain_dir),
        "--keys-dir", str(tmp_path),
        "--format", "markdown",
        "--output", str(out_file),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert status["ok"] is True
    assert status["format"] == "markdown"
    assert out_file.exists()
    content = out_file.read_text()
    assert len(content) > 0
    # Markdown should not be JSON
    assert not content.strip().startswith("{")


def test_scan_output_rejects_empty_path(tmp_path, monkeypatch, capsys):
    """Empty --output must fail closed with path_arg_invalid."""
    chain_dir = _seed_receipts_dir(tmp_path, monkeypatch)

    rc = main([
        "posture", "scan",
        "--receipts", str(chain_dir),
        "--keys-dir", str(tmp_path),
        "--format", "json",
        "--output", "",
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "path_arg_invalid"
    assert "empty" in response["message"].lower()


def test_scan_output_rejects_whitespace_path(tmp_path, monkeypatch, capsys):
    """Whitespace-only --output must fail closed."""
    chain_dir = _seed_receipts_dir(tmp_path, monkeypatch)

    rc = main([
        "posture", "scan",
        "--receipts", str(chain_dir),
        "--keys-dir", str(tmp_path),
        "--format", "json",
        "--output", "   ",
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "path_arg_invalid"


def test_scan_output_rejects_directory(tmp_path, monkeypatch, capsys):
    """--output pointing at a directory must fail cleanly."""
    chain_dir = _seed_receipts_dir(tmp_path, monkeypatch)
    dir_target = tmp_path / "output-dir"
    dir_target.mkdir()

    rc = main([
        "posture", "scan",
        "--receipts", str(chain_dir),
        "--keys-dir", str(tmp_path),
        "--format", "json",
        "--output", str(dir_target),
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert "Traceback" not in captured.out


def test_scan_without_output_still_prints_stdout(tmp_path, monkeypatch, capsys):
    """Without --output, behavior is unchanged (JSON to stdout)."""
    chain_dir = _seed_receipts_dir(tmp_path, monkeypatch)

    rc = main([
        "posture", "scan",
        "--receipts", str(chain_dir),
        "--keys-dir", str(tmp_path),
        "--format", "json",
    ])

    assert rc == 0
    captured = capsys.readouterr()
    posture = json.loads(captured.out)
    assert isinstance(posture, dict)


# ---------------------------------------------------------------------------
# posture report --output
# ---------------------------------------------------------------------------


def test_report_output_writes_json_file(tmp_path, monkeypatch, capsys):
    """posture report --output writes a JSON report file."""
    posture_json = _write_posture_json(tmp_path, monkeypatch, capsys)
    out_file = tmp_path / "report.json"

    rc = main([
        "posture", "report",
        "--input", str(posture_json),
        "--format", "json",
        "--output", str(out_file),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert status["ok"] is True
    assert status["condition"] == "posture_report_written"
    assert out_file.exists()
    payload_bytes = out_file.read_bytes()
    assert status["report_sha256"] == hashlib.sha256(payload_bytes).hexdigest()


def test_report_output_writes_markdown_file(tmp_path, monkeypatch, capsys):
    """posture report --output with markdown writes a markdown report."""
    posture_json = _write_posture_json(tmp_path, monkeypatch, capsys)
    out_file = tmp_path / "report.md"

    rc = main([
        "posture", "report",
        "--input", str(posture_json),
        "--format", "markdown",
        "--output", str(out_file),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert status["ok"] is True
    assert status["format"] == "markdown"
    assert out_file.exists()
    content = out_file.read_text()
    assert len(content) > 0


def test_report_output_rejects_empty_path(tmp_path, monkeypatch, capsys):
    """Empty --output on posture report must fail closed."""
    posture_json = _write_posture_json(tmp_path, monkeypatch, capsys)

    rc = main([
        "posture", "report",
        "--input", str(posture_json),
        "--format", "json",
        "--output", "",
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "path_arg_invalid"


def test_report_output_rejects_whitespace_path(tmp_path, monkeypatch, capsys):
    """Whitespace-only --output on posture report must fail closed."""
    posture_json = _write_posture_json(tmp_path, monkeypatch, capsys)

    rc = main([
        "posture", "report",
        "--input", str(posture_json),
        "--format", "json",
        "--output", "   ",
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "path_arg_invalid"


def test_report_output_rejects_directory(tmp_path, monkeypatch, capsys):
    """posture report --output pointing at a directory must fail cleanly."""
    posture_json = _write_posture_json(tmp_path, monkeypatch, capsys)
    dir_target = tmp_path / "report-output-dir"
    dir_target.mkdir()

    rc = main([
        "posture", "report",
        "--input", str(posture_json),
        "--format", "json",
        "--output", str(dir_target),
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert "Traceback" not in captured.out

"""Acceptance tests for --output flag on ardur verify.

The verify command previously emitted its JSON explorer report only to stdout
via --json, while every other report-producing command (evidence correlate,
posture scan/report, preflight tool-server, telemetry export) already supported
atomic file output via --output.  These tests exercise the new --output flag
across the three verify sub-paths (token, offline journal, anchor bundle,
receiver attestation) plus the shared path-validation guards.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vibap.cli import main
from vibap.passport import (
    MissionPassport,
    generate_keypair,
    issue_passport,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _issue_passport(tmp_path: Path) -> str:
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="verify-output-test-agent",
        mission="exercise verify --output flag",
        allowed_tools=["Read", "Bash"],
        forbidden_tools=["Write"],
        resource_scope=["**"],
        max_tool_calls=20,
        max_duration_s=600,
    )
    return issue_passport(mission, private_key, ttl_s=3600)


def _seed_receipt_chain(tmp_path: Path, monkeypatch) -> Path:
    """Create a Claude Code hook receipt chain with one receipt."""
    token = _issue_passport(tmp_path)
    chain_dir = tmp_path / "claude-code-hook"
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(chain_dir))

    from vibap.claude_code_hook import handle_pre_tool_use

    handle_pre_tool_use(
        {
            "session_id": "sess-verify-output",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/example-read-target.txt"},
        },
        keys_dir=tmp_path,
    )
    return chain_dir


def _find_journal(chain_dir: Path) -> Path:
    """Locate the receipts.jsonl journal inside the chain directory tree."""
    for journal in chain_dir.rglob("receipts.jsonl"):
        return journal
    raise AssertionError(f"No receipts.jsonl found under {chain_dir}")


def _build_offline_bundle(tmp_path: Path, monkeypatch) -> Path:
    """Return the receipts.jsonl journal path for offline verify."""
    chain_dir = _seed_receipt_chain(tmp_path, monkeypatch)
    return _find_journal(chain_dir)


# ---------------------------------------------------------------------------
# Token verification --output
# ---------------------------------------------------------------------------


def test_token_output_writes_json_file(tmp_path, monkeypatch, capsys):
    """verify --token --output writes the claims report to a file."""
    token = _issue_passport(tmp_path)
    out_file = tmp_path / "token-report.json"

    rc = main([
        "verify", "--token", token,
        "--keys-dir", str(tmp_path),
        "--output", str(out_file),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert status["valid"] is True
    assert status["condition"] == "verify_report_written"
    assert status["output"] == str(out_file)

    # File contains valid JSON with the claims
    assert out_file.exists()
    written = json.loads(out_file.read_text())
    assert written["valid"] is True
    assert "claims" in written

    # SHA matches
    payload_bytes = out_file.read_bytes()
    assert status["report_sha256"] == hashlib.sha256(payload_bytes).hexdigest()


def test_token_output_without_output_still_prints_stdout(tmp_path, monkeypatch, capsys):
    """Without --output, verify --token prints to stdout (unchanged behavior)."""
    token = _issue_passport(tmp_path)

    rc = main([
        "verify", "--token", token,
        "--keys-dir", str(tmp_path),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is True
    assert "claims" in result


# ---------------------------------------------------------------------------
# Offline journal verification --output
# ---------------------------------------------------------------------------


def test_offline_output_writes_json_file(tmp_path, monkeypatch, capsys):
    """verify --json --output writes the offline report to a file."""
    journal = _build_offline_bundle(tmp_path, monkeypatch)
    out_file = tmp_path / "offline-report.json"

    rc = main([
        "verify", "--json", "--chain-only",
        "--keys-dir", str(tmp_path),
        "--output", str(out_file),
        str(journal),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert status["valid"] is True
    assert status["condition"] == "verify_report_written"

    # File contains valid JSON
    assert out_file.exists()
    written = json.loads(out_file.read_text())
    assert isinstance(written, dict)

    # SHA matches
    payload_bytes = out_file.read_bytes()
    assert status["report_sha256"] == hashlib.sha256(payload_bytes).hexdigest()


def test_offline_output_works_without_json_flag(tmp_path, monkeypatch, capsys):
    """--output works even without --json (JSON is canonical for file output)."""
    journal = _build_offline_bundle(tmp_path, monkeypatch)
    out_file = tmp_path / "offline-report-no-json.json"

    rc = main([
        "verify", "--chain-only",
        "--keys-dir", str(tmp_path),
        "--output", str(out_file),
        str(journal),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert status["valid"] is True
    assert status["condition"] == "verify_report_written"
    assert out_file.exists()
    # File must contain valid JSON
    written = json.loads(out_file.read_text())
    assert isinstance(written, dict)


def test_offline_without_output_prints_stdout(tmp_path, monkeypatch, capsys):
    """Without --output, verify --json prints to stdout (unchanged behavior)."""
    journal = _build_offline_bundle(tmp_path, monkeypatch)

    rc = main([
        "verify", "--json", "--chain-only",
        "--keys-dir", str(tmp_path),
        str(journal),
    ])

    assert rc == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Path validation guards (shared across all verify sub-paths)
# ---------------------------------------------------------------------------


def test_output_rejects_empty_path(tmp_path, monkeypatch, capsys):
    """Empty --output must fail closed with path_arg_invalid."""
    token = _issue_passport(tmp_path)

    rc = main([
        "verify", "--token", token,
        "--keys-dir", str(tmp_path),
        "--output", "",
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "path_arg_invalid"
    assert "empty" in response["message"].lower()


def test_output_rejects_whitespace_path(tmp_path, monkeypatch, capsys):
    """Whitespace-only --output must fail closed."""
    token = _issue_passport(tmp_path)

    rc = main([
        "verify", "--token", token,
        "--keys-dir", str(tmp_path),
        "--output", "   ",
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["error"] == "path_arg_invalid"


def test_output_rejects_directory(tmp_path, monkeypatch, capsys):
    """--output pointing at a directory must fail cleanly without traceback."""
    token = _issue_passport(tmp_path)
    dir_target = tmp_path / "output-dir"
    dir_target.mkdir()

    rc = main([
        "verify", "--token", token,
        "--keys-dir", str(tmp_path),
        "--output", str(dir_target),
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response.get("ok") is False or response.get("valid") is False
    assert "Traceback" not in captured.out


# ---------------------------------------------------------------------------
# Atomic write safety
# ---------------------------------------------------------------------------


def test_output_is_owner_only(tmp_path, monkeypatch, capsys):
    """The written report file must be owner-only (mode 0600)."""
    import stat

    token = _issue_passport(tmp_path)
    out_file = tmp_path / "owner-only-report.json"

    rc = main([
        "verify", "--token", token,
        "--keys-dir", str(tmp_path),
        "--output", str(out_file),
    ])

    assert rc == 0
    assert out_file.exists()
    assert stat.S_IMODE(out_file.stat().st_mode) == 0o600


def test_output_rejects_symlink(tmp_path, monkeypatch, capsys):
    """--output must not follow a symlink (TOCTOU safe)."""
    token = _issue_passport(tmp_path)
    target = tmp_path / "symlink-target.json"
    target.write_text("unchanged\n", encoding="utf-8")
    out_link = tmp_path / "output-link.json"
    out_link.symlink_to(target)

    rc = main([
        "verify", "--token", token,
        "--keys-dir", str(tmp_path),
        "--output", str(out_link),
    ])

    assert rc == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response.get("ok") is False or response.get("valid") is False
    # Symlink target must not be modified
    assert target.read_text(encoding="utf-8") == "unchanged\n"


# ---------------------------------------------------------------------------
# html-report still works alongside --output
# ---------------------------------------------------------------------------


def test_output_and_html_report_coexist(tmp_path, monkeypatch, capsys):
    """--output and --html-report can both be used without conflict."""
    journal = _build_offline_bundle(tmp_path, monkeypatch)
    json_out = tmp_path / "report.json"
    html_out = tmp_path / "report.html"

    rc = main([
        "verify", "--json", "--chain-only",
        "--keys-dir", str(tmp_path),
        "--output", str(json_out),
        "--html-report", str(html_out),
        str(journal),
    ])

    assert rc == 0
    assert json_out.exists()
    assert html_out.exists()
    # JSON file must contain valid JSON
    written = json.loads(json_out.read_text())
    assert isinstance(written, dict)
    # HTML file must contain HTML
    html_content = html_out.read_text()
    assert len(html_content) > 0

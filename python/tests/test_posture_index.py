"""Acceptance tests for the read-only Ardur posture index."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vibap.passport import MissionPassport, generate_keypair, issue_passport


def _issue_mission(tmp_path: Path, *, allowed_tools: list[str], forbidden_tools: list[str]) -> str:
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="posture-test-agent",
        mission="exercise posture index fixtures",
        allowed_tools=allowed_tools,
        forbidden_tools=forbidden_tools,
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=600,
    )
    return issue_passport(mission, private_key, ttl_s=3600)


def _seed_pre_tool_receipts(tmp_path: Path, monkeypatch, calls: list[dict]) -> Path:
    token = _issue_mission(
        tmp_path,
        allowed_tools=["Read", "Bash"],
        forbidden_tools=["Write"],
    )
    chain_dir = tmp_path / "claude-code-hook"
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(chain_dir))

    from vibap.claude_code_hook import handle_pre_tool_use

    for call in calls:
        handle_pre_tool_use(call, keys_dir=tmp_path)
    return chain_dir


def _assert_placeholder_safe_next_steps(next_steps: list[dict], tmp_path: Path, condition: str) -> None:
    assert next_steps
    assert any(step.get("condition") == condition for step in next_steps)
    encoded = json.dumps(next_steps, sort_keys=True)
    assert str(tmp_path) not in encoded
    assert "<chain-dir>" in encoded
    assert "<keys-dir>" in encoded
    assert "tmp_path" not in encoded


def test_redactor_redacts_local_paths_and_file_uris_but_preserves_https_urls():
    from vibap.posture_index import _Redactor

    redactor = _Redactor()
    local_path = "/tmp/ardur-file-uri-sentinel/private.txt"
    file_uri = "file:///tmp/ardur-file-uri-sentinel/private.txt"
    https_url = "https://example.test/path/private.txt"

    assert local_path not in redactor.text(local_path)
    assert "<PATH:" in redactor.text(local_path)
    redacted_file_uri = redactor.text(file_uri)
    assert "ardur-file-uri-sentinel" not in redacted_file_uri
    assert "private.txt" not in redacted_file_uri
    assert "<PATH:" in redacted_file_uri
    assert redactor.text(https_url) == https_url


def test_scan_redacts_file_uri_targets_in_observations(tmp_path, monkeypatch):
    file_uri_target = "file:///tmp/ardur-file-uri-sentinel/private.txt"
    chain_dir = _seed_pre_tool_receipts(
        tmp_path,
        monkeypatch,
        [
            {
                "session_id": "sess-file-uri-observation",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": file_uri_target},
            }
        ],
    )

    from vibap.posture_index import build_posture_index

    posture = build_posture_index(receipts=chain_dir, keys_dir=tmp_path)
    posture_json = json.dumps(posture, sort_keys=True)

    assert posture["chain_verification"]["status"] == "pass"
    assert file_uri_target not in posture_json
    assert "ardur-file-uri-sentinel" not in posture_json
    assert "private.txt" not in posture_json
    assert "<PATH:" in posture["observations"][0]["target"]


def test_cli_scan_json_redacts_signed_receipt_file_uri_targets(tmp_path, monkeypatch, capsys):
    file_uri_target = "file:///tmp/ardur-cli-file-uri-sentinel/private.txt"
    chain_dir = _seed_pre_tool_receipts(
        tmp_path,
        monkeypatch,
        [
            {
                "session_id": "sess-cli-file-uri",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": file_uri_target},
            }
        ],
    )

    from vibap.cli import main

    assert main(["posture", "scan", "--receipts", str(chain_dir), "--keys-dir", str(tmp_path), "--format", "json"]) == 0
    scan_output = capsys.readouterr().out
    posture = json.loads(scan_output)

    assert posture["chain_verification"]["status"] == "pass"
    assert file_uri_target not in scan_output
    assert "ardur-cli-file-uri-sentinel" not in scan_output
    assert "private.txt" not in scan_output
    assert "<PATH:" in posture["observations"][0]["target"]


def test_scan_valid_chain_with_profile_and_bundle_is_redacted(tmp_path, monkeypatch):
    project = tmp_path / "private-project"
    project.mkdir()
    profile = project / "ARDUR.md"
    profile.write_text(
        "# Ardur Profile\n\nmode: read-only\nscope: ./private-project\n",
        encoding="utf-8",
    )
    evidence_bundle = tmp_path / "bundle.redacted.json"
    evidence_bundle.write_text(
        json.dumps(
            {
                "artifacts": {"policy_digest": "sha256:" + "a" * 64},
                "redaction": {"api_token": "redaction-sentinel-value"},
            }
        ),
        encoding="utf-8",
    )
    target = project / "README.md"
    chain_dir = _seed_pre_tool_receipts(
        tmp_path,
        monkeypatch,
        [
            {
                "session_id": "sess-valid",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": str(target)},
            },
            {
                "session_id": "sess-valid",
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": str(project / "blocked.txt"), "content": "nope"},
            },
        ],
    )

    from vibap.posture_index import build_posture_index

    posture = build_posture_index(
        receipts=chain_dir,
        keys_dir=tmp_path,
        profile=profile,
        evidence_bundle=evidence_bundle,
    )
    posture_json = json.dumps(posture, sort_keys=True)

    assert posture["schema_version"] == "ardur.posture_index.v0"
    assert posture["positioning"] == "derived_local_evidence"
    assert posture["chain_verification"]["status"] == "pass"
    assert posture["next_steps"] == []
    assert posture["summary"]["receipt_count"] == 2
    assert posture["summary"]["policy_verdict_counts"] == {"allow": 1, "deny": 1, "unknown": 0}
    assert posture["observed_tools"] == {"Read": 1, "Write": 1}
    assert posture["observed_actions"] == {"read": 1, "write": 1}
    assert posture["profile"]["sha256"] == hashlib.sha256(profile.read_bytes()).hexdigest()
    assert posture["policy"]["digests"] == ["sha256:" + "a" * 64]
    assert "redaction-sentinel-value" not in posture_json
    assert "[REDACTED]" in posture_json
    assert str(tmp_path) not in posture_json
    assert str(project) not in posture_json
    assert "<PATH:" in posture_json


def test_scan_broken_chain_reports_failed_verification_without_mutating(tmp_path, monkeypatch):
    chain_dir = _seed_pre_tool_receipts(
        tmp_path,
        monkeypatch,
        [
            {
                "session_id": "sess-broken",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": str(tmp_path / "one.txt")},
            },
            {
                "session_id": "sess-broken",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": str(tmp_path / "two.txt")},
            },
        ],
    )
    receipt_file = next(chain_dir.rglob("receipts.jsonl"))
    before = receipt_file.read_text(encoding="utf-8")
    lines = before.splitlines()
    receipt_file.write_text(lines[1] + "\n", encoding="utf-8")

    from vibap.posture_index import build_posture_index

    posture = build_posture_index(receipts=chain_dir, keys_dir=tmp_path)

    assert receipt_file.read_text(encoding="utf-8") == lines[1] + "\n"
    assert posture["chain_verification"]["status"] == "fail"
    assert posture["chains"][0]["verification"]["status"] == "fail"
    assert "broken_receipt_chain" in posture["coverage_gaps"]
    assert posture["summary"]["receipt_count"] == 1
    _assert_placeholder_safe_next_steps(posture["next_steps"], tmp_path, "broken_receipt_chain")


def test_scan_missing_telemetry_returns_unknown_gap(tmp_path):
    from vibap.posture_index import build_posture_index, format_posture_report

    posture = build_posture_index(receipts=tmp_path / "missing-telemetry", keys_dir=tmp_path)

    assert posture["summary"]["receipt_count"] == 0
    assert posture["chain_verification"]["status"] == "missing"
    assert posture["summary"]["policy_verdict_counts"] == {"allow": 0, "deny": 0, "unknown": 1}
    assert "missing_receipt_telemetry" in posture["coverage_gaps"]
    _assert_placeholder_safe_next_steps(posture["next_steps"], tmp_path, "missing_receipt_telemetry")
    markdown = format_posture_report(posture)
    assert "## Next steps" in markdown
    assert "ardur posture scan --receipts <chain-dir> --keys-dir <keys-dir> --format markdown" in markdown
    assert str(tmp_path) not in markdown


def test_scan_not_verified_chain_includes_keys_next_steps(tmp_path, monkeypatch):
    chain_dir = _seed_pre_tool_receipts(
        tmp_path,
        monkeypatch,
        [
            {
                "session_id": "sess-not-verified",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": str(tmp_path / "unverified.txt")},
            }
        ],
    )

    from vibap.posture_index import build_posture_index

    posture = build_posture_index(receipts=chain_dir, keys_dir=tmp_path / "missing-keys")

    assert posture["chain_verification"]["status"] == "not_verified"
    assert "receipt_chain_not_verified" in posture["coverage_gaps"]
    _assert_placeholder_safe_next_steps(posture["next_steps"], tmp_path, "receipt_chain_not_verified")
    assert any(
        step.get("command") == "ardur posture scan --receipts <chain-dir> --keys-dir <keys-dir> --format markdown"
        for step in posture["next_steps"]
    )


def test_scan_unknown_boundary_for_bash_subprocess_effects(tmp_path, monkeypatch):
    chain_dir = _seed_pre_tool_receipts(
        tmp_path,
        monkeypatch,
        [
            {
                "session_id": "sess-unknown-boundary",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": f"python3 {tmp_path / 'script.py'}"},
            }
        ],
    )

    from vibap.posture_index import build_posture_index

    posture = build_posture_index(receipts=chain_dir, keys_dir=tmp_path)

    assert posture["summary"]["policy_verdict_counts"] == {"allow": 1, "deny": 0, "unknown": 0}
    assert posture["summary"]["boundary_counts"]["unknown"] == 1
    assert posture["summary"]["unknown_boundary_count"] == 1
    assert "tool_boundary_only:bash_subprocess_effects" in posture["coverage_gaps"]


def test_cli_scan_json_and_report_markdown(tmp_path, monkeypatch, capsys):
    chain_dir = _seed_pre_tool_receipts(
        tmp_path,
        monkeypatch,
        [
            {
                "session_id": "sess-cli",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": str(tmp_path / "cli.txt")},
            }
        ],
    )

    from vibap.cli import main

    assert main(["posture", "scan", "--receipts", str(chain_dir), "--keys-dir", str(tmp_path), "--format", "json"]) == 0
    scan_output = capsys.readouterr().out
    posture = json.loads(scan_output)
    assert posture["chain_verification"]["status"] == "pass"
    assert str(tmp_path) not in scan_output

    posture_file = tmp_path / "posture.json"
    posture_file.write_text(scan_output, encoding="utf-8")
    assert main(["posture", "report", "--input", str(posture_file), "--format", "markdown"]) == 0
    markdown = capsys.readouterr().out
    assert "# Ardur Posture Report" in markdown
    assert "derived local evidence" in markdown.lower()
    assert "Read: 1" in markdown
    assert "## Next steps" not in markdown
    assert str(tmp_path) not in markdown


def test_cli_posture_report_missing_input_json_returns_next_steps_without_path_leak(tmp_path, capsys):
    from vibap.cli import main

    missing_input = tmp_path / "missing-posture.json"

    assert main(["posture", "report", "--input", str(missing_input), "--format", "json"]) == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    encoded = json.dumps(response, sort_keys=True)

    assert captured.err == ""
    assert response["ok"] is False
    assert response["error"] == "posture_report_input_missing"
    assert response["condition"] == "posture_report_input_missing"
    assert "next_steps" in response
    assert "<posture-json>" in encoded
    assert "<chain-dir>" in encoded
    assert str(tmp_path) not in encoded
    assert "Traceback" not in captured.out


def test_cli_posture_report_malformed_input_json_returns_next_steps_without_path_leak(tmp_path, capsys):
    from vibap.cli import main

    malformed_input = tmp_path / "malformed-posture.json"
    malformed_input.write_text("{not-json", encoding="utf-8")

    assert main(["posture", "report", "--input", str(malformed_input), "--format", "json"]) == 1
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    encoded = json.dumps(response, sort_keys=True)

    assert captured.err == ""
    assert response["ok"] is False
    assert response["error"] == "posture_report_input_malformed"
    assert response["condition"] == "posture_report_input_malformed"
    assert "next_steps" in response
    assert "<posture-json>" in encoded
    assert str(tmp_path) not in encoded
    assert "Traceback" not in captured.out


def test_cli_posture_report_missing_input_markdown_returns_next_steps_without_path_leak(tmp_path, capsys):
    from vibap.cli import main

    missing_input = tmp_path / "missing-posture.json"

    assert main(["posture", "report", "--input", str(missing_input), "--format", "markdown"]) == 1
    captured = capsys.readouterr()

    assert captured.err == ""
    assert "Error: Posture report input file could not be read." in captured.out
    assert "Next steps:" in captured.out
    assert "ardur posture scan --receipts <chain-dir> --keys-dir <keys-dir> --format json > <posture-json>" in captured.out
    assert str(tmp_path) not in captured.out
    assert "Traceback" not in captured.out


def test_cli_scan_rejects_empty_receipts_path(tmp_path, capsys):
    """Empty --receipts must fail closed instead of silently scanning CWD."""
    from vibap.cli import main

    rc = main(["posture", "scan", "--receipts", "", "--keys-dir", str(tmp_path), "--format", "json"])
    assert rc == 1
    captured = capsys.readouterr()
    posture = json.loads(captured.out)
    assert posture["ok"] is False
    assert posture["error"] == "posture_receipts_empty"
    assert posture["condition"] == "posture_receipts_empty"
    assert "empty" in posture["message"].lower()
    assert "Traceback" not in captured.out
    assert str(tmp_path) not in captured.out


def test_cli_scan_rejects_whitespace_receipts_path(tmp_path, capsys):
    """Whitespace-only --receipts must fail closed instead of silently scanning CWD."""
    from vibap.cli import main

    rc = main(["posture", "scan", "--receipts", "   ", "--keys-dir", str(tmp_path), "--format", "json"])
    assert rc == 1
    captured = capsys.readouterr()
    posture = json.loads(captured.out)
    assert posture["ok"] is False
    assert posture["error"] == "posture_receipts_empty"
    assert posture["condition"] == "posture_receipts_empty"
    assert "Traceback" not in captured.out
    assert str(tmp_path) not in captured.out


def test_build_posture_index_rejects_empty_receipts():
    """Module-level API must also reject empty receipts."""
    from vibap.posture_index import PostureReceiptsError, build_posture_index

    raised = False
    try:
        build_posture_index(receipts="")
    except PostureReceiptsError as exc:
        raised = True
        assert exc.condition == "posture_receipts_empty"
    assert raised, "expected PostureReceiptsError for empty receipts"


def test_build_posture_index_rejects_whitespace_receipts():
    """Module-level API must also reject whitespace-only receipts."""
    from vibap.posture_index import PostureReceiptsError, build_posture_index

    raised = False
    try:
        build_posture_index(receipts="   ")
    except PostureReceiptsError as exc:
        raised = True
        assert exc.condition == "posture_receipts_empty"
    assert raised, "expected PostureReceiptsError for whitespace receipts"

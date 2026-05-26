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


def test_scan_missing_telemetry_returns_unknown_gap(tmp_path):
    from vibap.posture_index import build_posture_index

    posture = build_posture_index(receipts=tmp_path / "missing-telemetry", keys_dir=tmp_path)

    assert posture["summary"]["receipt_count"] == 0
    assert posture["chain_verification"]["status"] == "missing"
    assert posture["summary"]["policy_verdict_counts"] == {"allow": 0, "deny": 0, "unknown": 1}
    assert "missing_receipt_telemetry" in posture["coverage_gaps"]


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
    assert str(tmp_path) not in markdown

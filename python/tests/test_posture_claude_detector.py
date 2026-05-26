"""Acceptance tests for the Claude Code read-only posture detector."""

from __future__ import annotations

import json
from pathlib import Path

from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.shareable_redaction import local_path_leak_hits


def _issue_mission(tmp_path: Path) -> str:
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="claude-posture-test-agent",
        mission="exercise Claude Code posture detection fixtures",
        allowed_tools=["Read", "Write", "Bash", "WebFetch", "Task", "SubagentStart"],
        forbidden_tools=["Write"],
        resource_scope=[],
        max_tool_calls=50,
        max_duration_s=600,
    )
    return issue_passport(mission, private_key, ttl_s=3600)


def _seed_claude_receipts(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    token = _issue_mission(tmp_path)
    home = tmp_path / "home"
    chain_dir = tmp_path / "claude-code-hook"
    project = tmp_path / "secret-project"
    project.mkdir()

    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(home))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(chain_dir))
    monkeypatch.setenv("ARDUR_TRACE_ID", "trace-posture-fixture")

    from vibap.claude_code_hook import handle_pre_tool_use, handle_subagent_start

    handle_pre_tool_use(
        {
            "session_id": "sess-posture",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(project / "private.txt"),
                "content": "api_key=sk-test-secret-value-1234567890",
            },
            "cwd": str(project),
        },
        keys_dir=tmp_path,
    )
    handle_pre_tool_use(
        {
            "session_id": "sess-posture",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"python3 {project / 'script.py'}"},
            "cwd": str(project),
        },
        keys_dir=tmp_path,
    )
    handle_pre_tool_use(
        {
            "session_id": "sess-posture",
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.test/agent-risk"},
            "cwd": str(project),
        },
        keys_dir=tmp_path,
    )
    handle_pre_tool_use(
        {
            "session_id": "sess-posture",
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_input": {"subagent_type": "general-purpose", "description": "inspect local trace"},
            "cwd": str(project),
        },
        keys_dir=tmp_path,
    )
    handle_subagent_start(
        {
            "session_id": "sess-posture",
            "hook_event_name": "SubagentStart",
            "agent_id": "agent-child-1",
            "agent_type": "general-purpose",
            "agent_transcript_path": str(project / "agent-transcript.jsonl"),
            "cwd": str(project),
        },
        keys_dir=tmp_path,
    )
    return chain_dir, project


def test_claude_detector_extracts_governance_signals_and_redacts_shareable_output(tmp_path, monkeypatch):
    chain_dir, project = _seed_claude_receipts(tmp_path, monkeypatch)

    from vibap.posture.claude_detector import build_claude_posture_summary

    first = build_claude_posture_summary(receipts=chain_dir, keys_dir=tmp_path)
    second = build_claude_posture_summary(receipts=chain_dir, keys_dir=tmp_path)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["schema_version"] == "ardur.claude_posture_detector.v0"
    assert first["positioning"] == "read_only_observation"
    assert first["chain_verification"] == {"status": "pass", "ok": True, "chain_count": 1}
    assert first["summary"]["receipt_count"] == 5
    assert first["summary"]["signal_counts"] == {
        "command_executions": 1,
        "file_writes": 1,
        "network_activity_markers": 1,
        "subagent_spawns": 2,
        "tool_denials": 1,
    }
    assert first["signals"]["tool_denials"]["events"][0]["tool"] == "Write"
    assert first["signals"]["file_writes"]["events"][0]["verdict"] == "violation"
    assert first["signals"]["command_executions"]["events"][0]["tool"] == "Bash"
    assert first["signals"]["network_activity_markers"]["events"][0]["tool"] == "WebFetch"
    assert {event["tool"] for event in first["signals"]["subagent_spawns"]["events"]} == {"Task", "SubagentStart"}
    assert first["summary"]["subagent_registry_records"] == 1
    assert first["narrative_fields"] == first["summary"]["signal_counts"] | {
        "receipt_count": 5,
        "chain_count": 1,
        "verification_status": "pass",
    }
    assert "read-only Claude Code posture scan observed 5 receipts" in first["narrative"]
    assert "does not enforce policy" in first["narrative"]

    shareable = json.dumps(first, sort_keys=True)
    assert str(tmp_path) not in shareable
    assert str(project) not in shareable
    assert "secret-project" not in shareable
    assert "private.txt" not in shareable
    assert "script.py" not in shareable
    assert "agent-transcript.jsonl" not in shareable
    assert "sk-tes...7890" not in shareable
    assert local_path_leak_hits(shareable) == []


def test_claude_detector_reports_missing_receipts_as_observation_gap(tmp_path):
    from vibap.posture.claude_detector import build_claude_posture_summary

    summary = build_claude_posture_summary(receipts=tmp_path / "missing", keys_dir=tmp_path)

    assert summary["chain_verification"] == {"status": "missing", "ok": False, "chain_count": 0}
    assert summary["summary"]["receipt_count"] == 0
    assert summary["summary"]["signal_counts"] == {
        "command_executions": 0,
        "file_writes": 0,
        "network_activity_markers": 0,
        "subagent_spawns": 0,
        "tool_denials": 0,
    }
    assert "missing_claude_receipt_telemetry" in summary["coverage_gaps"]
    assert "0 receipts" in summary["narrative"]

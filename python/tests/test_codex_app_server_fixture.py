"""Tests for the local-only Ardur Codex app-server/host-event fixture."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.receipt import verify_chain


def _issue_codex_passport(
    keys_dir: Path,
    *,
    allowed_tools: list[str] | None = None,
    forbidden_tools: list[str] | None = None,
    resource_scope: list[str] | None = None,
    allowed_side_effect_classes: list[str] | None = None,
) -> tuple[str, EllipticCurvePublicKey]:
    private_key, public_key = generate_keypair(keys_dir=keys_dir)
    mission = MissionPassport(
        agent_id="codex-app-server-fixture",
        mission="exercise Codex app-server local host-event fixture",
        allowed_tools=allowed_tools or ["*"],
        forbidden_tools=forbidden_tools or [],
        resource_scope=resource_scope or [],
        allowed_side_effect_classes=allowed_side_effect_classes or [],
        max_tool_calls=20,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    return token, public_key


def test_codex_fixture_writes_local_config_and_redacted_shareable_context(tmp_path):
    from vibap.codex_app_server_fixture import build_local_fixture, build_shareable_context

    fixture = build_local_fixture(
        home=tmp_path / "home",
        project_dir=tmp_path / "project",
        chain_dir=tmp_path / "chain",
        keys_dir=tmp_path / "keys",
    )

    config_path = Path(fixture["config_path"])
    hook_schema_path = Path(fixture["hook_schema_path"])
    project_context_path = Path(fixture["project_context_path"])

    assert config_path.is_file()
    assert hook_schema_path.is_file()
    assert project_context_path.is_file()
    assert config_path.is_relative_to(tmp_path / "home")
    assert hook_schema_path.is_relative_to(tmp_path / "home")

    config = json.loads(config_path.read_text(encoding="utf-8"))
    config_text = json.dumps(config, sort_keys=True)
    assert "ardur codex-app-server-event --keys-dir" in config_text
    assert str(Path.home() / ".codex") not in config_text

    shareable = build_shareable_context(fixture)
    shareable_text = json.dumps(shareable, sort_keys=True)

    assert shareable["schema_version"] == "ardur.codex_app_server.local_context.v0.1"
    assert shareable["claim_boundary"]["scope"] == "local_fixture_only"
    assert "live Codex cloud enforcement" in shareable["claim_boundary"]["not_claimed"]
    assert "provider_hidden_actions" in shareable["unknown_boundaries"]
    assert shareable["host_context"]["config_digest"]["alg"] == "sha-256"
    assert shareable["host_context"]["hook_schema_digest"]["alg"] == "sha-256"
    assert str(tmp_path) not in shareable_text


def test_codex_fixture_default_does_not_write_callers_global_codex_home(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    project = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    keys_dir = tmp_path / "keys"
    caller_home.mkdir()
    project.mkdir()
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "vibap.cli",
            "codex-app-server-fixture",
            "--project-dir",
            str(project),
            "--chain-dir",
            str(chain_dir),
            "--keys-dir",
            str(keys_dir),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=repo_root,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
    assert not (caller_home / ".codex").exists()
    assert (ardur_home / "codex-app-server-fixture" / ".codex" / "config.json").is_file()
    output = json.loads(completed.stdout)
    assert output["claim_boundary"]["scope"] == "local_fixture_only"


def test_codex_host_events_emit_allow_deny_unknown_receipts_and_redacted_report(tmp_path, monkeypatch):
    from vibap.codex_app_server_fixture import build_shareable_report, handle_host_event

    keys_dir = tmp_path / "keys"
    home = tmp_path / "home"
    project = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    project.mkdir()
    (project / "README.md").write_text("hello\n", encoding="utf-8")
    token, public_key = _issue_codex_passport(
        keys_dir,
        allowed_tools=["read_file", "shell_command", "codex_unmapped_tool"],
        forbidden_tools=["shell_command"],
        resource_scope=[str(project), f"{project}/*"],
    )
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(home))
    monkeypatch.setenv("ARDUR_CODEX_APP_SERVER_DIR", str(chain_dir))

    host_context = {
        "config": {
            "approval_policy": "never",
            "sandbox_mode": "workspace-write",
            "api_key": "raw-secret-value-that-must-not-be-copied",
        },
        "hook_schema": {"event": "host_event", "schema_version": "0.1"},
        "protocol": {"transport": "local-app-server-fixture"},
    }

    allow_output = handle_host_event(
        {
            "event_type": "tool_decision",
            "event_id": "evt-allow",
            "session_id": "codex-session-1",
            "cwd": str(project),
            "tool_name": "read_file",
            "tool_input": {"path": str(project / "README.md")},
            "host_context": host_context,
        },
        keys_dir=keys_dir,
    )
    deny_output = handle_host_event(
        {
            "event_type": "tool_decision",
            "event_id": "evt-deny",
            "session_id": "codex-session-1",
            "cwd": str(project),
            "tool_name": "shell_command",
            "tool_input": {"command": "echo blocked"},
            "host_context": host_context,
        },
        keys_dir=keys_dir,
    )
    unknown_output = handle_host_event(
        {
            "event_type": "tool_decision",
            "event_id": "evt-unknown",
            "session_id": "codex-session-1",
            "cwd": str(project),
            "tool_name": "codex_unmapped_tool",
            "tool_input": {"opaque_target": str(project / "opaque")},
            "host_context": host_context,
        },
        keys_dir=keys_dir,
    )

    assert allow_output["status"] == "allow"
    assert deny_output["status"] == "deny"
    assert unknown_output["status"] == "unknown"
    assert unknown_output["block"] is True

    receipt_files = list(chain_dir.rglob("receipts.jsonl"))
    assert len(receipt_files) == 1
    receipt_file = receipt_files[0].resolve(strict=False)
    assert receipt_file.is_relative_to(chain_dir.resolve(strict=False))
    assert receipt_file.parent != chain_dir.resolve(strict=False)
    receipt_jwts = [line.strip() for line in receipt_files[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(receipt_jwts) == 3
    verify_chain(receipt_jwts, public_key, verify_expiry=False)

    claims = [pyjwt.decode(token, options={"verify_signature": False}) for token in receipt_jwts]
    assert [claim["verdict"] for claim in claims] == [
        "compliant",
        "violation",
        "insufficient_evidence",
    ]
    codex_meta = claims[0]["measurements"]["codex_app_server"]
    assert codex_meta["session_context"]["session_id"] == "codex-session-1"
    assert codex_meta["policy_input"]["approval_policy"] == "never"
    assert codex_meta["policy_input"]["sandbox_mode"] == "workspace-write"
    assert codex_meta["host_context"]["config_digest"]["alg"] == "sha-256"
    assert "provider_hidden_actions" in codex_meta["unknown_boundaries"]
    assert claims[2]["public_denial_reason"] == "insufficient_evidence"
    assert claims[2]["measurements"]["codex_app_server"]["mapping_confidence"] == "unknown"
    assert "raw-secret-value-that-must-not-be-copied" not in json.dumps(claims, sort_keys=True)

    report = build_shareable_report(
        home=home,
        chain_dir=chain_dir,
        keys_dir=keys_dir,
        verify_expiry=False,
    )
    report_text = json.dumps(report, sort_keys=True)
    assert report["policy_verdict_counts"] == {"allow": 1, "deny": 1, "unknown": 1}
    assert "provider_hidden_actions" in report["coverage_gaps"]
    assert "unmapped_codex_host_event_schema" in report["coverage_gaps"]
    assert str(tmp_path) not in report_text
    assert "raw-secret-value-that-must-not-be-copied" not in report_text


def test_codex_shareable_report_summarizes_high_risk_target_text(tmp_path, monkeypatch):
    from vibap.codex_app_server_fixture import build_shareable_report, handle_host_event

    keys_dir = tmp_path / "keys"
    home = tmp_path / "home"
    chain_dir = tmp_path / "chain"
    leak_sentinel = "FAKE_TOKEN_FOR_TEST_ONLY_codex_report_leak_sentinel"
    token, _public_key = _issue_codex_passport(
        keys_dir,
        allowed_tools=[
            "shell_command",
            "run_shell_command",
            "shell",
            "web_fetch",
            "web_search",
            "read_file",
            "codex_unmapped_tool",
        ],
    )
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(home))
    monkeypatch.setenv("ARDUR_CODEX_APP_SERVER_DIR", str(chain_dir))

    events = [
        {
            "tool_name": "shell_command",
            "tool_input": {"command": f"env TEST_TOKEN={leak_sentinel} python -V"},
        },
        {
            "tool_name": "run_shell_command",
            "tool_input": {"command": f"printf %s {leak_sentinel}"},
        },
        {
            "tool_name": "shell",
            "tool_input": {"command": f"curl https://example.test/?token={leak_sentinel}"},
        },
        {
            "tool_name": "web_fetch",
            "tool_input": {"url": f"https://example.test/search?access_token={leak_sentinel}&q=docs"},
        },
        {
            "tool_name": "web_search",
            "tool_input": {"query": f"bearer token {leak_sentinel}"},
        },
        {
            "tool_name": "read_file",
            "tool_input": {"target": f"opaque-target:{leak_sentinel}"},
        },
        {
            "tool_name": "codex_unmapped_tool",
            "tool_input": {"opaque_target": f"opaque://{leak_sentinel}"},
        },
    ]
    for idx, event in enumerate(events):
        output = handle_host_event(
            {
                "event_type": "tool_decision",
                "event_id": f"evt-public-target-{idx}",
                "session_id": "codex-public-target-session",
                "tool_name": event["tool_name"],
                "tool_input": event["tool_input"],
            },
            keys_dir=keys_dir,
        )
        if event["tool_name"] == "codex_unmapped_tool":
            assert output["status"] == "unknown"
        else:
            assert output["status"] == "allow"

    report = build_shareable_report(
        home=home,
        chain_dir=chain_dir,
        keys_dir=keys_dir,
        verify_expiry=False,
    )
    report_text = json.dumps(report, sort_keys=True)

    assert report["receipt_count"] == len(events)
    assert leak_sentinel not in report_text
    for receipt in report["receipts"]:
        assert receipt["target"].startswith("<redacted-target:")
        assert receipt["target_digest"]["alg"] == "sha-256"
        assert leak_sentinel not in json.dumps(receipt, sort_keys=True)


def test_codex_shareable_report_redacts_policy_reason_target_echoes(tmp_path, monkeypatch):
    from vibap.codex_app_server_fixture import build_shareable_report, handle_host_event

    keys_dir = tmp_path / "keys"
    home = tmp_path / "home"
    chain_dir = tmp_path / "chain"
    leak_sentinel = "FAKE_TOKEN_FOR_TEST_ONLY_codex_policy_reason_sentinel"
    raw_url = f"https://outside.example.test/download?access_token={leak_sentinel}"
    token, _public_key = _issue_codex_passport(
        keys_dir,
        allowed_tools=["web_fetch"],
        resource_scope=["https://allowed.example.test/*"],
    )
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(home))
    monkeypatch.setenv("ARDUR_CODEX_APP_SERVER_DIR", str(chain_dir))

    output = handle_host_event(
        {
            "event_type": "tool_decision",
            "event_id": "evt-policy-reason-redaction",
            "session_id": "codex-policy-reason-session",
            "tool_name": "web_fetch",
            "tool_input": {"url": raw_url},
        },
        keys_dir=keys_dir,
    )
    assert output["status"] == "deny"

    report = build_shareable_report(
        home=home,
        chain_dir=chain_dir,
        keys_dir=keys_dir,
        verify_expiry=False,
    )
    report_text = json.dumps(report, sort_keys=True)
    receipt = report["receipts"][0]

    assert leak_sentinel not in report_text
    assert raw_url not in report_text
    assert receipt["target"].startswith("<redacted-target:")
    assert receipt["target_digest"]["alg"] == "sha-256"
    assert receipt["reason"].startswith("<redacted-policy-reason:")
    assert receipt["reason_digest"]["alg"] == "sha-256"
    for decision in receipt["policy_decisions"]:
        assert decision["reason"].startswith("<redacted-policy-reason:")
        assert decision["reason_digest"]["alg"] == "sha-256"


def test_codex_app_server_event_cli_uses_exit_code_two_for_blocking_unknown(tmp_path):
    keys_dir = tmp_path / "keys"
    home = tmp_path / "home"
    project = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    project.mkdir()
    token, _public_key = _issue_codex_passport(
        keys_dir,
        allowed_tools=["codex_unmapped_tool"],
        resource_scope=[str(project), f"{project}/*"],
    )
    repo_root = Path(__file__).resolve().parents[2]
    env = {
        **os.environ,
        "ARDUR_MISSION_PASSPORT": token,
        "VIBAP_HOME": str(home),
        "ARDUR_CODEX_APP_SERVER_DIR": str(chain_dir),
        "PYTHONPATH": str(repo_root / "python"),
    }
    payload = {
        "event_type": "tool_decision",
        "event_id": "evt-cli-unknown",
        "session_id": "codex/session/../escape",
        "cwd": str(project),
        "tool_name": "codex_unmapped_tool",
        "tool_input": {"opaque_target": str(project / "opaque")},
        "host_context": {"config": {"approval_policy": "never", "sandbox_mode": "workspace-write"}},
    }

    completed = subprocess.run(
        [sys.executable, "-m", "vibap.cli", "codex-app-server-event", "--keys-dir", str(keys_dir)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=repo_root,
        timeout=20,
    )

    assert completed.returncode == 2
    output = json.loads(completed.stdout)
    assert output["status"] == "unknown"
    assert output["block"] is True
    assert "insufficient evidence" in output["message"].lower()
    receipt_files = list(chain_dir.rglob("receipts.jsonl"))
    assert len(receipt_files) == 1
    assert receipt_files[0].resolve(strict=False).is_relative_to(chain_dir.resolve(strict=False))
    assert receipt_files[0].parent != chain_dir

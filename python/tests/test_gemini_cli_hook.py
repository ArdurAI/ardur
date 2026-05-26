"""Tests for the local-only Ardur Gemini CLI hook/context proof slice."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import jwt as pyjwt
import pytest

from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.receipt import verify_chain


def _issue_gemini_passport(
    keys_dir: Path,
    *,
    allowed_tools: list[str] | None = None,
    forbidden_tools: list[str] | None = None,
    resource_scope: list[str] | None = None,
    allowed_side_effect_classes: list[str] | None = None,
) -> tuple[str, object]:
    private_key, public_key = generate_keypair(keys_dir=keys_dir)
    mission = MissionPassport(
        agent_id="gemini-local-fixture",
        mission="exercise Gemini CLI local hook fixture",
        allowed_tools=allowed_tools or ["*"],
        forbidden_tools=forbidden_tools or [],
        resource_scope=resource_scope or [],
        allowed_side_effect_classes=allowed_side_effect_classes or [],
        max_tool_calls=20,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    return token, public_key


def test_gemini_fixture_writes_local_settings_and_redacted_shareable_context(tmp_path):
    from vibap.gemini_cli_hook import build_local_fixture, build_shareable_context

    fixture = build_local_fixture(
        home=tmp_path / "home",
        project_dir=tmp_path / "project",
        chain_dir=tmp_path / "chain",
        keys_dir=tmp_path / "keys",
    )

    settings_path = Path(fixture["settings_path"])
    extension_path = Path(fixture["extension_path"])
    project_context_path = Path(fixture["project_context_path"])

    assert settings_path.is_file()
    assert extension_path.is_file()
    assert project_context_path.is_file()
    assert settings_path.is_relative_to(tmp_path / "home")
    assert extension_path.is_relative_to(tmp_path / "home")

    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings_text = json.dumps(settings, sort_keys=True)
    assert "ardur gemini-cli-hook --phase pre" in settings_text
    assert str(Path.home() / ".gemini") not in settings_text

    shareable = build_shareable_context(fixture)
    shareable_text = json.dumps(shareable, sort_keys=True)

    assert shareable["schema_version"] == "ardur.gemini_cli.local_context.v0.1"
    assert shareable["claim_boundary"]["scope"] == "local_fixture_only"
    assert "live Gemini enforcement" in shareable["claim_boundary"]["not_claimed"]
    assert "provider_hidden_actions" in shareable["unknown_boundaries"]
    assert shareable["host_context"]["settings_digest"]["alg"] == "sha-256"
    assert shareable["host_context"]["extension_digest"]["alg"] == "sha-256"
    assert str(tmp_path) not in shareable_text


def test_gemini_fixture_default_does_not_write_callers_global_gemini_home(tmp_path):
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
            "gemini-cli-fixture",
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
    assert not (caller_home / ".gemini").exists()
    assert (ardur_home / "gemini-cli-fixture" / ".gemini" / "settings.json").is_file()
    output = json.loads(completed.stdout)
    assert output["claim_boundary"]["scope"] == "local_fixture_only"


def test_gemini_shell_denied_by_read_only_side_effect_policy(tmp_path, monkeypatch):
    from vibap.gemini_cli_hook import handle_pre_tool_call

    keys_dir = tmp_path / "keys"
    home = tmp_path / "home"
    chain_dir = tmp_path / "chain"
    token, _public_key = _issue_gemini_passport(
        keys_dir,
        allowed_tools=["run_shell_command"],
        allowed_side_effect_classes=["none"],
    )
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(home))
    monkeypatch.setenv("ARDUR_GEMINI_HOOK_DIR", str(chain_dir))

    output = handle_pre_tool_call(
        {
            "event_name": "pre_tool_call",
            "session_id": "gemini-read-only-session",
            "tool_name": "run_shell_command",
            "tool_args": {"command": "echo should-not-run"},
        },
        keys_dir=keys_dir,
    )

    assert output["status"] == "deny"
    assert output["block"] is True
    assert "side_effect_class" in output["message"]
    assert "state_change" in output["message"]


def test_gemini_hook_allow_deny_unknown_receipts_and_redacted_report(tmp_path, monkeypatch):
    from vibap.gemini_cli_hook import build_shareable_report, handle_pre_tool_call

    keys_dir = tmp_path / "keys"
    home = tmp_path / "home"
    project = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    project.mkdir()
    (project / "README.md").write_text("hello\n", encoding="utf-8")
    token, public_key = _issue_gemini_passport(
        keys_dir,
        allowed_tools=["read_file", "run_shell_command", "gemini_unmapped_tool"],
        forbidden_tools=["run_shell_command"],
        resource_scope=[str(project), f"{project}/*"],
    )
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(home))
    monkeypatch.setenv("ARDUR_GEMINI_HOOK_DIR", str(chain_dir))

    host_context = {
        "settings": {
            "trustedFolders": [str(project)],
            "sandbox": False,
            "apiKey": "raw-secret-value-that-must-not-be-copied",
        },
        "policy": {"approvalMode": "default"},
        "extension": {"name": "ardur-local", "version": "0.1.0"},
    }

    allow_output = handle_pre_tool_call(
        {
            "event_name": "pre_tool_call",
            "session_id": "gemini-session-1",
            "cwd": str(project),
            "tool_name": "read_file",
            "tool_args": {"path": str(project / "README.md")},
            "host_context": host_context,
        },
        keys_dir=keys_dir,
    )
    deny_output = handle_pre_tool_call(
        {
            "event_name": "pre_tool_call",
            "session_id": "gemini-session-1",
            "cwd": str(project),
            "tool_name": "run_shell_command",
            "tool_args": {"command": "echo blocked"},
            "host_context": host_context,
        },
        keys_dir=keys_dir,
    )
    unknown_output = handle_pre_tool_call(
        {
            "event_name": "pre_tool_call",
            "session_id": "gemini-session-1",
            "cwd": str(project),
            "tool_name": "gemini_unmapped_tool",
            "tool_args": {"opaque_target": str(project / "opaque")},
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
    receipt_jwts = [line.strip() for line in receipt_files[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(receipt_jwts) == 3
    verify_chain(receipt_jwts, public_key, verify_expiry=False)

    claims = [pyjwt.decode(token, options={"verify_signature": False}) for token in receipt_jwts]
    assert [claim["verdict"] for claim in claims] == [
        "compliant",
        "violation",
        "insufficient_evidence",
    ]
    assert claims[0]["measurements"]["gemini_cli"]["host_context"]["settings_digest"]["alg"] == "sha-256"
    assert "provider_hidden_actions" in claims[0]["measurements"]["gemini_cli"]["unknown_boundaries"]
    assert claims[2]["public_denial_reason"] == "insufficient_evidence"
    assert claims[2]["measurements"]["gemini_cli"]["mapping_confidence"] == "unknown"
    assert "raw-secret-value-that-must-not-be-copied" not in json.dumps(claims, sort_keys=True)

    report = build_shareable_report(
        home=home,
        chain_dir=chain_dir,
        keys_dir=keys_dir,
        redaction_roots={
            "GEMINI_HOME": home,
            "GEMINI_PROJECT": project,
            "ARDUR_GEMINI_CHAIN": chain_dir,
        },
        verify_expiry=False,
    )
    report_text = json.dumps(report, sort_keys=True)
    assert report["policy_verdict_counts"] == {"allow": 1, "deny": 1, "unknown": 1}
    assert report["unknown_boundary_count"] >= 1
    assert "provider_hidden_actions" in report["coverage_gaps"]
    assert str(tmp_path) not in report_text
    assert "raw-secret-value-that-must-not-be-copied" not in report_text


@pytest.mark.parametrize(
    ("session_id", "env_trace_id", "expected_trace_id"),
    [
        ("..", None, ".."),
        (".", None, "."),
        ("gemini/session/../escape", None, "gemini/session/../escape"),
        ("ordinary-session", "..", ".."),
    ],
)
def test_gemini_hook_hashes_external_trace_ids_into_in_chain_receipt_paths(
    tmp_path, monkeypatch, session_id, env_trace_id, expected_trace_id
):
    from vibap.gemini_cli_hook import handle_pre_tool_call

    keys_dir = tmp_path / "keys"
    home = tmp_path / "home"
    project = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    project.mkdir()
    (project / "README.md").write_text("hello\n", encoding="utf-8")
    token, public_key = _issue_gemini_passport(
        keys_dir,
        allowed_tools=["read_file"],
        resource_scope=[str(project), f"{project}/*"],
    )
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(home))
    monkeypatch.setenv("ARDUR_GEMINI_HOOK_DIR", str(chain_dir))
    if env_trace_id is None:
        monkeypatch.delenv("ARDUR_TRACE_ID", raising=False)
    else:
        monkeypatch.setenv("ARDUR_TRACE_ID", env_trace_id)

    output = handle_pre_tool_call(
        {
            "event_name": "pre_tool_call",
            "session_id": session_id,
            "cwd": str(project),
            "tool_name": "read_file",
            "tool_args": {"path": str(project / "README.md")},
        },
        keys_dir=keys_dir,
    )

    assert output["status"] == "allow"
    assert not (chain_dir.parent / "receipts.jsonl").exists()
    receipt_files = list(chain_dir.rglob("receipts.jsonl"))
    assert len(receipt_files) == 1
    chain_root = chain_dir.resolve(strict=False)
    receipt_file = receipt_files[0].resolve(strict=False)
    assert receipt_file.is_relative_to(chain_root)
    assert receipt_file.parent != chain_root
    assert (receipt_file.parent / ".lock").resolve(strict=False).is_relative_to(chain_root)

    receipt_jwts = [line.strip() for line in receipt_files[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    claims = verify_chain(receipt_jwts, public_key, verify_expiry=False)
    assert len(claims) == 1
    assert claims[0]["trace_id"] == expected_trace_id
    assert claims[0]["measurements"]["gemini_cli"]["trace_id"] == expected_trace_id
    assert claims[0]["measurements"]["gemini_cli"]["gemini_session_id"] == session_id


def test_gemini_report_excludes_invalid_jwt_claims_from_trusted_counts(tmp_path):
    from vibap.gemini_cli_hook import CHAIN_FILENAME, build_shareable_report

    keys_dir = tmp_path / "keys"
    chain_file = tmp_path / "chain" / "tampered" / CHAIN_FILENAME
    _token, _public_key = _issue_gemini_passport(keys_dir)
    forged_token = pyjwt.encode(
        {
            "iss": "forged",
            "jti": "forged-receipt",
            "iat": 1_700_000_000,
            "exp": 4_100_000_000,
            "trace_id": "tampered",
            "run_nonce": "tampered",
            "verdict": "compliant",
            "measurements": {"gemini_cli": {"unknown_boundaries": ["forged_gap"]}},
        },
        "wrong-secret",
        algorithm="HS256",
    )
    chain_file.parent.mkdir(parents=True)
    chain_file.write_text(f"{forged_token}\n", encoding="utf-8")

    report = build_shareable_report(
        chain_dir=tmp_path / "chain",
        keys_dir=keys_dir,
        verify_expiry=False,
    )

    assert report["receipt_count"] == 0
    assert report["receipts"] == []
    assert report["policy_verdict_counts"] == {"allow": 0, "deny": 0, "unknown": 0}
    assert "forged_gap" not in report["coverage_gaps"]
    assert report["unknown_boundary_count"] == 0
    assert report["verification"][0]["valid"] is False
    assert report["verification"][0]["receipt_count"] == 0
    assert report["invalid_chains"][0]["token_count"] == 1


def test_gemini_hook_cli_uses_exit_code_two_for_blocking_unknown(tmp_path):
    keys_dir = tmp_path / "keys"
    home = tmp_path / "home"
    project = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    project.mkdir()
    token, _public_key = _issue_gemini_passport(
        keys_dir,
        allowed_tools=["gemini_unmapped_tool"],
        resource_scope=[str(project), f"{project}/*"],
    )
    repo_root = Path(__file__).resolve().parents[2]
    env = {
        **os.environ,
        "ARDUR_MISSION_PASSPORT": token,
        "VIBAP_HOME": str(home),
        "ARDUR_GEMINI_HOOK_DIR": str(chain_dir),
        "PYTHONPATH": str(repo_root / "python"),
    }
    payload = {
        "event_name": "pre_tool_call",
        "session_id": "gemini-session-2",
        "cwd": str(project),
        "tool_name": "gemini_unmapped_tool",
        "tool_args": {"opaque_target": str(project / "opaque")},
        "host_context": {"settings": {"trustedFolders": [str(project)]}},
    }

    completed = subprocess.run(
        [sys.executable, "-m", "vibap.gemini_cli_hook", "pre", "--keys-dir", str(keys_dir)],
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

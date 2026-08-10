"""Acceptance tests for ``ardur verify --attestation-token``.

The signed attestation JWT carries the verdict breakdown (unknowns,
insufficient_evidence, violations, denied_tools) as of commit 75dcd0f.
However, the verify command only handled passport JWTs (--token), offline
journals, anchor bundles, and receiver envelopes — there was no CLI path to
verify a behavioral attestation JWT. These tests exercise the new
``--attestation-token`` flag so an auditor can independently verify an
attestation and inspect its signed claims.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vibap.attestation import issue_attestation
from vibap.cli import main as cli_main
from vibap.passport import generate_keypair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _issue_attestation(keys_dir: Path, **extra_claims) -> str:
    """Issue a behavioral attestation JWT and return the token string."""
    private_key, _public_key = generate_keypair(keys_dir=keys_dir)
    return issue_attestation(
        passport_jti="verify-attest-jti",
        agent_id="verify-attest-agent",
        mission="test verify --attestation-token",
        events=[{"tool": "read", "decision": "permit"}],
        permits=1,
        denials=0,
        elapsed_s=0.5,
        private_key=private_key,
        extra_claims=extra_claims or None,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_verify_attestation_token_success(tmp_path, capsys):
    """verify --attestation-token returns valid + signed claims."""
    token = _issue_attestation(
        tmp_path,
        unknowns=2,
        insufficient_evidence=1,
        violations=0,
        denied_tools=["write_file"],
    )
    rc = cli_main([
        "verify", "--attestation-token", token,
        "--keys-dir", str(tmp_path),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is True
    claims = result["claims"]
    assert claims["type"] == "behavioral_attestation"
    assert claims["permits"] == 1
    assert claims["denials"] == 0
    assert claims["unknowns"] == 2
    assert claims["insufficient_evidence"] == 1
    assert claims["violations"] == 0
    assert claims["denied_tools"] == ["write_file"]
    assert claims["passport_jti"] == "verify-attest-jti"


def test_verify_attestation_token_without_verdict_breakdown(tmp_path, capsys):
    """Old-style attestation tokens (no extra_claims) still verify cleanly."""
    token = _issue_attestation(tmp_path)
    rc = cli_main([
        "verify", "--attestation-token", token,
        "--keys-dir", str(tmp_path),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is True
    assert "claims" in result
    # Verdict breakdown fields absent when not signed in (backward compat)
    assert "unknowns" not in result["claims"]


# ---------------------------------------------------------------------------
# --output flag
# ---------------------------------------------------------------------------


def test_verify_attestation_token_output_file(tmp_path, capsys):
    """verify --attestation-token --output writes claims to a file."""
    token = _issue_attestation(
        tmp_path,
        unknowns=1,
        denied_tools=["rm"],
    )
    out_file = tmp_path / "attestation-report.json"
    rc = cli_main([
        "verify", "--attestation-token", token,
        "--keys-dir", str(tmp_path),
        "--output", str(out_file),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert status["valid"] is True
    assert status["condition"] == "verify_report_written"
    assert status["output"] == str(out_file)

    written = json.loads(out_file.read_text())
    assert written["valid"] is True
    assert written["claims"]["unknowns"] == 1
    assert written["claims"]["denied_tools"] == ["rm"]
    payload_bytes = out_file.read_bytes()
    assert status["report_sha256"] == hashlib.sha256(payload_bytes).hexdigest()


# ---------------------------------------------------------------------------
# --redact-paths flag
# ---------------------------------------------------------------------------


def test_verify_attestation_token_redact_paths(tmp_path, capsys):
    """--redact-paths replaces local paths in the claims output."""
    token = _issue_attestation(tmp_path)
    rc = cli_main([
        "verify", "--attestation-token", token,
        "--keys-dir", str(tmp_path),
        "--redact-paths",
        "--json",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is True
    # The keys_dir path must not leak into the output
    assert str(tmp_path) not in captured.out


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_verify_attestation_token_malformed(tmp_path, capsys):
    """Malformed JWT produces structured error JSON, not a traceback."""
    rc = cli_main([
        "verify", "--attestation-token", "not-a-jwt",
        "--keys-dir", str(tmp_path),
    ])
    assert rc == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is False
    assert "Behavioral attestation" in result["message"]
    assert "Mission Passport" not in result["message"]


def test_verify_attestation_token_malformed_message(tmp_path, capsys):
    """Malformed --attestation-token error says 'Behavioral attestation', not 'Mission Passport'."""
    rc = cli_main([
        "verify", "--attestation-token", "garbage-token",
        "--keys-dir", str(tmp_path),
    ])
    assert rc == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is False
    assert "Behavioral attestation" in result["message"]
    assert "Mission Passport" not in result["message"]


def test_verify_attestation_token_wrong_key(tmp_path, capsys):
    """Token signed by a different key produces verification failure."""
    token = _issue_attestation(tmp_path)
    other_keys = tmp_path / "other-keys"
    other_keys.mkdir()
    generate_keypair(keys_dir=other_keys)
    rc = cli_main([
        "verify", "--attestation-token", token,
        "--keys-dir", str(other_keys),
    ])
    assert rc == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is False


def test_verify_attestation_token_keys_dir_missing(tmp_path, capsys):
    """Missing keys dir produces structured error, not a traceback."""
    token = _issue_attestation(tmp_path)
    missing = tmp_path / "nonexistent-keys"
    rc = cli_main([
        "verify", "--attestation-token", token,
        "--keys-dir", str(missing),
    ])
    assert rc == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is False


def test_verify_attestation_and_token_mutually_exclusive(tmp_path, capsys):
    """--token and --attestation-token cannot be used together."""
    token = _issue_attestation(tmp_path)
    # argparse handles this at the parser level — exit code 2
    import pytest
    with pytest.raises(SystemExit) as exc_info:
        cli_main([
            "verify",
            "--token", token,
            "--attestation-token", token,
            "--keys-dir", str(tmp_path),
        ])
    assert exc_info.value.code == 2


def test_verify_no_input_still_errors(tmp_path, capsys):
    """With no verification input, the error message mentions --attestation-token."""
    rc = cli_main([
        "verify",
        "--keys-dir", str(tmp_path),
    ])
    assert rc == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["valid"] is False
    assert "--attestation-token" in result["message"]


# ---------------------------------------------------------------------------
# Attestation-specific error codes / conditions / next_steps
# (regression: verify --attestation-token must NOT reuse passport error codes)
# ---------------------------------------------------------------------------


def test_verify_attestation_malformed_uses_attestation_error_code(tmp_path, capsys):
    """Malformed attestation JWT returns invalid_attestation_token, not invalid_passport_token."""
    rc = cli_main([
        "verify", "--attestation-token", "garbage-token",
        "--keys-dir", str(tmp_path),
    ])
    assert rc == 1
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "invalid_attestation_token"
    assert result["condition"] == "invalid_attestation_token"


def test_verify_attestation_malformed_next_steps_reference_attestation_commands(tmp_path, capsys):
    """Malformed attestation JWT next_steps point to attest/verify-attestation-token, not issue/verify-token."""
    rc = cli_main([
        "verify", "--attestation-token", "garbage-token",
        "--keys-dir", str(tmp_path),
    ])
    assert rc == 1
    result = json.loads(capsys.readouterr().out)
    steps = result["next_steps"]
    assert len(steps) == 2
    for step in steps:
        assert step["condition"] == "invalid_attestation_token"
    commands = " ".join(s["command"] for s in steps)
    assert "--attestation-token" in commands
    assert "ardur attest" in commands
    # Must NOT mention passport-only commands
    assert "ardur issue" not in commands
    assert "ardur verify --token" not in commands


def test_verify_attestation_wrong_key_uses_attestation_error_code(tmp_path, capsys):
    """Attestation signed by a different key returns invalid_attestation_token."""
    token = _issue_attestation(tmp_path)
    other_keys = tmp_path / "other-keys"
    other_keys.mkdir()
    generate_keypair(keys_dir=other_keys)
    rc = cli_main([
        "verify", "--attestation-token", token,
        "--keys-dir", str(other_keys),
    ])
    assert rc == 1
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is False
    assert result["error"] == "invalid_attestation_token"
    assert result["condition"] == "invalid_attestation_token"


def test_verify_attestation_missing_public_key_uses_attestation_error_code(tmp_path, capsys):
    """Missing passport_public.pem returns attestation_public_key_missing, not passport_public_key_missing."""
    token = _issue_attestation(tmp_path)
    empty_dir = tmp_path / "empty-keys"
    empty_dir.mkdir()
    rc = cli_main([
        "verify", "--attestation-token", token,
        "--keys-dir", str(empty_dir),
    ])
    assert rc == 1
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is False
    assert result["error"] == "attestation_public_key_missing"
    assert result["error_code"] == "attestation_public_key_missing"
    assert result["condition"] == "attestation_public_key_missing"
    assert "Behavioral Attestation" in result["message"]
    steps = result["next_steps"]
    commands = " ".join(s["command"] for s in steps)
    assert "--attestation-token" in commands
    assert "ardur attest" in commands
    assert "ardur issue" not in commands


def test_verify_passport_malformed_still_uses_passport_error_code(tmp_path, capsys):
    """Passport verification error codes are unchanged by the attestation refactor."""
    rc = cli_main([
        "verify", "--token", "garbage-token",
        "--keys-dir", str(tmp_path),
    ])
    assert rc == 1
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "invalid_passport_token"
    assert result["condition"] == "invalid_passport_token"
    assert "Mission Passport" in result["message"]
    steps = result["next_steps"]
    commands = " ".join(s["command"] for s in steps)
    assert "ardur verify --token" in commands
    assert "ardur issue" in commands
    assert "--attestation-token" not in commands

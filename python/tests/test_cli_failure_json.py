from __future__ import annotations

import json

from vibap import cli


def _run_cli_and_read_json(argv: list[str], capsys) -> tuple[int, dict]:
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert captured.err == ""
    return rc, json.loads(captured.out)


def test_verify_invalid_token_returns_safe_json_failure(tmp_path, capsys):
    raw_token = "not-a-jwt"

    rc, payload = _run_cli_and_read_json(
        ["verify", "--token", raw_token, "--keys-dir", str(tmp_path / "keys")],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "invalid_passport_token"
    assert payload["error"] == "invalid_passport_token"
    assert payload["message"]
    assert payload["next_steps"]
    assert raw_token not in rendered
    assert str(tmp_path) not in rendered
    assert all("<token>" in step["command"] or "<" in step["command"] for step in payload["next_steps"])


def test_attest_invalid_session_id_returns_safe_json_failure(tmp_path, capsys):
    raw_session = "missing-session"

    rc, payload = _run_cli_and_read_json(
        [
            "attest",
            "--session",
            raw_session,
            "--keys-dir",
            str(tmp_path / "keys"),
            "--state-dir",
            str(tmp_path / "state"),
            "--log-path",
            str(tmp_path / "audit.jsonl"),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "invalid_session_id"
    assert payload["error"] == "invalid_session_id"
    assert payload["next_steps"]
    assert raw_session not in rendered
    assert str(tmp_path) not in rendered


def test_attest_missing_session_returns_safe_json_failure(tmp_path, capsys):
    missing_session = "00000000-0000-0000-0000-000000000000"

    rc, payload = _run_cli_and_read_json(
        [
            "attest",
            "--session",
            missing_session,
            "--keys-dir",
            str(tmp_path / "keys"),
            "--state-dir",
            str(tmp_path / "state"),
            "--log-path",
            str(tmp_path / "audit.jsonl"),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "session_not_found"
    assert payload["error"] == "session_not_found"
    assert payload["next_steps"]
    assert missing_session not in rendered
    assert str(tmp_path) not in rendered

from __future__ import annotations

import json

import pytest

from vibap import cli


def _run_cli_and_read_json(argv: list[str], capsys) -> tuple[int, dict]:
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert captured.err == ""
    return rc, json.loads(captured.out)


def test_print_json_uses_stdout_write_instead_of_print(monkeypatch, capsys):
    def fail_if_print_is_used(*_args, **_kwargs):
        raise AssertionError("_print_json must not use print/logging sinks for CLI JSON responses")

    monkeypatch.setattr("builtins.print", fail_if_print_is_used)

    cli._print_json({"ok": False, "condition": "home_not_directory"})

    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"ok": False, "condition": "home_not_directory"}


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


@pytest.mark.parametrize(
    "argv",
    [
        ["start"],
        ["issue", "--agent-id", "agent", "--mission", "mission"],
        ["verify", "--token", "not-a-jwt"],
        [
            "attest",
            "--session",
            "not-a-uuid",
            "--state-dir",
            "<state-dir>",
            "--log-path",
            "<audit-log>",
        ],
    ],
)
def test_core_passport_commands_fail_closed_for_existing_file_keys_dir(tmp_path, capsys, argv):
    keys_file = tmp_path / "keys-file"
    keys_file.write_text("not a directory", encoding="utf-8")
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    resolved_argv = [
        str(state_dir)
        if value == "<state-dir>"
        else str(audit_log)
        if value == "<audit-log>"
        else value
        for value in argv
    ]

    rc, payload = _run_cli_and_read_json(
        [*resolved_argv, "--keys-dir", str(keys_file)],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "keys_dir_not_directory"
    assert payload["error"] == "keys_dir_not_directory"
    assert payload["error_code"] == "keys_dir_not_directory"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert str(tmp_path) not in rendered
    assert str(keys_file) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["start"],
        ["attest", "--session", "not-a-uuid"],
    ],
)
def test_core_passport_commands_fail_closed_for_existing_file_state_dir(tmp_path, capsys, argv):
    keys_dir = tmp_path / "keys"
    state_file = tmp_path / "state-file"
    state_file.write_text("not a directory", encoding="utf-8")
    audit_log = tmp_path / "audit.jsonl"

    rc, payload = _run_cli_and_read_json(
        [
            *argv,
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_file),
            "--log-path",
            str(audit_log),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "state_dir_not_directory"
    assert payload["error"] == "state_dir_not_directory"
    assert payload["error_code"] == "state_dir_not_directory"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert str(tmp_path) not in rendered
    assert str(state_file) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


@pytest.mark.parametrize(
    ("budget_args", "condition"),
    [
        (["--max-tool-calls", "-1"], "issue_budget_max_tool_calls_invalid"),
        (["--max-duration-s", "0"], "issue_budget_max_duration_invalid"),
        (["--max-duration-s", "-1"], "issue_budget_max_duration_invalid"),
        (["--ttl-s", "0"], "issue_budget_ttl_invalid"),
        (["--ttl-s", "-5"], "issue_budget_ttl_invalid"),
        (
            ["--delegation-allowed", "--max-delegation-depth", "-1"],
            "issue_budget_max_delegation_depth_invalid",
        ),
    ],
)
def test_issue_invalid_budget_returns_safe_json_failure(tmp_path, capsys, budget_args, condition):
    keys_dir = tmp_path / "keys"
    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "agent",
            "--mission",
            "mission",
            *budget_args,
            "--keys-dir",
            str(keys_dir),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == condition
    assert payload["error"] == condition
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert str(tmp_path) not in rendered
    assert not (keys_dir / "passport_private.pem").exists()
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])


@pytest.mark.parametrize(
    ("budget_args", "condition"),
    [
        (["--max-tool-calls", "abc"], "issue_budget_max_tool_calls_invalid"),
        (["--max-duration-s", "abc"], "issue_budget_max_duration_invalid"),
        (["--ttl-s", "abc"], "issue_budget_ttl_invalid"),
        (
            ["--delegation-allowed", "--max-delegation-depth", "abc"],
            "issue_budget_max_delegation_depth_invalid",
        ),
    ],
)
def test_issue_non_integer_budget_returns_safe_json_usage_failure(tmp_path, capsys, budget_args, condition):
    keys_dir = tmp_path / "keys"
    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "agent",
            "--mission",
            "mission",
            *budget_args,
            "--keys-dir",
            str(keys_dir),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["condition"] == condition
    assert payload["error"] == condition
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "invalid int value" not in rendered
    assert "abc" not in rendered
    assert "token" not in payload
    assert str(tmp_path) not in rendered
    assert not (keys_dir / "passport_private.pem").exists()
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])


def test_issue_zero_tool_call_budget_remains_valid(tmp_path, capsys):
    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "agent",
            "--mission",
            "mission",
            "--max-tool-calls",
            "0",
            "--keys-dir",
            str(tmp_path / "keys"),
        ],
        capsys,
    )

    assert rc == 0
    assert "token" in payload
    assert payload["claims"]["max_tool_calls"] == 0
    assert payload["claims"]["max_duration_s"] == 600


def test_issue_positive_ttl_override_remains_valid(tmp_path, capsys):
    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "agent",
            "--mission",
            "mission",
            "--ttl-s",
            "60",
            "--keys-dir",
            str(tmp_path / "keys"),
        ],
        capsys,
    )

    assert rc == 0
    assert "token" in payload
    assert payload["claims"]["exp"] - payload["claims"]["iat"] == 60
    assert payload["claims"]["max_tool_calls"] == 50
    assert payload["claims"]["max_duration_s"] == 600

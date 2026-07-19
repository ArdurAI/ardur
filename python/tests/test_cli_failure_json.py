from __future__ import annotations

import argparse
import base64
import json

import pytest

from vibap import cli
from vibap import personal_hub


def _run_cli_and_read_json(argv: list[str], capsys) -> tuple[int, dict]:
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert captured.err == ""
    return rc, json.loads(captured.out)


def _write_valid_mission_file(path) -> None:
    path.write_text(
        json.dumps(
            {
                "agent_id": "log-path-test-agent",
                "mission": "exercise log path validation",
                "allowed_tools": ["read_file"],
                "forbidden_tools": ["delete_file"],
                "resource_scope": [],
                "max_tool_calls": 5,
                "max_duration_s": 60,
            }
        ),
        encoding="utf-8",
    )


def test_issue_explicit_unrestricted_scope_is_signed_and_warned(tmp_path, capsys):
    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "explicit-unrestricted",
            "--mission",
            "operator explicitly permits every resource",
            "--allowed-tools",
            "Read",
            "--resource-scope",
            "**",
            "--keys-dir",
            str(tmp_path / "keys"),
        ],
        capsys,
    )

    assert rc == 0
    assert payload["claims"]["resource_scope"] == ["**"]
    assert payload["warnings"] == [
        "resource_scope explicitly permits all resources via the sole '**' pattern"
    ]


def test_issue_rejects_unrestricted_sentinel_mixed_with_bounded_scope(
    tmp_path, capsys
):
    keys_dir = tmp_path / "keys"
    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "ambiguous-scope",
            "--mission",
            "reject two sources of scope intent",
            "--allowed-tools",
            "Read",
            "--resource-scope",
            "**",
            "/workspace/*",
            "--keys-dir",
            str(keys_dir),
        ],
        capsys,
    )

    assert rc == 1
    assert payload["condition"] == "issue_resource_scope_invalid"
    assert "must be the only resource_scope pattern" in payload["detail"]
    assert not keys_dir.exists()


def _relative_tree_entries(root) -> list[str]:
    entries = []
    for path in root.rglob("*"):
        suffix = "/" if path.is_dir() else ""
        entries.append(f"{path.relative_to(root)}{suffix}")
    return sorted(entries)


def _base64url_json(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _well_formed_invalid_es256_token() -> str:
    signature = base64.urlsafe_b64encode(b"invalid-signature").rstrip(b"=").decode("ascii")
    return ".".join(
        [
            _base64url_json({"alg": "ES256", "typ": "JWT"}),
            _base64url_json(
                {
                    "iss": "vibap-governance-proxy",
                    "sub": "well-formed-invalid-token-agent",
                    "aud": "vibap-proxy",
                    "iat": 1000000000,
                    "exp": 4102444800,
                    "jti": "well-formed-invalid-token-jti",
                }
            ),
            signature,
        ]
    )


def test_print_json_uses_stdout_write_instead_of_print(monkeypatch, capsys):
    def fail_if_print_is_used(*_args, **_kwargs):
        raise AssertionError("_print_json must not use print/logging sinks for CLI JSON responses")

    monkeypatch.setattr("builtins.print", fail_if_print_is_used)

    cli._print_json({"ok": False, "condition": "home_not_directory"})

    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"ok": False, "condition": "home_not_directory"}


def test_personal_hub_print_json_response_does_not_call_print(monkeypatch, capsys):
    def fail_if_print_is_used(*_args, **_kwargs):
        raise AssertionError("_print_json_response must not use print/logging sinks for CLI JSON responses")

    monkeypatch.setattr("builtins.print", fail_if_print_is_used)

    personal_hub._print_json_response({"ok": False, "condition": "personal_home_not_directory"})

    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"ok": False, "condition": "personal_home_not_directory"}


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


@pytest.mark.parametrize("raw_token", ["not-a-jwt", "", "abc.def.ghi"])
def test_verify_malformed_token_fails_before_key_artifacts(tmp_path, capsys, raw_token):
    keys_dir = tmp_path / "keys"
    before_entries = _relative_tree_entries(tmp_path)

    rc, payload = _run_cli_and_read_json(
        ["verify", "--token", raw_token, "--keys-dir", str(keys_dir)],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "invalid_passport_token"
    assert payload["error"] == "invalid_passport_token"
    assert payload.get("error_code") is None
    assert payload["message"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    if raw_token:
        assert raw_token not in rendered
    assert str(tmp_path) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )
    assert _relative_tree_entries(tmp_path) == before_entries
    assert not keys_dir.exists()
    assert not (keys_dir / "passport_private.pem").exists()
    assert not (keys_dir / "passport_public.pem").exists()


@pytest.mark.parametrize("precreate_keys_dir", [False, True])
def test_verify_well_formed_invalid_token_fails_before_key_artifacts(
    tmp_path, capsys, precreate_keys_dir
):
    raw_token = _well_formed_invalid_es256_token()
    keys_dir = tmp_path / "keys"
    if precreate_keys_dir:
        keys_dir.mkdir()
    before_entries = _relative_tree_entries(tmp_path)

    rc, payload = _run_cli_and_read_json(
        ["verify", "--token", raw_token, "--keys-dir", str(keys_dir)],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "passport_public_key_missing"
    assert payload["error"] == "passport_public_key_missing"
    assert payload["error_code"] == "passport_public_key_missing"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert raw_token not in rendered
    assert str(tmp_path) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )
    assert _relative_tree_entries(tmp_path) == before_entries
    assert not (keys_dir / "passport_private.pem").exists()
    assert not (keys_dir / "passport_public.pem").exists()


def test_verify_corrupt_existing_public_key_returns_safe_json_without_key_artifacts(
    tmp_path, capsys
):
    issue_keys_dir = tmp_path / "issue-keys"
    corrupt_keys_dir = tmp_path / "corrupt-keys"
    issue_rc, issued = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "corrupt-public-key-agent",
            "--mission",
            "exercise corrupt public key verification",
            "--keys-dir",
            str(issue_keys_dir),
        ],
        capsys,
    )
    assert issue_rc == 0
    raw_token = issued["token"]
    corrupt_keys_dir.mkdir()
    corrupt_public_key = corrupt_keys_dir / "passport_public.pem"
    corrupt_public_key.write_text("not a pem public key\n", encoding="utf-8")
    before_entries = _relative_tree_entries(corrupt_keys_dir)

    rc, payload = _run_cli_and_read_json(
        ["verify", "--token", raw_token, "--keys-dir", str(corrupt_keys_dir)],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "passport_public_key_invalid"
    assert payload["error"] == "passport_public_key_invalid"
    assert payload["error_code"] == "passport_public_key_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert raw_token not in rendered
    assert str(tmp_path) not in rendered
    assert "not a pem public key" not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )
    assert _relative_tree_entries(corrupt_keys_dir) == before_entries
    assert corrupt_public_key.read_text(encoding="utf-8") == "not a pem public key\n"
    assert not (corrupt_keys_dir / "passport_private.pem").exists()


@pytest.mark.parametrize("path_shape", ["directory", "symlink_to_directory"])
def test_verify_existing_public_key_path_shape_returns_safe_json_without_key_artifacts(
    tmp_path, capsys, path_shape
):
    issue_keys_dir = tmp_path / "issue-keys"
    broken_keys_dir = tmp_path / "broken-keys"
    issue_rc, issued = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            f"public-key-{path_shape}-agent",
            "--mission",
            "exercise public key path-shape verification",
            "--keys-dir",
            str(issue_keys_dir),
        ],
        capsys,
    )
    assert issue_rc == 0
    raw_token = issued["token"]
    broken_keys_dir.mkdir()
    public_key_path = broken_keys_dir / "passport_public.pem"
    if path_shape == "directory":
        public_key_path.mkdir()
    elif path_shape == "symlink_to_directory":
        target_dir = tmp_path / "public-key-directory-target"
        target_dir.mkdir()
        try:
            public_key_path.symlink_to(target_dir, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
    else:  # pragma: no cover - parametrization guard
        raise AssertionError(f"unknown public key path shape: {path_shape}")
    before_entries = _relative_tree_entries(broken_keys_dir)

    rc, payload = _run_cli_and_read_json(
        ["verify", "--token", raw_token, "--keys-dir", str(broken_keys_dir)],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "passport_public_key_invalid"
    assert payload["error"] == "passport_public_key_invalid"
    assert payload["error_code"] == "passport_public_key_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert raw_token not in rendered
    assert str(tmp_path) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"]
        for step in payload["next_steps"]
    )
    assert _relative_tree_entries(broken_keys_dir) == before_entries
    assert public_key_path.exists()
    assert not (broken_keys_dir / "passport_private.pem").exists()


def test_verify_unreadable_existing_public_key_returns_safe_json_without_key_artifacts(
    tmp_path, capsys
):
    issue_keys_dir = tmp_path / "issue-keys"
    broken_keys_dir = tmp_path / "broken-keys"
    issue_rc, issued = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "unreadable-public-key-agent",
            "--mission",
            "exercise unreadable public key verification",
            "--keys-dir",
            str(issue_keys_dir),
        ],
        capsys,
    )
    assert issue_rc == 0
    raw_token = issued["token"]
    broken_keys_dir.mkdir()
    public_key_path = broken_keys_dir / "passport_public.pem"
    public_key_path.write_text(
        "unreadable public key content must not leak\n", encoding="utf-8"
    )
    public_key_path.chmod(0)
    try:
        try:
            public_key_path.read_bytes()
        except OSError:
            pass
        else:
            public_key_path.chmod(0o600)
            pytest.skip("unreadable public-key file is not reproducible on this filesystem")
        before_entries = _relative_tree_entries(broken_keys_dir)

        rc, payload = _run_cli_and_read_json(
            ["verify", "--token", raw_token, "--keys-dir", str(broken_keys_dir)],
            capsys,
        )
    finally:
        public_key_path.chmod(0o600)

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "passport_public_key_invalid"
    assert payload["error"] == "passport_public_key_invalid"
    assert payload["error_code"] == "passport_public_key_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert raw_token not in rendered
    assert str(tmp_path) not in rendered
    assert "unreadable public key content" not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"]
        for step in payload["next_steps"]
    )
    assert _relative_tree_entries(broken_keys_dir) == before_entries
    assert (
        public_key_path.read_text(encoding="utf-8")
        == "unreadable public key content must not leak\n"
    )
    assert not (broken_keys_dir / "passport_private.pem").exists()


def test_verify_token_issued_by_existing_keys_dir_remains_valid(tmp_path, capsys):
    keys_dir = tmp_path / "keys"
    issue_rc, issued = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "verify-agent",
            "--mission",
            "exercise verify with existing keys",
            "--keys-dir",
            str(keys_dir),
        ],
        capsys,
    )
    assert issue_rc == 0
    assert "token" in issued

    verify_rc, verified = _run_cli_and_read_json(
        ["verify", "--token", issued["token"], "--keys-dir", str(keys_dir)],
        capsys,
    )

    assert verify_rc == 0
    assert verified["valid"] is True
    assert verified["claims"]["sub"] == "verify-agent"


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
    ("session_id", "condition", "precreate_session_dir"),
    [
        ("not-a-uuid", "invalid_session_id", False),
        ("", "invalid_session_id", False),
        ("00000000-0000-0000-0000-000000000000", "session_not_found", True),
    ],
)
def test_attest_invalid_or_missing_session_fails_before_local_artifacts(
    tmp_path, capsys, session_id, condition, precreate_session_dir
):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    if precreate_session_dir:
        (state_dir / "sessions").mkdir(parents=True)
    before_entries = _relative_tree_entries(tmp_path)

    rc, payload = _run_cli_and_read_json(
        [
            "attest",
            "--session",
            session_id,
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_log),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == condition
    assert payload["error"] == condition
    assert payload["next_steps"]
    assert "token" not in payload
    assert "Traceback" not in rendered
    if session_id:
        assert session_id not in rendered
    assert str(tmp_path) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )
    assert _relative_tree_entries(tmp_path) == before_entries
    assert not keys_dir.exists()
    assert not audit_log.exists()
    assert not (state_dir / "passport_state.lock").exists()
    assert not (state_dir / "replay_cache.json").exists()
    assert not (state_dir / "revoked.json").exists()
    assert not (state_dir / "lineage_hashes.json").exists()
    assert not (state_dir / "sessions" / f"{session_id}.lock").exists()


@pytest.mark.parametrize(
    ("case_name", "session_content"),
    [
        ("malformed_json", "{not json"),
        ("empty_json", ""),
        ("array_json", json.dumps([])),
        ("minimal_object", json.dumps({})),
        ("schema_invalid_object", json.dumps({"passport_token": "raw-session-content-do-not-leak"})),
        (
            "claims_missing_required_fields",
            json.dumps(
                {
                    "passport_token": "raw-session-content-do-not-leak",
                    "passport_claims": {},
                }
            ),
        ),
    ],
)
def test_attest_corrupt_session_file_fails_before_local_artifacts(
    tmp_path, capsys, case_name, session_content
):
    session_id = "11111111-1111-1111-1111-111111111111"
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    sessions_dir = state_dir / "sessions"
    audit_log = tmp_path / "audit.jsonl"
    sessions_dir.mkdir(parents=True)
    session_file = sessions_dir / f"{session_id}.json"
    session_file.write_text(session_content, encoding="utf-8")
    before_entries = _relative_tree_entries(tmp_path)

    rc, payload = _run_cli_and_read_json(
        [
            "attest",
            "--session",
            session_id,
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_log),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1, case_name
    assert payload["ok"] is False
    assert payload["valid"] is False
    assert payload["condition"] == "session_invalid"
    assert payload["error"] == "session_invalid"
    assert payload["next_steps"]
    assert "token" not in payload
    assert "Traceback" not in rendered
    assert "raw-session-content-do-not-leak" not in rendered
    assert "not json" not in rendered
    assert session_id not in rendered
    assert str(tmp_path) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )
    assert _relative_tree_entries(tmp_path) == before_entries
    assert not keys_dir.exists()
    assert not audit_log.exists()
    assert not (state_dir / "passport_state.lock").exists()
    assert not (state_dir / "replay_cache.json").exists()
    assert not (state_dir / "revoked.json").exists()
    assert not (state_dir / "lineage_hashes.json").exists()
    assert not (state_dir / "lineage_budgets").exists()
    assert not (sessions_dir / f"{session_id}.lock").exists()


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
        ["claude-code-report", "--json"],
        ["claude-code-report"],
    ],
)
def test_claude_code_report_fail_closed_for_existing_file_keys_dir(tmp_path, capsys, argv):
    keys_file = tmp_path / "keys-file"
    keys_file.write_text("not a directory", encoding="utf-8")

    rc, payload = _run_cli_and_read_json(
        [*argv, "--keys-dir", str(keys_file)],
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
    assert str(tmp_path) not in rendered
    assert str(keys_file) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


def test_claude_code_report_fail_closed_for_existing_file_home(tmp_path, capsys):
    home_file = tmp_path / "home-file"
    home_file.write_text("not a directory", encoding="utf-8")

    rc, payload = _run_cli_and_read_json(
        ["claude-code-report", "--json", "--home", str(home_file)],
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
    assert str(tmp_path) not in rendered
    assert str(home_file) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


def test_gemini_cli_report_fail_closed_for_existing_file_keys_dir(tmp_path, capsys):
    keys_file = tmp_path / "keys-file"
    keys_file.write_text("not a directory", encoding="utf-8")

    rc, payload = _run_cli_and_read_json(
        ["gemini-cli-report", "--json", "--keys-dir", str(keys_file)],
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
    assert str(tmp_path) not in rendered
    assert str(keys_file) not in rendered
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


def test_codex_app_server_report_fail_closed_for_existing_file_keys_dir(tmp_path, capsys):
    keys_file = tmp_path / "keys-file"
    keys_file.write_text("not a directory", encoding="utf-8")

    rc, payload = _run_cli_and_read_json(
        ["codex-app-server-report", "--json", "--keys-dir", str(keys_file)],
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


def test_start_existing_file_state_dir_fails_before_artifacts(
    tmp_path, capsys, monkeypatch
):
    keys_dir = tmp_path / "keys"
    state_file = tmp_path / "state-file"
    state_file.write_text("not a directory", encoding="utf-8")
    audit_log = tmp_path / "audit.jsonl"

    def fail_if_proxy_starts(*_args, **_kwargs):  # pragma: no cover - assertion path
        raise AssertionError("invalid start state-dir must fail before proxy startup")

    monkeypatch.setattr(cli, "serve_proxy", fail_if_proxy_starts)

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_file),
            "--log-path",
            str(audit_log),
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--no-tls",
            "--no-require-auth",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "state_dir_not_directory"
    assert payload["error"] == "state_dir_not_directory"
    assert payload["error_code"] == "state_dir_not_directory"
    assert "token" not in payload
    assert "session_id" not in payload
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    assert str(state_file) not in rendered
    assert not keys_dir.exists()
    assert not (keys_dir / "passport_private.pem").exists()
    assert not (keys_dir / "passport_public.pem").exists()
    assert state_file.read_text(encoding="utf-8") == "not a directory"
    assert not audit_log.exists()


@pytest.mark.parametrize(
    ("write_target", "parent_kind", "condition"),
    [
        ("state_dir_parent", "regular_file", "state_dir_parent_not_directory"),
        ("log_path_parent", "regular_file", "log_path_parent_not_directory"),
        ("state_dir_parent", "dangling_symlink", "state_dir_parent_not_directory"),
        ("log_path_parent", "dangling_symlink", "log_path_parent_not_directory"),
    ],
)
def test_start_existing_non_directory_parent_for_state_or_log_path_fails_before_artifacts(
    tmp_path, capsys, write_target, parent_kind, condition
):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    parent_path = tmp_path / f"parent-{parent_kind}"
    if parent_kind == "regular_file":
        parent_path.write_text("not a directory", encoding="utf-8")
    elif parent_kind == "dangling_symlink":
        try:
            parent_path.symlink_to(tmp_path / "missing-target")
        except (NotImplementedError, OSError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
    else:
        raise AssertionError(f"unknown parent kind: {parent_kind}")
    if write_target == "state_dir_parent":
        state_arg = parent_path / "state"
        log_arg = audit_log
    else:
        state_arg = state_dir
        log_arg = parent_path / "audit.jsonl"

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_arg),
            "--log-path",
            str(log_arg),
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--no-tls",
            "--no-require-auth",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == condition
    assert payload["error"] == condition
    assert payload["error_code"] == condition
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert "session_id" not in payload
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    assert str(parent_path) not in rendered
    if parent_kind == "regular_file":
        assert parent_path.read_text(encoding="utf-8") == "not a directory"
    else:
        assert parent_path.is_symlink()
        assert not parent_path.exists()
    assert not keys_dir.exists()
    assert not (keys_dir / "passport_private.pem").exists()
    assert not (keys_dir / "passport_public.pem").exists()
    assert not state_arg.exists()
    assert not log_arg.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


@pytest.mark.parametrize(
    ("write_target", "parent_kind", "condition"),
    [
        ("state_dir_parent", "regular_file", "state_dir_parent_not_directory"),
        ("log_path_parent", "regular_file", "log_path_parent_not_directory"),
        ("state_dir_parent", "dangling_symlink", "state_dir_parent_not_directory"),
        ("log_path_parent", "dangling_symlink", "log_path_parent_not_directory"),
    ],
)
def test_attest_existing_non_directory_parent_for_state_or_log_path_fails_before_artifacts(
    tmp_path, capsys, write_target, parent_kind, condition
):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    parent_path = tmp_path / f"attest-parent-{parent_kind}"
    if parent_kind == "regular_file":
        parent_path.write_text("not a directory", encoding="utf-8")
    elif parent_kind == "dangling_symlink":
        try:
            parent_path.symlink_to(tmp_path / "missing-target")
        except (NotImplementedError, OSError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
    else:
        raise AssertionError(f"unknown parent kind: {parent_kind}")
    if write_target == "state_dir_parent":
        state_arg = parent_path / "state"
        log_arg = audit_log
    else:
        state_arg = state_dir
        log_arg = parent_path / "audit.jsonl"

    rc, payload = _run_cli_and_read_json(
        [
            "attest",
            "--session",
            "00000000-0000-0000-0000-000000000000",
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_arg),
            "--log-path",
            str(log_arg),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == condition
    assert payload["error"] == condition
    assert payload["error_code"] == condition
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert "session_id" not in payload
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    assert str(parent_path) not in rendered
    if parent_kind == "regular_file":
        assert parent_path.read_text(encoding="utf-8") == "not a directory"
    else:
        assert parent_path.is_symlink()
        assert not parent_path.exists()
    assert not keys_dir.exists()
    assert not (keys_dir / "passport_private.pem").exists()
    assert not (keys_dir / "passport_public.pem").exists()
    assert not state_arg.exists()
    assert not log_arg.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


def test_start_with_mission_fails_closed_for_existing_directory_log_path(tmp_path, capsys):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    mission_file = tmp_path / "mission.json"
    audit_dir = tmp_path / "audit-dir"
    audit_dir.mkdir()
    _write_valid_mission_file(mission_file)

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--mission",
            str(mission_file),
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_dir),
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--no-tls",
            "--no-require-auth",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "log_path_not_file"
    assert payload["error"] == "log_path_not_file"
    assert payload["error_code"] == "log_path_not_file"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert str(tmp_path) not in rendered
    assert str(audit_dir) not in rendered
    assert not keys_dir.exists()
    assert not (keys_dir / "passport_private.pem").exists()
    assert not (keys_dir / "passport_public.pem").exists()
    assert not state_dir.exists()
    assert list(audit_dir.iterdir()) == []
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


def _invalid_start_mission_input(tmp_path, case: str):
    mission_file = tmp_path / f"{case}-mission.json"
    if case == "missing":
        return mission_file, ""
    if case == "malformed_json":
        leaked_text = "raw-secret-do-not-leak"
        mission_file.write_text("{raw-secret-do-not-leak", encoding="utf-8")
        return mission_file, leaked_text
    if case == "invalid_utf8":
        mission_file.write_bytes(b"\xff\xfe\x00raw-secret-do-not-leak")
        return mission_file, "raw-secret-do-not-leak"
    if case == "directory":
        mission_file.mkdir()
        return mission_file, ""
    if case == "wrong_shape":
        mission_file.write_text(json.dumps([]), encoding="utf-8")
        return mission_file, ""
    raise AssertionError(f"unknown invalid mission input case: {case}")


@pytest.mark.parametrize(
    ("case", "condition"),
    [
        ("missing", "start_mission_file_missing"),
        ("malformed_json", "start_mission_file_malformed_json"),
        ("invalid_utf8", "start_mission_file_malformed_json"),
        ("directory", "start_mission_file_invalid"),
        ("wrong_shape", "start_mission_file_invalid"),
    ],
)
def test_start_invalid_mission_file_returns_safe_json_before_artifacts(
    tmp_path, capsys, case, condition
):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    mission_input, leaked_text = _invalid_start_mission_input(tmp_path, case)

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--mission",
            str(mission_input),
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_log),
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--no-tls",
            "--no-require-auth",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == condition
    assert payload["error"] == condition
    assert payload["error_code"] == condition
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert "session_id" not in payload
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    assert str(mission_input) not in rendered
    if leaked_text:
        assert leaked_text not in rendered
    assert not keys_dir.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


@pytest.mark.parametrize(
    "write_target_args",
    [
        ["--state-dir", "<state-file>", "--log-path", "<audit-log>"],
        ["--state-dir", "<state-dir>", "--log-path", "<audit-dir>"],
    ],
)
def test_start_invalid_mission_precedes_invalid_write_targets(
    tmp_path, capsys, write_target_args
):
    keys_dir = tmp_path / "keys"
    state_file = tmp_path / "state-file"
    state_file.write_text("not a directory", encoding="utf-8")
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    audit_dir = tmp_path / "audit-dir"
    audit_dir.mkdir()
    missing_mission_file = tmp_path / "missing-mission.json"
    replacements = {
        "<state-file>": str(state_file),
        "<state-dir>": str(state_dir),
        "<audit-log>": str(audit_log),
        "<audit-dir>": str(audit_dir),
    }
    resolved_write_target_args = [
        replacements[value] if value in replacements else value
        for value in write_target_args
    ]

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--mission",
            str(missing_mission_file),
            "--keys-dir",
            str(keys_dir),
            *resolved_write_target_args,
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--no-tls",
            "--no-require-auth",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "start_mission_file_missing"
    assert "state_dir_not_directory" not in rendered
    assert "log_path_not_file" not in rendered
    assert str(tmp_path) not in rendered
    assert not keys_dir.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()
    assert list(audit_dir.iterdir()) == []


def test_attest_fails_closed_for_existing_directory_log_path(tmp_path, capsys):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_dir = tmp_path / "audit-dir"
    audit_dir.mkdir()

    rc, payload = _run_cli_and_read_json(
        [
            "attest",
            "--session",
            "not-a-uuid",
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_dir),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "log_path_not_file"
    assert payload["error"] == "log_path_not_file"
    assert payload["error_code"] == "log_path_not_file"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert str(tmp_path) not in rendered
    assert str(audit_dir) not in rendered
    assert not state_dir.exists()
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


@pytest.mark.parametrize("port", ["-1", "65536"])
def test_start_invalid_port_returns_safe_json_before_side_effects(tmp_path, capsys, port):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    missing_mission_file = tmp_path / "missing-mission.json"

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--mission",
            str(missing_mission_file),
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_log),
            "--host",
            "127.0.0.1",
            "--port",
            port,
            "--no-tls",
            "--no-require-auth",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "start_port_invalid"
    assert payload["error"] == "start_port_invalid"
    assert payload["error_code"] == "start_port_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert "session_id" not in payload
    assert "Traceback" not in rendered
    assert port not in rendered
    assert str(tmp_path) not in rendered
    assert str(missing_mission_file) not in rendered
    assert not keys_dir.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


@pytest.mark.parametrize("host", ["http://127.0.0.1", "ftp://127.0.0.1", "   "])
def test_start_invalid_host_returns_safe_json_before_side_effects(
    tmp_path, capsys, monkeypatch, host
):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    missing_mission_file = tmp_path / "missing-mission.json"

    def fail_if_key_material_is_generated(*_args, **_kwargs):
        raise AssertionError("invalid start host must fail before key generation")

    monkeypatch.setattr(cli, "generate_keypair", fail_if_key_material_is_generated)

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--mission",
            str(missing_mission_file),
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_log),
            "--host",
            host,
            "--port",
            "0",
            "--no-tls",
            "--no-require-auth",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "start_host_invalid"
    assert payload["error"] == "start_host_invalid"
    assert payload["error_code"] == "start_host_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert "session_id" not in payload
    assert "Traceback" not in rendered
    assert "socket" not in rendered.lower()
    assert "gaierror" not in rendered.lower()
    if host.strip():
        assert host.strip() not in rendered
    assert str(tmp_path) not in rendered
    assert str(missing_mission_file) not in rendered
    assert not keys_dir.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()
    assert all(
        "<" in step["command"] and ">" in step["command"] for step in payload["next_steps"]
    )


def test_start_invalid_port_still_takes_precedence_over_invalid_host(tmp_path, capsys):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    missing_mission_file = tmp_path / "missing-mission.json"

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--mission",
            str(missing_mission_file),
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_log),
            "--host",
            "http://127.0.0.1",
            "--port",
            "-1",
            "--no-tls",
            "--no-require-auth",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["condition"] == "start_port_invalid"
    assert payload["error"] == "start_port_invalid"
    assert "start_host_invalid" not in rendered
    assert "http://127.0.0.1" not in rendered
    assert not keys_dir.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()


@pytest.mark.parametrize("case", ["missing_cert_key", "cert_directory", "key_directory"])
def test_start_invalid_tls_material_returns_safe_json_before_side_effects(
    tmp_path, capsys, monkeypatch, case
):
    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    audit_log = tmp_path / "audit.jsonl"
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"

    if case == "cert_directory":
        cert_path.mkdir()
        key_path.write_text("not a private key", encoding="utf-8")
    elif case == "key_directory":
        cert_path.write_text("not a certificate", encoding="utf-8")
        key_path.mkdir()

    def fail_if_key_material_is_generated(*_args, **_kwargs):
        raise AssertionError("invalid explicit TLS material must fail before key generation")

    monkeypatch.setattr(cli, "generate_keypair", fail_if_key_material_is_generated)

    rc, payload = _run_cli_and_read_json(
        [
            "start",
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_log),
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--require-auth",
            "--tls-cert",
            str(cert_path),
            "--tls-key",
            str(key_path),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "start_tls_material_invalid"
    assert payload["error"] == "start_tls_material_invalid"
    assert payload["error_code"] == "start_tls_material_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert "session_id" not in payload
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    assert str(cert_path) not in rendered
    assert str(key_path) not in rendered
    assert not keys_dir.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])


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


@pytest.mark.parametrize(
    ("agent_id", "mission", "condition"),
    [
        ("", "test mission", "issue_agent_id_invalid"),
        ("   ", "test mission", "issue_agent_id_invalid"),
        ("\t\n", "test mission", "issue_agent_id_invalid"),
        ("test-agent", "", "issue_mission_invalid"),
        ("test-agent", "   ", "issue_mission_invalid"),
        ("test-agent", "\t\n", "issue_mission_invalid"),
        ("   ", "   ", "issue_agent_id_invalid"),
    ],
)
def test_issue_empty_or_whitespace_identity_returns_safe_json_failure(
    tmp_path, capsys, agent_id, mission, condition
):
    keys_dir = tmp_path / "keys"
    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            agent_id,
            "--mission",
            mission,
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
    assert payload["error_code"] == condition
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "token" not in payload
    assert "claims" not in payload
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No signing keys may be created when validation rejects the input.
    assert not keys_dir.exists() or not any(keys_dir.iterdir())
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])


def test_issue_valid_identity_still_succeeds(tmp_path, capsys):
    keys_dir = tmp_path / "keys"
    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "test-agent",
            "--mission",
            "test mission",
            "--keys-dir",
            str(keys_dir),
        ],
        capsys,
    )

    assert rc == 0
    assert "token" in payload
    assert payload["claims"]["sub"] == "test-agent"
    assert payload["claims"]["mission"] == "test mission"
    assert (keys_dir / "passport_private.pem").exists()
    assert (keys_dir / "passport_public.pem").exists()


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


@pytest.mark.parametrize(
    ("scope",),
    [
        ("",),
        ("   ",),
        ("\t\n",),
    ],
)
def test_protect_claude_code_empty_scope_returns_invalid(tmp_path, capsys, scope):
    """Empty/whitespace-only --scope must fail closed with structured JSON and
    must NOT create signing keys or active_mission.jwt.

    Regression: previously ``--scope`` used ``type=Path`` which normalized
    ``Path("")`` to ``PosixPath(".")`` (the CWD), silently creating real
    signing keys for the wrong directory.
    """
    home = tmp_path / "home"
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            scope,
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_scope_invalid"
    assert payload["error"] == "protect_scope_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No home directory, keys, or active_mission.jwt may be created when the
    # scope is rejected.
    assert not home.exists()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


def test_protect_claude_code_explicit_dot_scope_still_succeeds(tmp_path, capsys):
    """Explicit ``--scope .`` (current working directory) remains valid and must
    not be rejected by the empty/whitespace guard.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            ".",
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
        ],
        capsys,
    )

    assert rc == 0
    assert payload["ok"] is True


def test_protect_claude_code_scope_regular_file_returns_invalid(tmp_path, capsys):
    """``--scope <existing-regular-file>`` must fail closed with structured JSON
    and must NOT create signing keys or active_mission.jwt.

    Regression: previously ``--scope`` used ``type=Path`` which silently
    accepted an existing regular file as the project folder, creating real
    signing keys for the wrong path.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    # Create a real regular file to use as the invalid scope.
    scope_file = tmp_path / "not-a-directory.txt"
    scope_file.write_text("this is a file, not a project folder")
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(scope_file),
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_scope_invalid"
    assert payload["error"] == "protect_scope_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No home directory, keys, or active_mission.jwt may be created when the
    # scope is rejected.
    assert not home.exists()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


@pytest.mark.parametrize(
    ("agent_id",),
    [
        ("",),
        ("   ",),
        ("\t\n",),
    ],
)
def test_protect_claude_code_empty_agent_id_returns_invalid(tmp_path, capsys, agent_id):
    """Empty/whitespace-only --agent-id must fail closed with structured JSON
    and must NOT create signing keys, active_mission.jwt, or home artifacts.

    Regression: previously ``--agent-id ""`` or ``"   "`` overrode the argparse
    default ``local-user:claude-code`` and flowed into the Mission Passport
    ``agent_id`` (JWT ``sub`` claim) while generating real signing keys.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--agent-id",
            agent_id,
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_agent_id_invalid"
    assert payload["error"] == "protect_agent_id_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No home directory, keys, or active_mission.jwt may be created when the
    # agent-id is rejected.
    assert not home.exists()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


@pytest.mark.parametrize(
    ("mission",),
    [
        ("   ",),
        ("\t\n",),
    ],
)
def test_protect_claude_code_whitespace_mission_returns_invalid(tmp_path, capsys, mission):
    """Explicitly-provided whitespace-only --mission must fail closed with
    structured JSON and must NOT create signing keys, active_mission.jwt, or
    home artifacts.

    Note: an empty-string ``--mission ""`` is now also rejected (the guard was
    tightened to catch both empty and whitespace-only strings).
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mission",
            mission,
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_mission_invalid"
    assert payload["error"] == "protect_mission_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No home directory, keys, or active_mission.jwt may be created when the
    # mission is rejected.
    assert not home.exists()
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


@pytest.mark.parametrize(
    ("home",),
    [
        ("",),
        ("   ",),
        ("\t\n",),
    ],
)
def test_protect_claude_code_empty_home_returns_invalid(tmp_path, capsys, home):
    """Empty/whitespace-only --home must fail closed with structured JSON and
    must NOT create signing keys, active_mission.jwt, or home artifacts.

    Regression: previously ``--home`` used ``type=Path`` which normalized
    ``Path("")`` to ``PosixPath(".")`` (the CWD), silently creating real
    signing keys and ``active_mission.jwt`` in the current working directory
    instead of failing closed. Whitespace-only values (``"   "``) created a
    literal whitespace directory and wrote the JWT there.
    """
    project = tmp_path / "project"
    project.mkdir()
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            home,
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_home_invalid"
    assert payload["error"] == "protect_home_invalid"
    assert payload["error_code"] == "protect_home_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No home directory, keys, or active_mission.jwt may be created when the
    # home is rejected. Artifacts must not appear in CWD either.
    assert not (tmp_path / "home").exists()
    assert not (tmp_path / "active_mission.jwt").exists()
    assert not (tmp_path / ".vibap").exists()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


def test_protect_claude_code_explicit_dot_home_still_succeeds(
    tmp_path, capsys, monkeypatch
):
    """Explicit ``--home .`` (current working directory) remains valid and must
    not be rejected by the empty/whitespace guard. Only empty/whitespace-only
    strings are rejected; an explicit ``.`` is a deliberate CWD choice.
    """
    project = tmp_path / "project"
    project.mkdir()
    runtime_dir = tmp_path / "runtime-cwd"
    runtime_dir.mkdir()
    monkeypatch.chdir(runtime_dir)
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            ".",
        ],
        capsys,
    )

    assert rc == 0
    assert payload["ok"] is True
    assert (runtime_dir / "active_mission.jwt").is_file()
    assert (runtime_dir / "claude-code-pre_tool_use").is_file()
    assert (runtime_dir / "keys" / "passport_private.pem").is_file()
    assert (runtime_dir / "keys" / "passport_public.pem").is_file()


def test_protect_claude_code_home_regular_file_returns_invalid(tmp_path, capsys):
    """``--home <existing-regular-file>`` must fail closed with structured JSON
    and must NOT create signing keys or active_mission.jwt.

    Regression: previously ``--home`` pointing to an existing regular file
    tracebacked with ``FileExistsError`` at ``home.mkdir()`` instead of
    returning structured JSON with ``next_steps``.
    """
    project = tmp_path / "project"
    project.mkdir()
    # Create a real regular file to use as the invalid home.
    home_file = tmp_path / "not-a-directory.txt"
    home_file.write_text("this is a file, not a home directory")
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home_file),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_home_invalid"
    assert payload["error"] == "protect_home_invalid"
    assert payload["error_code"] == "protect_home_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No home directory, keys, or active_mission.jwt may be created when the
    # home is rejected.
    assert not home_file.is_dir()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


def test_protect_claude_code_keys_dir_regular_file_returns_invalid(tmp_path, capsys):
    """``--keys-dir <existing-regular-file>`` must fail closed with structured
    JSON and must NOT create signing keys or active_mission.jwt.

    Regression: previously ``--keys-dir`` pointing to an existing regular file
    tracebacked with ``KeyDirectoryError`` at ``generate_keypair()`` instead of
    returning structured JSON with ``next_steps``.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    # Create a real regular file to use as the invalid keys-dir.
    keys_file = tmp_path / "not-a-directory.txt"
    keys_file.write_text("this is a file, not a keys directory")
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
            "--keys-dir",
            str(keys_file),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_keys_dir_invalid"
    assert payload["error"] == "protect_keys_dir_invalid"
    assert payload["error_code"] == "protect_keys_dir_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No keys directory, signing keys, or active_mission.jwt may be created
    # when the keys-dir is rejected.
    assert not keys_file.is_dir()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


def test_protect_claude_code_negative_max_tool_calls_returns_invalid(tmp_path, capsys):
    """``--max-tool-calls -1`` must fail closed with structured JSON and must
    NOT create signing keys or active_mission.jwt.

    Regression: previously a negative ``--max-tool-calls`` silently produced a
    Mission Passport with a negative ``max_tool_calls`` claim.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
            "--max-tool-calls",
            "-1",
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_budget_max_tool_calls_invalid"
    assert payload["error"] == "protect_budget_max_tool_calls_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No keys directory, signing keys, or active_mission.jwt may be created
    # when the budget is rejected.
    assert not (home / "keys").exists()
    assert not (home / "active_mission.jwt").exists()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


@pytest.mark.parametrize("bad_value", ["-1", "0"])
def test_protect_claude_code_non_positive_max_duration_s_returns_invalid(
    tmp_path, capsys, bad_value
):
    """``--max-duration-s`` <= 0 must fail closed with structured JSON and
    must NOT create signing keys or active_mission.jwt.

    Regression: previously a non-positive ``--max-duration-s`` silently
    produced a Mission Passport with a non-positive ``max_duration_s`` claim.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
            "--max-duration-s",
            bad_value,
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_budget_max_duration_invalid"
    assert payload["error"] == "protect_budget_max_duration_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No keys directory, signing keys, or active_mission.jwt may be created
    # when the budget is rejected.
    assert not (home / "keys").exists()
    assert not (home / "active_mission.jwt").exists()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


@pytest.mark.parametrize("bad_value", ["-1", "0"])
def test_protect_claude_code_non_positive_ttl_s_returns_invalid(
    tmp_path, capsys, bad_value
):
    """``--ttl-s`` <= 0 must fail closed with structured JSON and must
    NOT create signing keys or active_mission.jwt.

    Regression: previously a non-positive ``--ttl-s`` tracebacked with
    ``ValueError: ttl_s must be positive`` from ``issue_passport()`` after
    keys were already generated.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
            "--ttl-s",
            bad_value,
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_budget_ttl_invalid"
    assert payload["error"] == "protect_budget_ttl_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No keys directory, signing keys, or active_mission.jwt may be created
    # when the TTL is rejected.
    assert not (home / "keys").exists()
    assert not (home / "active_mission.jwt").exists()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


def test_protect_claude_code_omitted_home_still_succeeds(tmp_path, capsys, monkeypatch):
    """Omitting ``--home`` entirely must keep working and use DEFAULT_HOME.
    The empty/whitespace guard only fires on an explicitly-provided invalid
    string, not on the ``args.home=None`` default.
    """
    project = tmp_path / "project"
    project.mkdir()
    # Redirect DEFAULT_HOME to a tmp path so the test does not write into the
    # real user home. ``DEFAULT_HOME`` is imported from ``vibap.config``.
    fake_home = tmp_path / "default-home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
        ],
        capsys,
    )

    assert rc == 0
    assert payload["ok"] is True


@pytest.mark.parametrize(
    ("keys_dir",),
    [
        ("",),
        ("   ",),
        ("\t\n",),
    ],
)
def test_protect_claude_code_empty_keys_dir_returns_invalid(tmp_path, capsys, keys_dir):
    """Empty/whitespace-only --keys-dir must fail closed with structured JSON and
    must NOT create signing keys, active_mission.jwt, or keys-dir artifacts.

    Regression: previously ``--keys-dir`` used ``type=Path`` which normalized
    ``Path("")`` to ``PosixPath(".")`` (the CWD), silently creating real
    signing keys in the current working directory instead of failing closed.
    Whitespace-only values (``"   "``) created a literal whitespace directory
    and wrote keys there.
    """
    project = tmp_path / "project"
    project.mkdir()
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--keys-dir",
            keys_dir,
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_keys_dir_invalid"
    assert payload["error"] == "protect_keys_dir_invalid"
    assert payload["error_code"] == "protect_keys_dir_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No keys directory, keys, or active_mission.jwt may be created when the
    # keys-dir is rejected. Artifacts must not appear in CWD either.
    assert not (tmp_path / "passport_private.pem").exists()
    assert not (tmp_path / "passport_public.pem").exists()
    assert not (tmp_path / "active_mission.jwt").exists()
    assert not (tmp_path / ".vibap").exists()
    # next_steps must be placeholder-only: no absolute local paths, tokens, or
    # tmp_path leakage in any command/detail field.
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


def test_protect_claude_code_explicit_dot_keys_dir_still_succeeds(tmp_path, capsys):
    """Explicit ``--keys-dir .`` (current working directory) remains valid and
    must not be rejected by the empty/whitespace guard. Only empty/whitespace-
    only strings are rejected; an explicit ``.`` is a deliberate CWD choice.
    """
    project = tmp_path / "project"
    project.mkdir()
    keys_dir = tmp_path / "keys-cwd"
    keys_dir.mkdir()
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--keys-dir",
            str(keys_dir),
        ],
        capsys,
    )

    assert rc == 0
    assert payload["ok"] is True


def test_protect_claude_code_omitted_keys_dir_still_succeeds(tmp_path, capsys, monkeypatch):
    """Omitting ``--keys-dir`` entirely must keep working and use the default
    keys directory under the Ardur home. The empty/whitespace guard only fires
    on an explicitly-provided invalid string, not on the ``args.keys_dir=None``
    default.
    """
    project = tmp_path / "project"
    project.mkdir()
    # Redirect HOME so the test does not write into the real user home.
    fake_home = tmp_path / "default-home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(fake_home),
        ],
        capsys,
    )

    assert rc == 0
    assert payload["ok"] is True


def test_protect_claude_code_empty_string_mission_returns_invalid(tmp_path, capsys):
    """An empty-string ``--mission ""`` must now be rejected with structured
    JSON and must NOT create signing keys, active_mission.jwt, or home
    artifacts. The guard was tightened to catch both empty and whitespace-only
    strings."""
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mission",
            "",
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
        ],
        capsys,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "protect_mission_invalid"
    assert payload["error"] == "protect_mission_invalid"
    assert payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert "Traceback" not in rendered
    assert str(tmp_path) not in rendered
    # No home directory, keys, or active_mission.jwt may be created when the
    # mission is rejected.
    assert not home.exists()
    for step in payload["next_steps"]:
        assert str(tmp_path) not in step.get("command", "")
        assert str(tmp_path) not in step.get("detail", "")


def test_protect_claude_code_omitted_agent_id_and_mission_still_succeeds(tmp_path, capsys):
    """Omitting both --agent-id and --mission must continue to work: argparse
    supplies the default agent-id and the mode default mission is used.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
        ],
        capsys,
    )

    assert rc == 0
    assert payload["ok"] is True
    assert payload["claims"]["sub"] == "local-user:claude-code"
    assert payload["claims"]["mission"]


def test_protect_claude_code_valid_agent_id_and_mission_still_succeed(tmp_path, capsys):
    """A non-empty valid --agent-id and --mission must continue to produce a
    passport with those exact claim values.
    """
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    rc, payload = _run_cli_and_read_json(
        [
            "protect",
            "claude-code",
            "--scope",
            str(project),
            "--agent-id",
            "ci-runner:pull-1234",
            "--mission",
            "run the focused test suite",
            "--mode",
            "read-only",
            "--json",
            "--home",
            str(home),
        ],
        capsys,
    )

    assert rc == 0
    assert payload["ok"] is True
    assert payload["claims"]["sub"] == "ci-runner:pull-1234"
    assert payload["claims"]["mission"] == "run the focused test suite"


# ---------------------------------------------------------------------------
# Path-arg validation: empty/whitespace --keys-dir, --state-dir, --log-path,
# --tls-cert, --tls-key, and --mission (start only) are rejected before any
# key generation, state creation, or directory resolution.
# ---------------------------------------------------------------------------


def test_start_keys_dir_empty_rejected(tmp_path, capsys):
    """Empty --keys-dir on start must be rejected before key/state creation."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    before = _relative_tree_entries(cwd)

    rc, payload = _run_cli_and_read_json(
        ["start", "--keys-dir", "", "--port", "0"],
        capsys,
    )

    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "path_arg_invalid"
    assert payload["error"] == "path_arg_invalid"
    assert payload["error_code"] == "path_arg_invalid"
    assert "keys-dir" in payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])
    # No artifacts created in cwd.
    assert _relative_tree_entries(cwd) == before
    assert not (cwd / "passport_private.pem").exists()
    assert not (cwd / "passport_public.pem").exists()
    assert not (cwd / ".vibap").exists()


def test_issue_keys_dir_empty_rejected(tmp_path, capsys):
    """Empty --keys-dir on issue must be rejected before key generation."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    before = _relative_tree_entries(cwd)

    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "test-agent",
            "--mission",
            "test mission",
            "--keys-dir",
            "",
        ],
        capsys,
    )

    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "path_arg_invalid"
    assert payload["error"] == "path_arg_invalid"
    assert payload["error_code"] == "path_arg_invalid"
    assert "keys-dir" in payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])
    assert "token" not in payload
    assert "claims" not in payload
    # No artifacts created in cwd.
    assert _relative_tree_entries(cwd) == before
    assert not (cwd / "passport_private.pem").exists()
    assert not (cwd / "passport_public.pem").exists()
    assert not (cwd / ".vibap").exists()


def test_verify_keys_dir_empty_rejected(tmp_path, capsys):
    """Empty --keys-dir on verify must be rejected before key/state creation."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    before = _relative_tree_entries(cwd)

    rc, payload = _run_cli_and_read_json(
        ["verify", "--token", "not-a-jwt", "--keys-dir", ""],
        capsys,
    )

    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "path_arg_invalid"
    assert payload["error"] == "path_arg_invalid"
    assert payload["error_code"] == "path_arg_invalid"
    assert "keys-dir" in payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])
    # No artifacts created in cwd.
    assert _relative_tree_entries(cwd) == before
    assert not (cwd / "passport_private.pem").exists()
    assert not (cwd / "passport_public.pem").exists()
    assert not (cwd / ".vibap").exists()


def test_attest_keys_dir_empty_rejected(tmp_path, capsys):
    """Empty --keys-dir on attest must be rejected before key/state creation."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    before = _relative_tree_entries(cwd)

    rc, payload = _run_cli_and_read_json(
        [
            "attest",
            "--session",
            "00000000-0000-0000-0000-000000000000",
            "--keys-dir",
            "",
            "--state-dir",
            str(tmp_path / "state"),
            "--log-path",
            str(tmp_path / "audit.jsonl"),
        ],
        capsys,
    )

    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "path_arg_invalid"
    assert payload["error"] == "path_arg_invalid"
    assert payload["error_code"] == "path_arg_invalid"
    assert "keys-dir" in payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])
    # No artifacts created in cwd.
    assert _relative_tree_entries(cwd) == before
    assert not (cwd / "passport_private.pem").exists()
    assert not (cwd / "passport_public.pem").exists()
    assert not (cwd / ".vibap").exists()


@pytest.mark.parametrize("keys_dir_value", ["", "   ", "\t\n"])
def test_issue_keys_dir_whitespace_rejected(tmp_path, capsys, keys_dir_value):
    """Whitespace-only --keys-dir on issue must be rejected before key generation."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    before = _relative_tree_entries(cwd)

    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "test-agent",
            "--mission",
            "test mission",
            "--keys-dir",
            keys_dir_value,
        ],
        capsys,
    )

    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "path_arg_invalid"
    assert payload["error"] == "path_arg_invalid"
    assert payload["error_code"] == "path_arg_invalid"
    assert "keys-dir" in payload["message"]
    assert payload["detail"]
    assert payload["next_steps"]
    assert all("<" in step["command"] and ">" in step["command"] for step in payload["next_steps"])
    assert "token" not in payload
    assert "claims" not in payload
    # No artifacts created in cwd.
    assert _relative_tree_entries(cwd) == before
    assert not (cwd / "passport_private.pem").exists()
    assert not (cwd / "passport_public.pem").exists()
    assert not (cwd / ".vibap").exists()


def test_issue_keys_dir_dot_still_works(tmp_path, capsys):
    """Explicit --keys-dir . (current working directory) must still succeed."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()

    rc, payload = _run_cli_and_read_json(
        [
            "issue",
            "--agent-id",
            "test-agent",
            "--mission",
            "test mission",
            "--keys-dir",
            str(cwd),
        ],
        capsys,
    )

    assert rc == 0
    assert "token" in payload
    assert payload["claims"]["sub"] == "test-agent"
    assert payload["claims"]["mission"] == "test mission"
    assert (cwd / "passport_private.pem").exists()
    assert (cwd / "passport_public.pem").exists()


# ---------------------------------------------------------------------------
# Start --mission empty/whitespace path guidance
#
# ``--mission`` on ``ardur start`` is a mission JSON file path, not a
# directory. The generic ``path_arg_invalid`` hint suggests ``--mission .``,
# which would fail with ``IsADirectoryError``. The ``start_mission_path_invalid``
# response points the user at ``<mission.json>`` instead.
# Uses placeholder model names to satisfy the model-name scan.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mission_value", ["", "   ", "\t\n"])
def test_start_mission_empty_or_whitespace_returns_mission_path_invalid(
    tmp_path, capsys, mission_value
):
    """Empty/whitespace --mission on start returns start_mission_path_invalid with mission-file next_steps."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    before = _relative_tree_entries(cwd)

    rc, payload = _run_cli_and_read_json(
        ["start", "--mission", mission_value, "--port", "0", "--no-tls"],
        capsys,
    )

    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "start_mission_path_invalid"
    assert payload["error"] == "start_mission_path_invalid"
    assert payload["error_code"] == "start_mission_path_invalid"
    # Message and detail must mention mission file/path, not directory.
    assert "mission" in payload["message"].lower()
    assert "path" in payload["message"].lower()
    assert "file" in payload["detail"].lower()
    # Every next_step must point to <mission.json> and never suggest --mission .
    assert payload["next_steps"]
    rendered = json.dumps(payload)
    assert "use '.'" not in rendered
    for step in payload["next_steps"]:
        assert "<mission.json>" in step["command"], step
        assert "--mission ." not in step["command"], step
        # Placeholder-only tokens, no raw local paths.
        assert "<" in step["command"] and ">" in step["command"]
    # No traceback, no raw cwd path in output.
    assert str(cwd) not in rendered
    assert "Traceback" not in rendered
    # No key/state/session artifacts created in cwd.
    assert _relative_tree_entries(cwd) == before
    assert not (cwd / "passport_private.pem").exists()
    assert not (cwd / "passport_public.pem").exists()
    assert not (cwd / ".vibap").exists()


# ---------------------------------------------------------------------------
# Start --api-token whitespace rejection
#
# ``--api-token`` is stripped inside ``serve_proxy``. An explicit whitespace-
# only argument is truthy before stripping but resolves to an empty bearer
# token after, silently starting the server with auth-on and an empty token
# (same silent-empty bug class closed for ``--proxy-url`` in 4d98a01). The
# guard in ``cmd_start`` rejects whitespace-only tokens before key generation.
# An empty string ``""`` is falsy and intentionally falls through to
# autogeneration; only whitespace-only strings are rejected.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("token_value", ["   ", "\t", "\n", " \t\n "])
def test_start_api_token_whitespace_returns_api_token_invalid(
    tmp_path, capsys, token_value
):
    """Whitespace-only --api-token on start returns start_api_token_invalid before keys are created."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    before = _relative_tree_entries(cwd)

    rc, payload = _run_cli_and_read_json(
        ["start", "--api-token", token_value, "--port", "0", "--no-tls"],
        capsys,
    )

    assert rc == 1
    assert payload["ok"] is False
    assert payload["condition"] == "start_api_token_invalid"
    assert payload["error"] == "start_api_token_invalid"
    assert payload["error_code"] == "start_api_token_invalid"
    assert "api-token" in payload["message"].lower().replace("-", "-")
    assert "whitespace" in payload["message"].lower()
    assert payload["next_steps"]
    rendered = json.dumps(payload)
    for step in payload["next_steps"]:
        # Placeholder-only tokens or the omit-the-flag step; no raw local paths.
        command = step["command"]
        is_omit_step = step["action"] == "omit_api_token_to_autogenerate"
        assert is_omit_step or ("<" in command and ">" in command), step
    # No traceback, no raw cwd path in output.
    assert str(cwd) not in rendered
    assert "Traceback" not in rendered
    # No key/state/session artifacts created in cwd (guard fires pre-keygen).
    assert _relative_tree_entries(cwd) == before
    assert not (cwd / "passport_private.pem").exists()
    assert not (cwd / "passport_public.pem").exists()
    assert not (cwd / ".vibap").exists()


def test_start_api_token_empty_string_is_not_rejected_like_whitespace():
    """An empty-string --api-token \"\" is falsy and must NOT hit the whitespace guard.

    It falls through to autogeneration (token_source=generated), which is the
    documented, acceptable behavior for empty-but-not-whitespace. Only
    whitespace-only truthy strings are rejected. This pins the boundary so a
    future tightening (rejecting \"\" too) is a deliberate change, not a drift.

    We test the guard helper directly because exercising the full ``cmd_start``
    path with a valid token would actually start the HTTP server.
    """
    ns_unset = argparse.Namespace(api_token=None)
    assert cli._start_api_token_invalid_failure(ns_unset) is None

    ns_empty = argparse.Namespace(api_token="")
    assert cli._start_api_token_invalid_failure(ns_empty) is None

    ns_valid = argparse.Namespace(api_token="real-token-value")
    assert cli._start_api_token_invalid_failure(ns_valid) is None

    # Whitespace-only is the only rejected shape.
    ns_ws = argparse.Namespace(api_token="   ")
    failure = cli._start_api_token_invalid_failure(ns_ws)
    assert failure is not None
    assert failure["condition"] == "start_api_token_invalid"


# ---------------------------------------------------------------------------
# Hub-client --hub-token whitespace guard.
#
# ``resolve_hub_token`` strips the env-var path but returns the CLI-explicit
# path verbatim, so a whitespace-only ``--hub-token '   '`` is truthy and
# resolves to a whitespace bearer token inside ``hub_request``. That reaches
# ``urlrequest.urlopen`` and surfaces as a confusing ``hub_unavailable`` after
# a 5-second network timeout instead of a clear input-validation error. The
# guard in each Hub-client command handler rejects whitespace-only tokens
# before the network call. An empty string ``""`` is falsy and intentionally
# falls through to env/config; only whitespace-only strings are rejected.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("token_value", ["   ", "\t", "\n", " \t\n "])
def test_hub_token_whitespace_invalid_failure_helper(token_value):
    """The _hub_token_invalid_failure helper rejects whitespace-only and accepts None/empty/real."""
    ns_unset = argparse.Namespace(hub_token=None)
    assert cli._hub_token_invalid_failure(ns_unset) is None

    ns_empty = argparse.Namespace(hub_token="")
    assert cli._hub_token_invalid_failure(ns_empty) is None

    ns_valid = argparse.Namespace(hub_token="real-hub-token-value")
    assert cli._hub_token_invalid_failure(ns_valid) is None

    ns_ws = argparse.Namespace(hub_token=token_value)
    failure = cli._hub_token_invalid_failure(ns_ws)
    assert failure is not None
    assert failure["ok"] is False
    assert failure["condition"] == "hub_token_invalid"
    assert failure["error"] == "hub_token_invalid"
    assert failure["error_code"] == "hub_token_invalid"
    assert "hub-token" in failure["message"].lower()
    assert "whitespace" in failure["message"].lower()
    assert failure["next_steps"]
    rendered = json.dumps(failure)
    # Placeholder-only next-step commands; no raw local paths.
    for step in failure["next_steps"]:
        assert "<hub-token>" in step["command"] or step["command"] == "ardur <command>", step
    assert "Traceback" not in rendered


@pytest.mark.parametrize("token_value", ["   ", "\t", "\n", " \t\n "])
def test_status_hub_token_whitespace_returns_hub_token_invalid(
    tmp_path, capsys, token_value
):
    """Whitespace-only --hub-token on status returns hub_token_invalid before hub_request."""
    from argparse import Namespace

    rc = cli.cmd_status(
        Namespace(
            home=str(tmp_path),
            hub_url="http://127.0.0.1:8765",
            hub_token=token_value,
        )
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False
    assert result["condition"] == "hub_token_invalid"
    assert result["error_code"] == "hub_token_invalid"


@pytest.mark.parametrize("token_value", ["   ", "\t", "\n", " \t\n "])
def test_doctor_hub_token_whitespace_returns_hub_token_invalid(
    tmp_path, capsys, token_value
):
    """Whitespace-only --hub-token on doctor returns hub_token_invalid before hub_request."""
    from argparse import Namespace

    rc = cli.cmd_doctor(
        Namespace(
            home=str(tmp_path),
            hub_url="http://127.0.0.1:8765",
            hub_token=token_value,
        )
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False
    assert result["condition"] == "hub_token_invalid"
    assert result["error_code"] == "hub_token_invalid"


@pytest.mark.parametrize("token_value", ["   ", "\t", "\n", " \t\n "])
def test_run_hub_token_whitespace_returns_hub_token_invalid(
    tmp_path, capsys, token_value
):
    """Whitespace-only --hub-token on legacy `ardur run` returns hub_token_invalid.

    Governance flags are all unset so _run_has_governance_intent returns False
    and the legacy Hub-streaming path is selected. The whitespace guard fires
    before run_under_hub is reached.
    """
    from argparse import Namespace

    rc = cli.cmd_run(
        Namespace(
            hub_url="http://127.0.0.1:8765",
            hub_token=token_value,
            home=str(tmp_path),
            mission=None,
            allowed_tools=None,
            forbidden_tools=None,
            via=None,
            govern=None,
            enforce=None,
            no_kernel_correlation=None,
            resource_scope=None,
            no_resource_scope=None,
            max_tool_calls=None,
            max_duration_s=None,
            command=["echo", "hello"],
        )
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False
    assert result["condition"] == "hub_token_invalid"
    assert result["error_code"] == "hub_token_invalid"


@pytest.mark.parametrize("token_value", ["   ", "\t", "\n", " \t\n "])
def test_desktop_observe_hub_token_whitespace_returns_hub_token_invalid(
    tmp_path, capsys, token_value
):
    """Whitespace-only --hub-token on desktop-observe returns hub_token_invalid before hub_request."""
    from argparse import Namespace

    rc = cli.cmd_desktop_observe(
        Namespace(
            home=str(tmp_path),
            hub_url="http://127.0.0.1:8765",
            hub_token=token_value,
            session_id=None,
            app=None,
            title=None,
            text=None,
        )
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert result["ok"] is False
    assert result["condition"] == "hub_token_invalid"
    assert result["error_code"] == "hub_token_invalid"


@pytest.mark.parametrize("token_value", ["   ", "\t", "\n", " \t\n "])
def test_personal_native_host_hub_token_whitespace_returns_hub_token_invalid(
    tmp_path, capsys, token_value
):
    """Whitespace-only --hub-token on personal-native-host returns hub_token_invalid before hub_request."""
    from argparse import Namespace

    rc = cli.cmd_personal_native_host(
        Namespace(
            home=str(tmp_path),
            hub_url="http://127.0.0.1:8765",
            hub_token=token_value,
            once_json=None,
        )
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert rc == 1
    assert captured.err == ""
    assert result["ok"] is False
    assert result["condition"] == "hub_token_invalid"
    assert result["error_code"] == "hub_token_invalid"


def test_status_hub_token_empty_and_omitted_still_reach_hub_request(monkeypatch, tmp_path, capsys):
    """Empty-string and omitted --hub-token fall through to hub_request (regression).

    The guard must not reject these cases: they mean "resolve from env/config",
    matching resolve_hub_token's explicit-empty semantics and the --api-token
    precedent. We monkeypatch hub_request so no real network call is made and
    assert it is actually invoked.
    """
    from argparse import Namespace

    calls: list[dict] = []

    def fake_hub_request(method, path, *args, **kwargs):
        calls.append({"method": method, "path": path, "kwargs": kwargs})
        return {"ok": False, "error": "hub_unavailable", "error_code": "hub_unavailable"}

    monkeypatch.setattr(cli, "hub_request", fake_hub_request)

    for token_value in (None, ""):
        calls.clear()
        rc = cli.cmd_status(
            Namespace(
                home=str(tmp_path),
                hub_url="http://127.0.0.1:8765",
                hub_token=token_value,
            )
        )
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        # hub_request was actually reached (not short-circuited by the guard).
        assert len(calls) == 1, f"hub_request not reached for token={token_value!r}"
        assert calls[0]["kwargs"].get("hub_token") == token_value
        # Result is the hub response, NOT hub_token_invalid.
        assert result.get("error_code") != "hub_token_invalid"
        # rc reflects the (failing) hub response, not the guard.
        _ = rc


def test_status_hub_token_valid_reaches_hub_request(monkeypatch, tmp_path, capsys):
    """A valid non-whitespace --hub-token reaches hub_request (regression)."""
    from argparse import Namespace

    calls: list[dict] = []

    def fake_hub_request(method, path, *args, **kwargs):
        calls.append({"method": method, "path": path, "kwargs": kwargs})
        return {"ok": False, "error": "hub_unavailable", "error_code": "hub_unavailable"}

    monkeypatch.setattr(cli, "hub_request", fake_hub_request)

    rc = cli.cmd_status(
        Namespace(
            home=str(tmp_path),
            hub_url="http://127.0.0.1:8765",
            hub_token="abc",
        )
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert len(calls) == 1
    assert calls[0]["kwargs"].get("hub_token") == "abc"
    assert result.get("error_code") == "hub_unavailable"
    assert result.get("error_code") != "hub_token_invalid"
    _ = rc

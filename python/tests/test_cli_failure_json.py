from __future__ import annotations

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

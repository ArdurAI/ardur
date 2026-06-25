from __future__ import annotations

import json

from vibap import cli


def _start_args(tmp_path, mission_path):
    parser = cli.build_parser()
    return parser.parse_args(
        [
            "start",
            "--mission",
            str(mission_path),
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--keys-dir",
            str(tmp_path / "keys"),
            "--state-dir",
            str(tmp_path / "state"),
            "--log-path",
            str(tmp_path / "audit.log"),
            "--no-tls",
        ]
    )


def _patch_start_before_serve(monkeypatch):
    class FakeGovernanceProxy:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    def fake_generate_keypair(*, keys_dir=None):
        return object(), object()

    def fail_serve_proxy(**kwargs):  # pragma: no cover - assertion path
        raise AssertionError("serve_proxy must not start after invalid mission input")

    monkeypatch.setattr(cli, "GovernanceProxy", FakeGovernanceProxy)
    monkeypatch.setattr(cli, "generate_keypair", fake_generate_keypair)
    monkeypatch.setattr(cli, "serve_proxy", fail_serve_proxy)


def _assert_structured_mission_failure(capsys, tmp_path, exit_code, condition, leaked_text=""):
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    assert "Traceback" not in captured.out
    assert str(tmp_path) not in captured.out
    if leaked_text:
        assert leaked_text not in captured.out
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error"] == condition
    assert payload["condition"] == condition
    assert payload["next_steps"]
    rendered_next_steps = json.dumps(payload["next_steps"], sort_keys=True)
    assert "<mission.json>" in rendered_next_steps
    assert "<keys-dir>" in rendered_next_steps
    assert str(tmp_path) not in rendered_next_steps


def test_start_api_token_argument_is_forwarded_to_serve_proxy(monkeypatch):
    captured: dict[str, object] = {}

    class FakeGovernanceProxy:
        def __init__(self, **kwargs):
            captured["proxy_kwargs"] = kwargs

    def fake_generate_keypair(*, keys_dir=None):
        captured["keys_dir"] = keys_dir
        return object(), object()

    def fake_serve_proxy(**kwargs):
        captured["serve_proxy_kwargs"] = kwargs

    monkeypatch.setattr(cli, "GovernanceProxy", FakeGovernanceProxy)
    monkeypatch.setattr(cli, "generate_keypair", fake_generate_keypair)
    monkeypatch.setattr(cli, "serve_proxy", fake_serve_proxy)

    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "start",
            "--host",
            "127.0.0.1",
            "--port",
            "9876",
            "--api-token",
            "configured-token-for-test",
            "--no-tls",
        ]
    )

    assert args.api_token == "configured-token-for-test"
    assert cli.cmd_start(args) == 0

    serve_kwargs = captured["serve_proxy_kwargs"]
    assert isinstance(serve_kwargs, dict)
    assert serve_kwargs["api_token"] == "configured-token-for-test"
    assert serve_kwargs["require_auth"] is True
    assert serve_kwargs["no_tls"] is True
    assert serve_kwargs["host"] == "127.0.0.1"
    assert serve_kwargs["port"] == 9876


def test_start_missing_mission_file_returns_structured_json(monkeypatch, tmp_path, capsys):
    _patch_start_before_serve(monkeypatch)

    args = _start_args(tmp_path, tmp_path / "missing-mission.json")

    exit_code = cli.cmd_start(args)

    _assert_structured_mission_failure(capsys, tmp_path, exit_code, "start_mission_file_missing")


def test_start_malformed_mission_file_returns_structured_json(monkeypatch, tmp_path, capsys):
    _patch_start_before_serve(monkeypatch)
    mission_file = tmp_path / "mission.json"
    mission_file.write_text("{raw-secret: do-not-leak", encoding="utf-8")

    exit_code = cli.cmd_start(_start_args(tmp_path, mission_file))

    _assert_structured_mission_failure(
        capsys,
        tmp_path,
        exit_code,
        "start_mission_file_malformed_json",
        leaked_text="raw-secret",
    )


def test_start_invalid_mission_schema_returns_structured_json(monkeypatch, tmp_path, capsys):
    _patch_start_before_serve(monkeypatch)
    mission_file = tmp_path / "mission.json"
    mission_file.write_text(json.dumps({"agent_id": "agent-only"}), encoding="utf-8")

    exit_code = cli.cmd_start(_start_args(tmp_path, mission_file))

    _assert_structured_mission_failure(capsys, tmp_path, exit_code, "start_mission_file_invalid")


def test_start_valid_mission_file_still_starts_session_and_serves(monkeypatch, tmp_path, capsys):
    captured: dict[str, object] = {}
    mission_file = tmp_path / "mission.json"
    mission_file.write_text(
        json.dumps(
            {
                "agent_id": "demo-agent",
                "mission": "demo mission",
                "allowed_tools": ["read_file"],
                "ttl_s": 120,
            }
        ),
        encoding="utf-8",
    )

    class FakeSession:
        jti = "session-123"

    class FakeGovernanceProxy:
        def __init__(self, **kwargs):
            captured["proxy_kwargs"] = kwargs

        def start_session(self, token):
            captured["started_token"] = token
            return FakeSession()

    def fake_generate_keypair(*, keys_dir=None):
        captured["keys_dir"] = keys_dir
        return "private-key", "public-key"

    def fake_issue_passport(mission, private_key, *, ttl_s=None):
        captured["issued_mission"] = mission
        captured["issued_private_key"] = private_key
        captured["issued_ttl_s"] = ttl_s
        return "mission-token"

    def fake_serve_proxy(**kwargs):
        captured["serve_proxy_kwargs"] = kwargs

    monkeypatch.setattr(cli, "GovernanceProxy", FakeGovernanceProxy)
    monkeypatch.setattr(cli, "generate_keypair", fake_generate_keypair)
    monkeypatch.setattr(cli, "issue_passport", fake_issue_passport)
    monkeypatch.setattr(cli, "serve_proxy", fake_serve_proxy)

    args = _start_args(tmp_path, mission_file)
    args.api_token = "configured-token-for-test"

    assert cli.cmd_start(args) == 0

    stdout = capsys.readouterr().out
    payload = json.loads(stdout)
    assert payload["status"] == "session_started"
    assert payload["mission_file"] == str(mission_file)
    assert payload["session_id"] == "session-123"
    assert payload["agent_id"] == "demo-agent"
    assert payload["mission"] == "demo mission"
    assert payload["token"] == "mission-token"
    assert captured["issued_ttl_s"] == 120
    assert captured["started_token"] == "mission-token"
    serve_kwargs = captured["serve_proxy_kwargs"]
    assert isinstance(serve_kwargs, dict)
    assert serve_kwargs["initial_session_id"] == "session-123"
    assert serve_kwargs["api_token"] == "configured-token-for-test"
    assert serve_kwargs["no_tls"] is True

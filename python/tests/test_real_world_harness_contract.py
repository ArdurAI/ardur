from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from vibap.cli import protect_claude_code


REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_CODE_PLUGIN_DIR = REPO_ROOT / "plugins" / "claude-code"
HARNESS = REPO_ROOT / "scripts" / "run-rwt-phase1-fresh-user.py"


def _protect_args(**overrides):
    values = {
        "scope": None,
        "profile": None,
        "mode": None,
        "json": True,
        "home": None,
        "plugin_dir": CLAUDE_CODE_PLUGIN_DIR,
        "keys_dir": None,
        "agent_id": "test:claude-code",
        "mission": None,
        "max_tool_calls": 250,
        "max_duration_s": 86400,
        "ttl_s": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _load_harness():
    spec = importlib.util.spec_from_file_location("rwt_phase1_harness", HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_protect_claude_code_exposes_matrix_active_mission_path_alias(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = protect_claude_code(
        _protect_args(scope=project, mode="read-only", home=tmp_path / "home", keys_dir=tmp_path / "keys")
    )

    assert result["active_mission_path"] == result["active_passport"]
    assert Path(result["active_mission_path"]).is_file()


def _assert_redaction_contract(harness, raw: str, raw_secrets: list[str]) -> None:
    assert harness.secret_scan_hits(raw), f"expected non-empty secret_scan_hits for payload: {raw}"
    redacted = harness.redact_text(raw)
    for secret in raw_secrets:
        assert secret not in redacted
    assert harness.secret_scan_hits(redacted) == []


def _fake_private_key_block() -> tuple[str, str, str]:
    begin = "-----BEGIN EC PRIVATE KEY-----"
    body = "RWT_FAKE_PRIVATE_KEY_BODY_123456789"
    end = "-----END EC PRIVATE KEY-----"
    return begin, body, f"{begin}\n{body}\n{end}"


def _fake_bare_jwt() -> str:
    return ".".join(
        [
            "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJ" + "zdWIiOiJyZWFsLXdvcmxkLWhhcm5lc3MiLCJzY29wZSI6InRlc3QifQ",
            "c2lnbmF0dXJlX2Zha2VfdmFsdWU",
        ]
    )


_FAKE_PRIVATE_KEY_BEGIN, _FAKE_PRIVATE_KEY_BODY, _FAKE_PRIVATE_KEY_BLOCK = _fake_private_key_block()
_FAKE_BARE_JWT = _fake_bare_jwt()
_FAKE_API_KEY_VALUE = "RWT_FAKE_API_KEY_VALUE"
_FAKE_TOKEN_VALUE = "RWT_FAKE_TOKEN_VALUE"
_FAKE_ACCESS_TOKEN = "RWT_FAKE_ACCESS_TOKEN"
_FAKE_AUTH_TOKEN = "RWT_FAKE_AUTH_TOKEN"
_FAKE_OPENROUTER_KEY = "RWT_FAKE_OPENROUTER_KEY"
_FAKE_ANTHROPIC_TOKEN = "RWT_FAKE_ANTHROPIC_TOKEN"
_FAKE_GITHUB_TOKEN = "RWT_FAKE_GITHUB_TOKEN"
_FAKE_STDERR_TOKEN = "RWT_FAKE_STDERR_TOKEN"
_FAKE_BEARER_VALUE = "RWT_FAKE_BEARER_VALUE"
_FAKE_URL_QUERY_TOKEN = "RWT_FAKE_URL_QUERY_TOKEN"


@pytest.mark.parametrize(
    ("name", "raw", "raw_secrets"),
    [
        (
            "json_key_values",
            json.dumps({"api_key": _FAKE_API_KEY_VALUE, "token": _FAKE_TOKEN_VALUE}),
            [_FAKE_API_KEY_VALUE, _FAKE_TOKEN_VALUE],
        ),
        (
            "nested_json",
            json.dumps({"outer": {"auth": {"access_token": _FAKE_ACCESS_TOKEN}}, "items": [{"auth_token": _FAKE_AUTH_TOKEN}]}),
            [_FAKE_ACCESS_TOKEN, _FAKE_AUTH_TOKEN],
        ),
        (
            "env_assignments",
            "\n".join(
                [
                    f"OPENROUTER_API_KEY={_FAKE_OPENROUTER_KEY}",
                    f"ANTHROPIC_AUTH_TOKEN={_FAKE_ANTHROPIC_TOKEN}",
                    f"GITHUB_TOKEN={_FAKE_GITHUB_TOKEN}",
                ]
            ),
            [_FAKE_OPENROUTER_KEY, _FAKE_ANTHROPIC_TOKEN, _FAKE_GITHUB_TOKEN],
        ),
        (
            "stderr_style",
            f"stderr: authentication failed: AUTH_TOKEN={_FAKE_STDERR_TOKEN}",
            [_FAKE_STDERR_TOKEN],
        ),
        (
            "bearer_header",
            f"Authorization: Bearer {_FAKE_BEARER_VALUE}",
            [_FAKE_BEARER_VALUE],
        ),
        (
            "private_key_pem",
            _FAKE_PRIVATE_KEY_BLOCK,
            [_FAKE_PRIVATE_KEY_BEGIN, _FAKE_PRIVATE_KEY_BODY],
        ),
        (
            "bare_jwt",
            _FAKE_BARE_JWT,
            [_FAKE_BARE_JWT],
        ),
        (
            "url_query_token",
            f"https://example.invalid/callback?token={_FAKE_URL_QUERY_TOKEN}&next=/home",
            [_FAKE_URL_QUERY_TOKEN],
        ),
    ],
)
def test_rwt_phase1_harness_redacts_secret_like_values(name, raw, raw_secrets):
    del name
    harness = _load_harness()
    _assert_redaction_contract(harness, raw, raw_secrets)


def test_rwt_phase1_harness_copies_python_source_without_build_side_effects(tmp_path):
    harness = _load_harness()
    fake_repo = tmp_path / "repo"
    python_src = fake_repo / "python"
    (python_src / "build").mkdir(parents=True)
    (python_src / "build" / "generated.py").write_text("generated\n", encoding="utf-8")
    (python_src / "vibap" / "__pycache__").mkdir(parents=True)
    (python_src / "vibap" / "__init__.py").write_text("__version__ = '0.1.0'\n", encoding="utf-8")
    (python_src / "pyproject.toml").write_text("[project]\nname = 'fake'\n", encoding="utf-8")
    ctx = SimpleNamespace(repo=fake_repo, temp_root=tmp_path / "temp")

    copied = harness.copy_python_source_for_wheel(ctx)

    assert copied == tmp_path / "temp" / "source" / "python"
    assert (copied / "pyproject.toml").is_file()
    assert (copied / "vibap" / "__init__.py").is_file()
    assert not (copied / "build").exists()
    assert not (copied / "vibap" / "__pycache__").exists()


def test_rwt_phase1_harness_copy_python_source_rejects_symlinks(tmp_path):
    harness = _load_harness()
    fake_repo = tmp_path / "repo"
    python_src = fake_repo / "python"
    (python_src / "vibap").mkdir(parents=True)
    (python_src / "vibap" / "__init__.py").write_text("__version__ = '0.1.0'\n", encoding="utf-8")
    (python_src / "pyproject.toml").write_text("[project]\nname = 'fake'\n", encoding="utf-8")
    secret_file = tmp_path / "outside-secret.txt"
    secret_file.write_text("do-not-copy\n", encoding="utf-8")

    link_path = python_src / "vibap" / "linked-secret.txt"
    try:
        link_path.symlink_to(secret_file)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is not supported in this test environment")

    ctx = SimpleNamespace(repo=fake_repo, temp_root=tmp_path / "temp")
    with pytest.raises(RuntimeError, match="symlink"):
        harness.copy_python_source_for_wheel(ctx)


def test_rwt_phase1_bundle_artifact_metadata_is_secret_scan_safe(tmp_path):
    harness = _load_harness()
    project = tmp_path / "project"
    ardur_home = tmp_path / "ardur-home"
    out_dir = tmp_path / "evidence" / "commands"
    fixtures = tmp_path / "evidence" / "fixtures"
    project.mkdir()
    ardur_home.mkdir()
    out_dir.mkdir(parents=True)
    fixtures.mkdir(parents=True)
    (project / "ARDUR.md").write_text("# test\n", encoding="utf-8")
    (ardur_home / "active_mission.jwt").write_text(_FAKE_BARE_JWT, encoding="utf-8")
    ctx = SimpleNamespace(project=project, ardur_home=ardur_home, out_dir=out_dir, output_dir=tmp_path / "evidence", fixtures=fixtures)

    artifacts = harness.collect_artifacts(ctx)
    serialized = json.dumps({"artifacts": artifacts}, sort_keys=True)

    assert artifacts["active_mission_jwt_presence"] == "present_not_copied"
    assert "active_mission_jwt" not in artifacts
    assert _FAKE_BARE_JWT not in serialized
    assert harness.secret_scan_hits(serialized) == []


def test_rwt_phase1_harness_allows_clean_local_candidate_commit(monkeypatch, tmp_path):
    harness = _load_harness()
    fake_repo = tmp_path / "repo"
    fake_repo.mkdir()
    (fake_repo / ".git").write_text("gitdir: ../.git/worktrees/fake\n", encoding="utf-8")

    def fake_short_git(_repo, *args):
        if args == ("rev-parse", "HEAD"):
            return "candidate123"
        if args == ("rev-parse", "origin/dev"):
            return "base123"
        raise AssertionError(args)

    monkeypatch.setattr(harness, "short_git", fake_short_git)
    monkeypatch.setattr(harness, "git_text", lambda _repo, *args: "")
    monkeypatch.setattr(harness, "git_success", lambda _repo, *args: args == ("merge-base", "--is-ancestor", "origin/dev", "HEAD"))
    ctx = SimpleNamespace(repo=fake_repo, expected_origin_dev=None, allow_dirty=False)

    repo_info, blocker = harness.validate_repo_preflight(ctx)

    assert blocker is None
    assert repo_info["head"] == "candidate123"
    assert repo_info["origin_dev"] == "base123"
    assert repo_info["origin_dev_ancestor_of_head"] is True
    assert repo_info["clean_before"] is True
    assert "clean local candidate" in repo_info["preflight_note"]


def test_rwt_phase1_harness_version_info_handles_missing_ardur_binary(tmp_path):
    harness = _load_harness()
    ctx = SimpleNamespace(
        python_bin=sys.executable,
        ardur_bin=tmp_path / "venv" / "bin" / "ardur",
        repo=tmp_path,
        project=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
    )

    versions = harness.version_info(ctx)

    assert versions["python"].startswith("Python ")
    assert versions["ardur"] == "missing"


def test_rwt_phase1_bundle_redacts_local_absolute_paths(monkeypatch, tmp_path):
    harness = _load_harness()
    fake_repo = tmp_path / "repo"
    fake_repo.mkdir()
    (fake_repo / ".git").write_text("gitdir: ../.git/worktrees/fake\n", encoding="utf-8")
    output_dir = tmp_path / "output"
    out_dir = output_dir / "out"
    fixtures = output_dir / "fixtures"
    output_dir.mkdir(parents=True)
    out_dir.mkdir(parents=True)
    fixtures.mkdir(parents=True)
    temp_root = tmp_path / "temp-root"
    home = temp_root / "home"
    ardur_home = temp_root / "ardur-home"
    project = temp_root / "project"
    evidence = temp_root / "evidence"
    for path in [temp_root, home, ardur_home, project, evidence]:
        path.mkdir(parents=True, exist_ok=True)

    ctx = SimpleNamespace(
        repo=fake_repo,
        output_dir=output_dir,
        out_dir=out_dir,
        fixtures=fixtures,
        started_at="2026-05-12T00:00:00+00:00",
        operator_profile="planner",
        allow_dirty=False,
        temp_root=temp_root,
        home=home,
        ardur_home=ardur_home,
        project=project,
        evidence=evidence,
        python_bin="/Users/test-user/.local/bin/python3.13",
        ardur_bin=temp_root / "venv" / "bin" / "ardur",
        cleanup_temp_root_removed=False,
        cleanup_retained_path=None,
        gate_results=[
            harness.GateResult("RWT-1", ["fresh-user", "integration", "matrix"], harness.STATUS_PASS, "ok"),
            harness.GateResult("RWT-2", ["fixture", "integration"], harness.STATUS_PASS, "ok"),
            harness.GateResult("RWT-3", ["real-host", "fresh-user", "integration"], harness.STATUS_SKIP_GATED, "ok"),
        ],
        commands=[
            harness.CommandRecord(
                id="example",
                cwd=str(project),
                argv_redacted=[
                    "/Users/test-user/.local/bin/python3.13",
                    str(temp_root / "venv" / "bin" / "ardur"),
                    str(fake_repo / "plugins" / "claude-code"),
                    str(ardur_home),
                ],
                exit_code=0,
                stdout_redacted_path="out/example.stdout.txt",
                stderr_redacted_path="out/example.stderr.txt",
                elapsed_ms=1,
            )
        ],
    )

    monkeypatch.setattr(harness, "short_git", lambda _repo, *_args: "abc123def456")
    monkeypatch.setattr(harness, "git_text", lambda _repo, *_args: "")
    monkeypatch.setattr(harness, "collect_artifacts", lambda _ctx: {"reports": []})
    monkeypatch.setattr(harness, "collect_receipts", lambda _ctx: {"verify_status": "pass", "receipt_count": 0})
    monkeypatch.setattr(
        harness,
        "host_info",
        lambda: {"os": "Darwin", "arch": "arm64", "kernel": "test", "container": "unknown", "wsl": "false"},
    )
    monkeypatch.setattr(
        harness,
        "version_info",
        lambda _ctx: {"python": "Python 3.13.0", "ardur": "0.0.0", "git": "git version test"},
    )

    bundle = harness.bundle_for(
        ctx,
        repo_info={
            "worktree": str(fake_repo),
            "head": "abc123def456",
            "origin_dev": "abc123def456",
            "expected_origin_dev": "abc123def456",
            "origin_dev_ancestor_of_head": True,
            "clean_before": True,
            "dirty_paths_before": [],
        },
        repo_blocker=None,
    )
    serialized = json.dumps(bundle, sort_keys=True)

    assert "<REPO>" in serialized
    assert "<RWT_HOME>" in serialized
    assert "<RWT_ARDUR_HOME>" in serialized
    assert "<RWT_PROJECT>" in serialized
    assert "<RWT_EVIDENCE>" in serialized
    assert "<RWT_OUTPUT>" in serialized
    assert "<PYTHON>" in serialized
    assert "<ARDUR_BIN>" in serialized
    assert bundle["redaction"]["path_scan_hits"] == 0
    assert "generic_local_absolute_paths" in bundle["redaction"]["path_patterns_applied"]
    assert "file_uri_targets" in bundle["redaction"]["path_redaction_scope"]
    assert str(fake_repo) not in serialized
    assert str(temp_root) not in serialized
    assert "/Users/" not in serialized


def test_rwt_phase1_shareable_sanitizer_redacts_adversarial_local_paths(tmp_path):
    harness = _load_harness()
    repo = tmp_path / "repo"
    output_dir = tmp_path / "output"
    temp_root = tmp_path / "temp-root"
    home = temp_root / "home"
    ardur_home = temp_root / "ardur-home"
    project = temp_root / "project"
    evidence = temp_root / "evidence"
    ardur_bin = temp_root / "venv" / "bin" / "ardur"
    ctx = SimpleNamespace(
        repo=repo,
        output_dir=output_dir,
        temp_root=temp_root,
        home=home,
        ardur_home=ardur_home,
        project=project,
        evidence=evidence,
        python_bin="/Users/test-user/.local/bin/python3.13",
        ardur_bin=ardur_bin,
    )
    payload = {
        "json_string_values": [
            "/Users/alice/.hermes/workspace/projects/ardur/private.txt",
            "/home/alice/.config/ardur/private.txt",
            "/tmp/ardur-rwt-phase1/private-output.txt",
            "/private/var/folders/zz/ardur-rwt-phase1/private-output.txt",
            "/var/folders/zz/ardur-rwt-phase1/private-output.txt",
            "/private/tmp/ardur-symlink-like/../private-output.txt",
            "/tmp/ユニコード/秘密-output.txt",
            "file:///Users/alice/private/file-uri-output.txt",
            "file:///tmp/ardur-rwt-phase1/file-uri-output.txt",
        ],
        "log_error_text": "error while opening /tmp/ardur-rwt-phase1/private-output.txt from file:///home/alice/private/file-uri-output.txt",
        "secret_adjacent_path": f"OPENROUTER_API_KEY={_FAKE_OPENROUTER_KEY} path=/tmp/ardur-rwt-phase1/secret-adjacent.txt",
        "project_file": str(project / "ARDUR.md"),
        "ctx_roots": [str(repo), str(output_dir), str(temp_root), str(home), str(ardur_home), str(project), str(evidence), str(ardur_bin)],
    }

    sanitized = harness.sanitize_shareable_value(payload, ctx)
    serialized = json.dumps(sanitized, sort_keys=True, ensure_ascii=False)

    forbidden_fragments = [
        "/Users/",
        "/home/",
        "/tmp/",
        "/private/var/folders/",
        "/var/folders/",
        "/private/tmp/",
        "ardur-rwt-phase1",
        "file-uri-output.txt",
        "private-output.txt",
        "secret-adjacent.txt",
        "秘密-output.txt",
        _FAKE_OPENROUTER_KEY,
        str(repo),
        str(output_dir),
        str(temp_root),
        str(home),
        str(ardur_home),
        str(project),
        str(evidence),
        str(ardur_bin),
    ]
    for forbidden in forbidden_fragments:
        assert forbidden not in serialized
    assert "[REDACTED]" in serialized
    assert "<REPO>" in serialized
    assert "<RWT_TEMP>" in serialized
    assert "<RWT_OUTPUT>" in serialized
    assert "<RWT_PROJECT>/ARDUR.md" in serialized
    assert "<ABSOLUTE_PATH:" in serialized or "<FILE_URI:" in serialized


def test_rwt_phase1_path_leak_scan_flags_tmp_and_file_uri_paths(tmp_path):
    harness = _load_harness()
    ctx = SimpleNamespace(
        repo=tmp_path / "repo",
        output_dir=tmp_path / "output",
        temp_root=tmp_path / "temp-root",
        home=tmp_path / "temp-root" / "home",
        ardur_home=tmp_path / "temp-root" / "ardur-home",
        project=tmp_path / "temp-root" / "project",
        evidence=tmp_path / "temp-root" / "evidence",
        python_bin="/Users/test-user/.local/bin/python3.13",
        ardur_bin=tmp_path / "temp-root" / "venv" / "bin" / "ardur",
    )
    text = "bundle leak: /tmp/ardur-rwt-phase1/private-output.txt and file:///tmp/ardur-rwt-phase1/file-uri-output.txt; public https://example.test/docs/path stays public"

    hits = harness.path_leak_scan_hits(text, ctx)

    assert any(hit.startswith("/tmp/") for hit in hits)
    assert any(hit.startswith("file://") for hit in hits)
    assert not any("example.test" in hit for hit in hits)


def test_rwt_phase1_declared_shareable_artifacts_are_path_clean(tmp_path):
    harness = _load_harness()
    output_dir = tmp_path / "output"
    out_dir = output_dir / "out"
    fixtures = output_dir / "fixtures"
    temp_root = tmp_path / "temp-root"
    project = temp_root / "project"
    ardur_home = temp_root / "ardur-home"
    for path in [out_dir, fixtures, project, ardur_home]:
        path.mkdir(parents=True, exist_ok=True)
    ctx = SimpleNamespace(
        repo=tmp_path / "repo",
        output_dir=output_dir,
        out_dir=out_dir,
        fixtures=fixtures,
        temp_root=temp_root,
        home=temp_root / "home",
        ardur_home=ardur_home,
        project=project,
        evidence=temp_root / "evidence",
        python_bin=sys.executable,
        ardur_bin=temp_root / "venv" / "bin" / "ardur",
        env=os.environ.copy(),
        commands=[],
    )

    harness.write_rwt2_fixtures(ctx)
    result = harness.run_capture(
        ctx,
        "rwt2-claude-code-report",
        [
            sys.executable,
            "-c",
            "import json, os; print(json.dumps({'cwd': os.getcwd(), 'tmp': '/tmp/ardur-rwt-phase1/private-output.txt', 'uri': 'file:///tmp/ardur-rwt-phase1/file-uri-output.txt'}))",
        ],
        cwd=project,
    )
    assert str(project) in result.stdout
    assert "/tmp/ardur-rwt-phase1/private-output.txt" in result.stdout

    artifacts = harness.collect_artifacts(ctx)
    declared = sorted(
        set(artifacts["fixtures"])
        | set(artifacts["reports"])
        | set(artifacts["redacted_stdout_files"])
    )
    assert declared
    for relative_path in declared:
        artifact_text = (output_dir / relative_path).read_text(encoding="utf-8")
        assert harness.path_leak_scan_hits(artifact_text, ctx) == []
        assert harness.secret_scan_hits(artifact_text) == []


def test_rwt_phase1_write_bundle_fails_when_post_write_path_leaks_detected(monkeypatch, tmp_path):
    harness = _load_harness()
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True)
    temp_root = tmp_path / "temp-root"
    temp_root.mkdir(parents=True)
    ctx = SimpleNamespace(
        output_dir=output_dir,
        repo=tmp_path / "repo",
        temp_root=temp_root,
        home=temp_root / "home",
        ardur_home=temp_root / "ardur-home",
        project=temp_root / "project",
        evidence=temp_root / "evidence",
        python_bin="/Users/test-user/.local/bin/python3.13",
        ardur_bin=temp_root / "venv" / "bin" / "ardur",
    )

    monkeypatch.setattr(
        harness,
        "bundle_for",
        lambda _ctx, _repo_info, _repo_blocker: {
            "status": harness.STATUS_PASS,
            "redaction": {"secret_scan_hits": 0, "notes": []},
            "repo": {"worktree": "/Users/test-user/private/repo"},
            "tmp_log": "/tmp/ardur-rwt-phase1/private-output.txt",
            "private_tmp_log": "/private/tmp/ardur-rwt-phase1/private-output.txt",
            "file_uri_log": "file:///tmp/ardur-rwt-phase1/file-uri-output.txt",
            "unicode_log": "/tmp/ユニコード/秘密-output.txt",
            "secret_adjacent_path": f"OPENROUTER_API_KEY={_FAKE_OPENROUTER_KEY} path=/tmp/ardur-rwt-phase1/secret-adjacent.txt",
        },
    )

    bundle_path = harness.write_bundle(ctx, repo_info={}, repo_blocker=None)
    persisted_text = bundle_path.read_text(encoding="utf-8")
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

    assert bundle["status"] == harness.STATUS_FAIL
    assert bundle["redaction"]["path_scan_hits"] > 0
    assert "post_write_path_leak_scan" in bundle["redaction"]["path_patterns_applied"]
    assert any("path leak" in note.lower() for note in bundle["redaction"]["notes"])
    assert any("absolute_path_marker:/Users" in note for note in bundle["redaction"]["notes"])
    forbidden_values = [
        "/Users/",
        "/home/",
        "/private/var/folders/",
        "/var/folders/",
        "/tmp/",
        "/private/tmp/",
        "/Users/test-user/private/repo",
        "ardur-rwt-phase1",
        "file-uri-output.txt",
        "private-output.txt",
        "secret-adjacent.txt",
        "秘密-output.txt",
        _FAKE_OPENROUTER_KEY,
        str(temp_root),
        str(output_dir),
        ctx.python_bin,
        str(ctx.ardur_bin),
    ]
    for forbidden in forbidden_values:
        assert forbidden not in persisted_text
    notes_text = json.dumps(bundle["redaction"]["notes"], sort_keys=True)
    for forbidden in forbidden_values:
        assert forbidden not in notes_text

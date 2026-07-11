"""Focused regression tests for codex-app-server-fixture path validation.

Covers: --home, --chain-dir, --keys-dir existing-file, and --project-dir
dangling-symlink. All failures must return structured JSON with exit 1,
no traceback, no raw local paths, and no artifacts created before failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run_fixture(*args: str, env: dict[str, str], repo_root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "vibap.cli", "codex-app-server-fixture", *args],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=repo_root,
        timeout=20,
    )


def _assert_structured_failure(
    completed: subprocess.CompletedProcess,
    condition: str,
    *,
    tmp_path: Path,
    no_artifacts: list[Path] | None = None,
) -> dict:
    assert completed.returncode == 1, f"expected exit 1, got {completed.returncode}"
    assert completed.stderr == "", f"expected empty stderr, got: {completed.stderr!r}"
    output = json.loads(completed.stdout)
    output_text = json.dumps(output, sort_keys=True)
    assert output["ok"] is False
    assert output["error"] == condition
    assert output["condition"] == condition
    assert "not a directory" in output["message"].lower() or "dangling" in output["message"].lower()
    assert "Traceback" not in output_text
    assert str(tmp_path) not in output_text
    for path in (no_artifacts or []):
        assert not path.exists(), f"artifact {path} should not exist"
    return output


def test_codex_fixture_rejects_home_existing_file(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    home_file = tmp_path / "home-file"
    project_dir = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    keys_dir = tmp_path / "keys"
    caller_home.mkdir()
    home_file.write_text("not a directory\n", encoding="utf-8")
    project_dir.mkdir()
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = _run_fixture(
        "--home", str(home_file),
        "--project-dir", str(project_dir),
        "--chain-dir", str(chain_dir),
        "--keys-dir", str(keys_dir),
        env=env,
        repo_root=repo_root,
    )

    _assert_structured_failure(
        completed,
        "codex_app_server_fixture_home_not_directory",
        tmp_path=tmp_path,
        no_artifacts=[chain_dir, keys_dir],
    )
    assert home_file.is_file()


def test_codex_fixture_rejects_chain_dir_existing_file(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    fixture_home = tmp_path / "fixture-home"
    project_dir = tmp_path / "project"
    chain_file = tmp_path / "chain-file"
    keys_dir = tmp_path / "keys"
    caller_home.mkdir()
    project_dir.mkdir()
    chain_file.write_text("not a directory\n", encoding="utf-8")
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = _run_fixture(
        "--home", str(fixture_home),
        "--project-dir", str(project_dir),
        "--chain-dir", str(chain_file),
        "--keys-dir", str(keys_dir),
        env=env,
        repo_root=repo_root,
    )

    _assert_structured_failure(
        completed,
        "codex_app_server_fixture_chain_dir_not_directory",
        tmp_path=tmp_path,
        no_artifacts=[fixture_home, keys_dir],
    )
    assert chain_file.is_file()


def test_codex_fixture_rejects_keys_dir_existing_file(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    fixture_home = tmp_path / "fixture-home"
    project_dir = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    keys_file = tmp_path / "keys-file"
    caller_home.mkdir()
    project_dir.mkdir()
    keys_file.write_text("not a directory\n", encoding="utf-8")
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = _run_fixture(
        "--home", str(fixture_home),
        "--project-dir", str(project_dir),
        "--chain-dir", str(chain_dir),
        "--keys-dir", str(keys_file),
        env=env,
        repo_root=repo_root,
    )

    _assert_structured_failure(
        completed,
        "codex_app_server_fixture_keys_dir_not_directory",
        tmp_path=tmp_path,
        no_artifacts=[fixture_home, chain_dir],
    )
    assert keys_file.is_file()


def test_codex_fixture_rejects_project_dir_dangling_symlink(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    fixture_home = tmp_path / "fixture-home"
    chain_dir = tmp_path / "chain"
    keys_dir = tmp_path / "keys"
    dangling_target = tmp_path / "no-such-dir"
    dangling_link = tmp_path / "dangle-project"
    caller_home.mkdir()
    dangling_link.symlink_to(dangling_target)
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = _run_fixture(
        "--home", str(fixture_home),
        "--project-dir", str(dangling_link),
        "--chain-dir", str(chain_dir),
        "--keys-dir", str(keys_dir),
        env=env,
        repo_root=repo_root,
    )

    _assert_structured_failure(
        completed,
        "codex_app_server_fixture_project_dir_not_directory",
        tmp_path=tmp_path,
        no_artifacts=[fixture_home, chain_dir, keys_dir, dangling_target],
    )
    assert dangling_link.is_symlink()
    assert not dangling_target.exists()


def test_codex_fixture_rejects_home_dangling_symlink(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    project_dir = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    keys_dir = tmp_path / "keys"
    dangling_target = tmp_path / "no-such-home"
    dangling_link = tmp_path / "dangle-home"
    caller_home.mkdir()
    project_dir.mkdir()
    dangling_link.symlink_to(dangling_target)
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = _run_fixture(
        "--home", str(dangling_link),
        "--project-dir", str(project_dir),
        "--chain-dir", str(chain_dir),
        "--keys-dir", str(keys_dir),
        env=env,
        repo_root=repo_root,
    )

    _assert_structured_failure(
        completed,
        "codex_app_server_fixture_home_not_directory",
        tmp_path=tmp_path,
        no_artifacts=[chain_dir, keys_dir],
    )
    assert not dangling_target.exists()


def test_codex_fixture_valid_inputs_still_work(tmp_path: Path) -> None:
    """Existing valid-input behavior preserved: directories accepted, fixture generated."""
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    fixture_home = tmp_path / "fixture-home"
    project_dir = tmp_path / "project"
    chain_dir = tmp_path / "chain"
    keys_dir = tmp_path / "keys"
    caller_home.mkdir()
    project_dir.mkdir()
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = _run_fixture(
        "--home", str(fixture_home),
        "--project-dir", str(project_dir),
        "--chain-dir", str(chain_dir),
        "--keys-dir", str(keys_dir),
        env=env,
        repo_root=repo_root,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    output = json.loads(completed.stdout)
    assert output.get("schema_version") == "ardur.codex_app_server.local_context.v0.1"
    assert fixture_home.exists()
    assert chain_dir.exists()
    assert keys_dir.exists()
    assert (project_dir / "CODEX.md").exists()


def test_codex_fixture_rejects_project_dir_empty(tmp_path: Path) -> None:
    """Empty --project-dir must fail closed before writing any fixture artifacts."""
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    fixture_home = tmp_path / "fixture-home"
    chain_dir = tmp_path / "chain"
    keys_dir = tmp_path / "keys"
    caller_home.mkdir()
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = _run_fixture(
        "--home", str(fixture_home),
        "--project-dir", "",
        "--chain-dir", str(chain_dir),
        "--keys-dir", str(keys_dir),
        env=env,
        repo_root=repo_root,
    )

    assert completed.returncode == 1
    assert completed.stderr == ""
    output = json.loads(completed.stdout)
    output_text = json.dumps(output, sort_keys=True)
    assert output["ok"] is False
    assert output["error"] == "codex_app_server_fixture_project_dir_empty"
    assert output["condition"] == "codex_app_server_fixture_project_dir_empty"
    assert "empty" in output["message"].lower()
    assert "Traceback" not in output_text
    assert str(tmp_path) not in output_text
    assert not fixture_home.exists()
    assert not chain_dir.exists()
    assert not keys_dir.exists()


def test_codex_fixture_rejects_project_dir_whitespace(tmp_path: Path) -> None:
    """Whitespace-only --project-dir must fail closed before writing any fixture artifacts."""
    repo_root = Path(__file__).resolve().parents[2]
    caller_home = tmp_path / "caller-home"
    ardur_home = tmp_path / "ardur-home"
    fixture_home = tmp_path / "fixture-home"
    chain_dir = tmp_path / "chain"
    keys_dir = tmp_path / "keys"
    caller_home.mkdir()
    env = {
        **os.environ,
        "HOME": str(caller_home),
        "VIBAP_HOME": str(ardur_home),
        "PYTHONPATH": str(repo_root / "python"),
    }

    completed = _run_fixture(
        "--home", str(fixture_home),
        "--project-dir", "   ",
        "--chain-dir", str(chain_dir),
        "--keys-dir", str(keys_dir),
        env=env,
        repo_root=repo_root,
    )

    assert completed.returncode == 1
    assert completed.stderr == ""
    output = json.loads(completed.stdout)
    output_text = json.dumps(output, sort_keys=True)
    assert output["ok"] is False
    assert output["error"] == "codex_app_server_fixture_project_dir_empty"
    assert output["condition"] == "codex_app_server_fixture_project_dir_empty"
    assert "Traceback" not in output_text
    assert str(tmp_path) not in output_text
    assert not fixture_home.exists()
    assert not chain_dir.exists()
    assert not keys_dir.exists()

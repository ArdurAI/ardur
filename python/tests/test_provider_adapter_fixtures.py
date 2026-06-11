from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_DIR = REPO_ROOT / "python"
MISSION = REPO_ROOT / "examples" / "missions" / "provider-adapter-no-key-mission.json"
ADAPTERS = ("openai-agents-sdk", "google-adk")
EXPECTED_STATUSES = {
    "call-allow-read": "allow",
    "call-deny-write": "deny",
    "call-unknown-opaque": "unknown",
}


def _runner(adapter: str) -> Path:
    return REPO_ROOT / "examples" / adapter / "run.sh"


def _json_report(stdout: str) -> dict[str, Any]:
    data = json.loads(stdout)
    assert isinstance(data, dict)
    return data


def _base_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHON", None)
    env["PYTHONPATH"] = str(PYTHON_DIR) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


def _env_with_path_python(tmp_path: Path) -> dict[str, str]:
    """Exercise runner default selection without masking it with PYTHON=sys.executable."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = bin_dir / "python3.13"
    shim.write_text(f"#!/usr/bin/env bash\nexec {shlex.quote(sys.executable)} \"$@\"\n", encoding="utf-8")
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    env = _base_env()
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    return env


def _unsupported_python_shim(tmp_path: Path) -> Path:
    """Fake a selected Python <3.10 so runner exit-status handling is deterministic."""

    shim = tmp_path / "python3.9-unsupported"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        "if [[ \"${1:-}\" == \"-\" ]]; then\n"
        "  selected=\"${2:-$0}\"\n"
        "  printf \"Ardur fixture requires Python >= 3.10; selected interpreter '%s' is Python 3.9.0. Set PYTHON to python3.10+ or run ./scripts/setup-dev.sh.\\n\" \"$selected\" >&2\n"
        "  exit 66\n"
        "fi\n"
        "printf \"unexpected unsupported-python shim invocation: %s\\n\" \"$*\" >&2\n"
        "exit 99\n",
        encoding="utf-8",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return shim


def _env_with_path_missing_dependency_python(tmp_path: Path) -> dict[str, str]:
    """Select a supported default Python that lacks Ardur package dependencies."""

    bin_dir = tmp_path / "missing-deps-bin"
    bin_dir.mkdir()
    shim = bin_dir / "python3.13"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        "script=\"$(cat)\"\n"
        "if [[ \"$script\" == *\"sys.version_info\"* ]]; then\n"
        "  exit 0\n"
        "fi\n"
        "if [[ \"$script\" == *\"importlib.util.find_spec\"* ]]; then\n"
        "  selected=\"${2:-$0}\"\n"
        "  printf \"Ardur fixture dependencies are not installed for selected interpreter '%s': missing PyJWT. Run ./scripts/setup-dev.sh or set PYTHON=python/.venv/bin/python.\\n\" \"$selected\" >&2\n"
        "  exit 65\n"
        "fi\n"
        "printf \"unexpected missing-dependency shim invocation: %s\\n\" \"$*\" >&2\n"
        "exit 99\n",
        encoding="utf-8",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    env = _base_env()
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    return env


def _run_fixture(adapter: str, out_dir: Path, env: dict[str, str]) -> tuple[dict[str, Any], subprocess.CompletedProcess[str]]:
    completed = subprocess.run(
        [str(_runner(adapter)), "--out-dir", str(out_dir), "--mission", str(MISSION)],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    return _json_report(completed.stdout), completed


def _assert_verified_no_key_report(adapter: str, report: dict[str, Any], out_dir: Path, stdout: str) -> None:
    assert report["receipt_chain_verified"] is True
    assert report["receipt_count"] == 3
    assert report["policy_verdict_counts"] == {"allow": 1, "deny": 1, "unknown": 1}
    assert report["adapter"]["id"] == adapter
    assert report["passport"]["issued_from_checked_in_mission_template"] is True
    assert "live provider API enforcement" in report["not_claimed"]
    assert "provider-hidden reasoning visibility" in report["not_claimed"]
    assert "server-side tool-call capture" in report["not_claimed"]
    assert "kernel/subprocess/network side-effect capture" in report["not_claimed"]

    statuses = {str(item["call_id"]): str(item["status"]) for item in report["visible_tool_calls"]}
    assert statuses == EXPECTED_STATUSES
    assert any(item["mapping_confidence"] == "unknown" for item in report["visible_tool_calls"])

    report_file = out_dir / "report.json"
    chain_file = out_dir / "receipts.jsonl"
    claims_file = out_dir / "passport.claims.redacted.json"
    assert report_file.is_file()
    assert chain_file.is_file()
    assert claims_file.is_file()
    assert len(chain_file.read_text(encoding="utf-8").strip().splitlines()) == 3

    shareable_text = report_file.read_text(encoding="utf-8")
    for forbidden in (str(out_dir), str(out_dir.resolve()), str(REPO_ROOT)):
        assert forbidden not in stdout
        assert forbidden not in shareable_text
    assert "<OUTPUT_DIR>" in shareable_text
    assert "<MISSION_TEMPLATE>" in shareable_text


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_runner_scripts_have_supported_python_default_selection(adapter: str) -> None:
    """The public runners must not silently fall back to unsupported ambient python3."""

    text = _runner(adapter).read_text(encoding="utf-8")
    assert "${PYTHON:-python3}" not in text
    assert "python/.venv/bin/python" in text
    assert "python3.13 python3.12 python3.11 python3.10 python3" in text
    assert "Ardur fixture requires Python >= 3.10" in text
    assert "select_python" in text
    assert "require_supported_python" in text


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_no_key_provider_adapter_runner_executes_without_python_override(tmp_path: Path, adapter: str) -> None:
    """Run the checked-in runner with no PYTHON env and verify shareable fixture evidence."""

    out_dir = tmp_path / adapter
    env = _env_with_path_python(tmp_path)
    assert "PYTHON" not in env
    report, completed = _run_fixture(adapter, out_dir, env)
    _assert_verified_no_key_report(adapter, report, out_dir, completed.stdout)


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_no_key_provider_adapter_runner_honors_explicit_python(tmp_path: Path, adapter: str) -> None:
    """PYTHON remains an explicit supported override for local review and CI reruns."""

    out_dir = tmp_path / f"{adapter}-explicit-python"
    env = _base_env()
    env["PYTHON"] = sys.executable
    report, completed = _run_fixture(adapter, out_dir, env)
    _assert_verified_no_key_report(adapter, report, out_dir, completed.stdout)


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_no_key_provider_adapter_runner_rejects_unsupported_explicit_python(tmp_path: Path, adapter: str) -> None:
    """Unsupported selected PYTHON must fail nonzero and avoid writing shareable evidence."""

    out_dir = tmp_path / f"{adapter}-unsupported-python"
    env = _base_env()
    env["PYTHON"] = str(_unsupported_python_shim(tmp_path))
    completed = subprocess.run(
        [str(_runner(adapter)), "--out-dir", str(out_dir), "--mission", str(MISSION)],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 66
    assert completed.stdout == ""
    assert "Ardur fixture requires Python >= 3.10" in completed.stderr
    assert "Set PYTHON to python3.10+" in completed.stderr
    assert not (out_dir / "report.json").exists()


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_no_key_provider_adapter_runner_reports_missing_default_dependencies(tmp_path: Path, adapter: str) -> None:
    """A supported default interpreter without Ardur dependencies must fail clearly."""

    out_dir = tmp_path / f"{adapter}-missing-dependencies"
    env = _env_with_path_missing_dependency_python(tmp_path)
    assert "PYTHON" not in env
    completed = subprocess.run(
        [str(_runner(adapter)), "--out-dir", str(out_dir), "--mission", str(MISSION)],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 65
    assert completed.stdout == ""
    assert "Ardur fixture dependencies are not installed" in completed.stderr
    assert "missing PyJWT" in completed.stderr
    assert "Run ./scripts/setup-dev.sh" in completed.stderr
    assert not (out_dir / "report.json").exists()

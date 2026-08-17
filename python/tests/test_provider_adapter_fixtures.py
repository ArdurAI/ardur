from __future__ import annotations

import json
import os
import shlex
import shutil
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


def _runner_without_repo_venv(tmp_path: Path, adapter: str) -> Path:
    """Copy a runner into an ephemeral repo root with no local virtualenv."""

    runner = tmp_path / "isolated-repo" / "examples" / adapter / "run.sh"
    runner.parent.mkdir(parents=True)
    shutil.copy(_runner(adapter), runner)
    return runner


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
    runner = _runner_without_repo_venv(tmp_path, adapter)
    isolated_repo_root = runner.parents[2]
    assert "PYTHON" not in env
    assert not (isolated_repo_root / "python" / ".venv").exists()
    completed = subprocess.run(
        [str(runner), "--out-dir", str(out_dir), "--mission", str(MISSION)],
        cwd=isolated_repo_root,
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

CLAUDE_PROJECT_MISSION = REPO_ROOT / "examples" / "missions" / "claude-project-context-no-key-mission.json"
CLAUDE_PROJECT_ADAPTER = "claude-code-projects"
CLAUDE_UNKNOWN_BOUNDARIES = {
    "provider_hidden_upload_internals",
    "provider_hidden_rag_internals",
    "sync_source_internals",
    "artifact_content_internals",
    "network_fetch_internals",
    "actual_provider_model_internals",
}
CLAUDE_METHODS = {"project_info", "project_read", "project_search", "project_write", "project_delete"}


def _run_claude_project_fixture(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    from vibap.provider_adapter_fixture import run_fixture

    out_dir = tmp_path / "claude-project-context"
    report = run_fixture(adapter_id=CLAUDE_PROJECT_ADAPTER, out_dir=out_dir, mission_path=CLAUDE_PROJECT_MISSION)
    return report, out_dir


def _host_events(report: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for call in report["visible_tool_calls"]:
        event = call.get("host_semantic_event")
        assert isinstance(event, dict)
        events.append(event)
    return events


def test_claude_project_context_fixture_report_shape_and_boundaries(tmp_path: Path) -> None:
    """Claude project context is modeled as no-key host-semantic evidence, not live Claude proof."""

    report, _out_dir = _run_claude_project_fixture(tmp_path)

    assert report["receipt_chain_verified"] is True
    assert report["receipt_count"] == 6
    assert report["policy_verdict_counts"] == {"allow": 6, "deny": 0, "unknown": 0}
    assert report["adapter"]["id"] == CLAUDE_PROJECT_ADAPTER
    assert report["adapter"]["visible_boundary"] == "Claude Code ProjectsInput and ProjectsOutput no-key semantic fixture"
    assert set(report["claude_project_context"]["host_semantic_methods"]) == CLAUDE_METHODS
    assert report["claude_project_context"]["claim_boundary"] == (
        "no-key/local fixture for Claude project-context source semantics; no live Claude claim"
    )
    assert report["claude_project_context"]["model_provenance"]["actual_provider_model"] == "unknown"
    assert report["claude_project_context"]["model_provenance"]["resolvedModel"] == "example-resolved-model-placeholder"
    assert "live Claude account/project mutation" in report["not_claimed"]
    assert "provider-side RAG or sync-source inspection" in report["not_claimed"]
    assert set(report["coverage_gaps"]).issuperset(CLAUDE_UNKNOWN_BOUNDARIES)


def test_claude_project_context_host_semantic_events_are_redacted_and_classified(tmp_path: Path) -> None:
    """Project read/write/search events keep provenance while stripping raw content and local paths."""

    report, _out_dir = _run_claude_project_fixture(tmp_path)
    events = _host_events(report)
    methods = {str(event["method"]) for event in events}

    assert methods == CLAUDE_METHODS
    for event in events:
        assert event["event_class"] == "host_semantic_event"
        assert event["evidence_class"] == ["policy_input", "session_context", "host_semantic_event"]
        assert set(event["unknown_boundaries"]) == CLAUDE_UNKNOWN_BOUNDARIES

    read_event = next(event for event in events if event["method"] == "project_read")
    read_output = read_event["host_reported_output"]
    assert read_output["content"]["content_present"] is True
    assert read_output["content"]["content_bytes"] == len("host-reported project note body".encode("utf-8"))
    assert "content_sha256" in read_output["content"]
    assert "host-reported project note body" not in json.dumps(read_output, sort_keys=True)
    assert read_output["local_file"]["redacted_path"] == "<OUTPUT_DIR>/host-local/project-read-result.md"
    assert read_output["local_file"]["path_visibility"] == "redacted_local_path"

    info_event = next(event for event in events if event["method"] == "project_info")
    sync_config = info_event["host_reported_output"]["sync_sources"][0]["config"]
    assert sync_config["redacted"] is True
    assert sync_config["config_visibility"] == "opaque_sync_config"
    assert "raw-config-value-that-must-not-leak" not in json.dumps(sync_config, sort_keys=True)


def test_claude_project_context_shareable_report_has_no_raw_local_or_project_content(tmp_path: Path) -> None:
    """Persisted shareable report must not leak local roots, raw project content, or opaque sync config."""

    report, out_dir = _run_claude_project_fixture(tmp_path)
    report_text = (out_dir / "report.json").read_text(encoding="utf-8")
    claims_text = (out_dir / "passport.claims.redacted.json").read_text(encoding="utf-8")
    combined = json.dumps(report, sort_keys=True) + report_text + claims_text

    forbidden = (
        str(out_dir),
        str(out_dir.resolve()),
        str(REPO_ROOT),
        "/Users/",
        "/private/",
        "raw-config-value-that-must-not-leak",
        "host-reported project note body",
        "inline host-supplied project context",
    )
    for marker in forbidden:
        assert marker not in combined
    assert "<OUTPUT_DIR>/host-local/project-upload-source.md" in combined
    assert "<OUTPUT_DIR>/host-local/project-read-result.md" in combined
    assert "<MISSION_TEMPLATE>" in combined


def test_claude_project_context_source_boundary_fields_do_not_invent_remote_trigger_version(
    tmp_path: Path,
) -> None:
    """Artifact/WebFetch provenance is distinct from RemoteTriggerOutput source metadata."""

    report, _out_dir = _run_claude_project_fixture(tmp_path)
    source_boundaries = report["claude_project_context"]["source_boundaries"]

    assert source_boundaries["artifact_output"] == {
        "source_type": "ArtifactOutput",
        "version": "artifact-version-placeholder",
        "boundary": "host-reported artifact version only",
    }
    assert source_boundaries["web_fetch_output"]["artifactRead"] == {
        "slug": "project-context-artifact-placeholder",
        "ver": "artifact-version-placeholder",
    }
    remote_trigger = source_boundaries["remote_trigger_output"]
    assert remote_trigger["fields_observed"] == ["status", "json", "summary"]
    assert remote_trigger["version_field_observed_by_version"] == {
        "2.1.175": False,
        "2.1.176": False,
        "2.1.177": False,
        "2.1.198": False,
    }
    assert remote_trigger["metadata_fields_observed_by_version"] == {
        "2.1.198": ["capabilities", "stored.contract", "stored.capabilities"]
    }
    assert remote_trigger["source_metadata_boundary"] == (
        "2.1.198 source surface exposes capabilities and stored contract metadata only; "
        "no live remote-trigger execution is claimed"
    )
    assert "version" not in remote_trigger


def test_claude_project_write_rejects_ambiguous_content_and_local_path(tmp_path: Path) -> None:
    """A project_write fixture cannot carry both inline content and local_path evidence."""

    from vibap.provider_adapter_fixture import normalize_claude_project_context_call

    with pytest.raises(ValueError, match="project_write.content and project_write.local_path are mutually exclusive"):
        normalize_claude_project_context_call(
            {
                "call_id": "bad-claude-project-write",
                "tool_name": "project_write",
                "arguments": {
                    "host_semantic_event": {
                        "method": "project_write",
                        "requested_input": {
                            "method": "project_write",
                            "path": "claude/ambiguous.md",
                            "content": "raw inline content",
                            "local_path": str(tmp_path / "ambiguous.md"),
                        },
                        "host_reported_output": {},
                    }
                },
            },
            roots={"OUTPUT_DIR": tmp_path},
        )


def test_out_dir_empty_string_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Empty --out-dir must produce a clean JSON error, no traceback, no CWD writes."""
    monkeypatch.chdir(tmp_path)

    from vibap.provider_adapter_fixture import main as fixture_main

    code = fixture_main(
        ["--adapter", "openai-agents-sdk", "--out-dir", "", "--mission", str(MISSION)]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert report["ok"] is False
    assert report["error"] == "provider_adapter_fixture_path_invalid"
    assert report["condition"] == "provider_adapter_fixture_out_dir_empty"
    assert "Traceback" not in captured.out
    assert not any(tmp_path.iterdir()), "no files written to CWD on empty --out-dir"


def test_out_dir_whitespace_only_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Whitespace-only --out-dir must produce a clean JSON error, no CWD writes."""
    monkeypatch.chdir(tmp_path)

    from vibap.provider_adapter_fixture import main as fixture_main

    code = fixture_main(
        ["--adapter", "openai-agents-sdk", "--out-dir", "   ", "--mission", str(MISSION)]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert report["ok"] is False
    assert report["error"] == "provider_adapter_fixture_path_invalid"
    assert report["condition"] == "provider_adapter_fixture_out_dir_empty"
    assert "Traceback" not in captured.out
    assert not any(p.name.strip() == "" or p.name == "   " for p in tmp_path.iterdir()), (
        "no whitespace-named dir created on whitespace-only --out-dir"
    )


def test_mission_empty_string_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Empty --mission must produce a clean JSON error, no traceback, no CWD writes."""
    from vibap.provider_adapter_fixture import main as fixture_main

    out_dir = tmp_path / "out"
    code = fixture_main(
        ["--adapter", "openai-agents-sdk", "--out-dir", str(out_dir), "--mission", ""]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert report["ok"] is False
    assert report["error"] == "provider_adapter_fixture_path_invalid"
    assert report["condition"] == "provider_adapter_fixture_mission_empty"
    assert "Traceback" not in captured.out
    assert not out_dir.exists(), "no output dir created on empty --mission"


def test_mission_whitespace_only_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Whitespace-only --mission must produce a clean JSON error, no traceback."""
    from vibap.provider_adapter_fixture import main as fixture_main

    out_dir = tmp_path / "out"
    code = fixture_main(
        ["--adapter", "openai-agents-sdk", "--out-dir", str(out_dir), "--mission", "   "]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert report["ok"] is False
    assert report["error"] == "provider_adapter_fixture_path_invalid"
    assert report["condition"] == "provider_adapter_fixture_mission_empty"
    assert "Traceback" not in captured.out
    assert not out_dir.exists(), "no output dir created on whitespace --mission"


def test_out_dir_empty_raises_specialized_error(tmp_path: Path) -> None:
    from vibap.provider_adapter_fixture import ProviderAdapterFixturePathError, run_fixture

    with pytest.raises(ProviderAdapterFixturePathError) as exc_info:
        run_fixture(
            adapter_id="openai-agents-sdk",
            out_dir="",
            mission_path=str(MISSION),
        )
    assert exc_info.value.condition == "provider_adapter_fixture_out_dir_empty"


def test_mission_empty_raises_specialized_error(tmp_path: Path) -> None:
    from vibap.provider_adapter_fixture import ProviderAdapterFixturePathError, run_fixture

    with pytest.raises(ProviderAdapterFixturePathError) as exc_info:
        run_fixture(
            adapter_id="openai-agents-sdk",
            out_dir=str(tmp_path / "out"),
            mission_path="",
        )
    assert exc_info.value.condition == "provider_adapter_fixture_mission_empty"

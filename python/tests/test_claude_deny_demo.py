from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SCRIPT = REPO_ROOT / "scripts" / "run-claude-deny-demo.py"


def _load_demo_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ardur_claude_deny_demo", DEMO_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_deny_output_requires_explicit_deny_and_reason() -> None:
    demo = _load_demo_module()

    reason = demo.validate_deny_output(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "ardur: blocked - forbidden tool: Bash",
            }
        }
    )

    assert reason == "ardur: blocked - forbidden tool: Bash"
    for malformed in (
        {},
        {"hookSpecificOutput": "invalid"},
        {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "permissionDecision": "deny",
            }
        },
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        },
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
            }
        },
    ):
        with pytest.raises(
            demo.DemoError, match="command not dispatched|human-readable"
        ):
            demo.validate_deny_output(malformed)


def test_filesystem_evidence_fails_on_canary_drift_or_marker(tmp_path: Path) -> None:
    demo = _load_demo_module()
    canary = tmp_path / "canary.txt"
    marker = tmp_path / "marker.txt"
    canary.write_text("original\n", encoding="utf-8")
    expected = demo._sha256(canary)

    assert demo.verify_filesystem_evidence(
        canary=canary, expected_sha256=expected, marker=marker
    ) == (True, True)

    canary.write_text("changed\n", encoding="utf-8")
    with pytest.raises(demo.DemoError, match="canary changed"):
        demo.verify_filesystem_evidence(
            canary=canary, expected_sha256=expected, marker=marker
        )

    canary.write_text("original\n", encoding="utf-8")
    marker.write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(demo.DemoError, match="marker exists"):
        demo.verify_filesystem_evidence(
            canary=canary, expected_sha256=expected, marker=marker
        )


def test_receipt_report_rejects_malformed_counts() -> None:
    demo = _load_demo_module()
    malformed_report = {
        "ok": True,
        "chain_verification": {"ok": True},
        "chain_count": 1,
        "receipt_count": "one",
        "totals": {
            "tools": {"Bash": 1},
            "verdicts": {"violation": 1},
            "violation_count": 1,
        },
    }

    with pytest.raises(demo.DemoError, match="invalid receipt count"):
        demo.validate_receipt_report(malformed_report)

    unrelated_aggregate = {
        "ok": True,
        "chain_verification": {"ok": True},
        "chain_count": 2,
        "receipt_count": 2,
        "totals": {
            "tools": {"Bash": 1, "Read": 1},
            "verdicts": {"allow": 1, "violation": 1},
            "violation_count": 1,
        },
    }
    with pytest.raises(demo.DemoError, match="exactly one receipt chain"):
        demo.validate_receipt_report(unrelated_aggregate)


def test_non_deny_output_fails_closed_and_cleans_temporary_state(
    tmp_path: Path,
) -> None:
    demo = _load_demo_module()
    labels: list[str] = []

    def fake_runner(
        command: list[str],
        *,
        label: str,
        cwd: Path,
        env: dict[str, str],
        deadline: float,
        stdin_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del command, cwd, env, deadline, stdin_payload
        labels.append(label)
        if label in {"profile setup", "Claude Code protection"}:
            return {"ok": True}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "unexpected permit",
            }
        }

    with pytest.raises(demo.DemoError, match="did not return an explicit deny"):
        demo.run_demo(
            repo_root=REPO_ROOT,
            timeout_s=10,
            temp_parent=tmp_path,
            command_runner=fake_runner,
        )

    assert labels == ["profile setup", "Claude Code protection", "PreToolUse denial"]
    assert list(tmp_path.iterdir()) == []


def test_real_demo_verifies_deny_receipt_filesystem_and_cleanup(tmp_path: Path) -> None:
    started = time.monotonic()
    result = subprocess.run(
        [
            sys.executable,
            str(DEMO_SCRIPT),
            "--timeout-s",
            "60",
            "--temp-parent",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        env=os.environ,
        capture_output=True,
        text=True,
        timeout=65,
        check=False,
    )
    elapsed_s = time.monotonic() - started

    assert result.returncode == 0, result.stdout + result.stderr
    assert elapsed_s < 60
    assert "PASS  Ardur returned DENY before host command dispatch" in result.stdout
    assert "PASS  canary digest is unchanged" in result.stdout
    assert "PASS  exfiltration marker is absent" in result.stdout
    assert "PASS  signed/hash-linked receipt chain verified" in result.stdout
    assert (
        "it is not independent process, kernel, network, or provider evidence"
        in result.stdout
    )
    assert (
        "Temporary keys, state, fixtures, and receipts were removed." in result.stdout
    )
    assert list(tmp_path.iterdir()) == []

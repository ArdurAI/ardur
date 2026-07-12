"""Provider-free proof for Ardur's personal action-firewall profile."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

from .shareable_redaction import redact_local_path_text


MAX_DEMO_SECONDS = 60.0
TRACE_ID = "personal-firewall-demo"


class PersonalFirewallDemoError(RuntimeError):
    """Fail-closed demo error safe to show without local path details."""


def _remaining(deadline: float, label: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PersonalFirewallDemoError(f"deadline expired before {label}")
    return remaining


def _run_json(
    command: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    deadline: float,
    label: str,
    stdin_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            input=json.dumps(stdin_payload) if stdin_payload is not None else None,
            capture_output=True,
            text=True,
            timeout=_remaining(deadline, label),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PersonalFirewallDemoError(f"{label} exceeded the demo deadline") from exc
    if result.returncode != 0:
        raise PersonalFirewallDemoError(f"{label} failed closed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PersonalFirewallDemoError(f"{label} returned malformed JSON") from exc
    if not isinstance(payload, dict):
        raise PersonalFirewallDemoError(f"{label} returned a non-object response")
    return payload


def _require_ok(payload: dict[str, Any], label: str) -> None:
    if payload.get("ok") is not True:
        raise PersonalFirewallDemoError(f"{label} did not complete")


def _hook_fixture(
    *,
    project: Path,
    tool_name: str,
    tool_input: dict[str, Any],
    suffix: str,
) -> dict[str, Any]:
    return {
        "session_id": "personal-firewall-demo-session",
        "transcript_path": str(project / "transcript.jsonl"),
        "cwd": str(project),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_use_id": f"personal-firewall-{suffix}",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }


def _require_native_prompt(payload: dict[str, Any]) -> None:
    if payload.get("continue") is not True:
        hook_output = payload.get("hookSpecificOutput")
        reason = (
            str(hook_output.get("permissionDecisionReason", "policy denied"))
            if isinstance(hook_output, dict)
            else "policy denied"
        )
        raise PersonalFirewallDemoError(
            f"safe local read was not permitted: {redact_local_path_text(reason)}"
        )
    hook_output = payload.get("hookSpecificOutput")
    if (
        isinstance(hook_output, dict)
        and hook_output.get("permissionDecision") == "allow"
    ):
        raise PersonalFirewallDemoError(
            "Ardur bypassed the agent's native permission flow"
        )


def _require_deny(payload: dict[str, Any], label: str) -> str:
    hook_output = payload.get("hookSpecificOutput")
    if (
        not isinstance(hook_output, dict)
        or hook_output.get("permissionDecision") != "deny"
    ):
        raise PersonalFirewallDemoError(f"{label} was not denied")
    reason = hook_output.get("permissionDecisionReason")
    if not isinstance(reason, str) or not reason.startswith("ardur: blocked"):
        raise PersonalFirewallDemoError(f"{label} deny omitted a readable reason")
    return redact_local_path_text(reason)


def _validate_report(report: dict[str, Any]) -> None:
    if (
        report.get("ok") is not True
        or report.get("chain_verification", {}).get("ok") is not True
    ):
        raise PersonalFirewallDemoError("signed receipt chain did not verify")
    if report.get("chain_count") != 1 or report.get("receipt_count") != 4:
        raise PersonalFirewallDemoError(
            "receipt report did not contain four demo decisions"
        )
    totals = report.get("totals", {})
    if totals.get("verdicts") != {"compliant": 1, "violation": 3}:
        raise PersonalFirewallDemoError("receipt report verdict counts are incorrect")
    actions = report.get("chains", [{}])[0].get("actions", [])
    if len(actions) != 4:
        raise PersonalFirewallDemoError(
            "receipt report omitted readable action summaries"
        )
    secret_action = actions[2]
    if not any(
        policy.get("backend") == "forbid_rules" and policy.get("decision") == "Deny"
        for policy in secret_action.get("policies", [])
    ):
        raise PersonalFirewallDemoError(
            "secret-like request did not exercise forbid rules"
        )


def run_personal_firewall_demo(
    *,
    timeout_s: float = MAX_DEMO_SECONDS,
    temp_parent: Path | None = None,
    emit: bool = True,
) -> dict[str, Any]:
    if not 0 < timeout_s <= MAX_DEMO_SECONDS:
        raise PersonalFirewallDemoError(
            f"timeout must be greater than zero and at most {MAX_DEMO_SECONDS:g} seconds"
        )
    if temp_parent is not None and not temp_parent.is_dir():
        raise PersonalFirewallDemoError(
            "temporary parent must be an existing directory"
        )

    started = time.monotonic()
    deadline = started + timeout_s
    cli = [sys.executable, "-m", "vibap.cli"]
    temp_root: Path | None = None

    with tempfile.TemporaryDirectory(
        prefix="ardur-personal-firewall-",
        dir=str(temp_parent) if temp_parent is not None else None,
    ) as temp_root_text:
        temp_root = Path(temp_root_text).resolve()
        project = temp_root / "project"
        home = temp_root / "ardur-home"
        keys = home / "keys"
        profile = project / "ARDUR.md"
        outside_target = temp_root / "outside-workspace.txt"
        secret_target = project / "secret-like.txt"
        project.mkdir()
        safe_file = project / "README.md"
        safe_file.write_text("local personal firewall fixture\n", encoding="utf-8")

        env = os.environ.copy()
        env.pop("ARDUR_MISSION_PASSPORT", None)
        env["VIBAP_HOME"] = str(home)
        env["ARDUR_CC_HOOK_DIR"] = str(home / "claude-code-hook")
        env["ARDUR_TRACE_ID"] = TRACE_ID

        profile_result = _run_json(
            [
                *cli,
                "profile",
                "init",
                "--template",
                "personal-firewall",
                "--path",
                str(profile),
                "--json",
            ],
            cwd=project,
            env=env,
            deadline=deadline,
            label="personal profile setup",
        )
        _require_ok(profile_result, "personal profile setup")
        protect_result = _run_json(
            [
                *cli,
                "protect",
                "claude-code",
                "--profile",
                str(profile),
                "--home",
                str(home),
                "--keys-dir",
                str(keys),
                "--agent-id",
                "demo:personal-firewall",
                "--json",
            ],
            cwd=project,
            env=env,
            deadline=deadline,
            label="personal firewall activation",
        )
        _require_ok(protect_result, "personal firewall activation")

        safe_read = _run_json(
            [*cli, "claude-code-hook", "pre", "--keys-dir", str(keys)],
            cwd=project,
            env=env,
            deadline=deadline,
            label="safe read decision",
            stdin_payload=_hook_fixture(
                project=project,
                tool_name="Read",
                tool_input={"file_path": str(safe_file)},
                suffix="safe-read",
            ),
        )
        _require_native_prompt(safe_read)

        outside_write = _run_json(
            [*cli, "claude-code-hook", "pre", "--keys-dir", str(keys)],
            cwd=project,
            env=env,
            deadline=deadline,
            label="outside-workspace write decision",
            stdin_payload=_hook_fixture(
                project=project,
                tool_name="Write",
                tool_input={"file_path": str(outside_target), "content": "blocked\n"},
                suffix="outside-write",
            ),
        )
        _require_deny(outside_write, "outside-workspace write")
        outside_reason = "outside the configured workspace scope"

        secret_write = _run_json(
            [*cli, "claude-code-hook", "pre", "--keys-dir", str(keys)],
            cwd=project,
            env=env,
            deadline=deadline,
            label="secret-like write decision",
            stdin_payload=_hook_fixture(
                project=project,
                tool_name="Write",
                tool_input={
                    "file_path": str(secret_target),
                    "content": "api_key=synthetic-demo-value\n",
                },
                suffix="secret-write",
            ),
        )
        _require_deny(secret_write, "secret-like write")
        secret_reason = "matched the personal secret-like argument policy"

        network_call = _run_json(
            [*cli, "claude-code-hook", "pre", "--keys-dir", str(keys)],
            cwd=project,
            env=env,
            deadline=deadline,
            label="network decision",
            stdin_payload=_hook_fixture(
                project=project,
                tool_name="WebFetch",
                tool_input={
                    "url": "https://example.invalid/collect",
                    "prompt": "send data",
                },
                suffix="network",
            ),
        )
        _require_deny(network_call, "external network request")
        network_reason = "external network tools are disabled by default"

        if outside_target.exists() or secret_target.exists():
            raise PersonalFirewallDemoError("a denied write reached the filesystem")

        report = _run_json(
            [
                *cli,
                "claude-code-report",
                "--home",
                str(home),
                "--keys-dir",
                str(keys),
                "--json",
            ],
            cwd=project,
            env=env,
            deadline=deadline,
            label="receipt verification",
        )
        _validate_report(report)

    if temp_root is None or temp_root.exists():
        raise PersonalFirewallDemoError("temporary demo state was not removed")
    elapsed_s = time.monotonic() - started
    result = {
        "ok": True,
        "schema_version": "ardur.personal_firewall_demo.v0.1",
        "elapsed_s": round(elapsed_s, 3),
        "decisions": [
            {
                "request": "workspace read",
                "result": "ASK",
                "detail": "native permission flow remains in charge",
            },
            {
                "request": "outside-workspace write",
                "result": "DENY",
                "detail": outside_reason,
            },
            {
                "request": "secret-like argument",
                "result": "DENY",
                "detail": secret_reason,
            },
            {"request": "external network", "result": "DENY", "detail": network_reason},
        ],
        "receipts": {
            "count": 4,
            "chains": 1,
            "verified": True,
            "readable_summaries": True,
        },
        "cost_boundary": report["cost_boundary"],
        "verification": report["verification"],
        "temporary_state_removed": True,
        "evidence_boundary": (
            "configured local Claude Code tool-boundary proof; not provider-hidden, "
            "kernel, universal secret-detection, or monetary-cost evidence"
        ),
    }
    if emit:
        print("Ardur personal action firewall")
        for decision in result["decisions"]:
            print(
                f"{decision['result']:4}  {decision['request']}: {decision['detail']}"
            )
        print("PASS  four signed decisions verified in one hash-linked receipt chain")
        print(f"COST  {result['cost_boundary']['detail']}")
        print(f"VERIFY  {result['verification']['command']}")
        print(f"BOUNDARY  {result['evidence_boundary']}")
    return result

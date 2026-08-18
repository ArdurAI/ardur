"""Security contract for Claude Code child-passport binding."""

from __future__ import annotations

import json
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import jwt

from vibap.claude_code_hook import (
    handle_post_tool_use,
    handle_post_tool_use_failure,
    handle_pre_tool_use,
    handle_subagent_start,
    handle_subagent_stop,
)
from vibap.passport import MissionPassport, generate_keypair, issue_passport


CHILD_POLICY_ENV_VAR = "ARDUR_CC_CHILD_POLICY_FILE"
CHILD_POLICY_SCHEMA = "ardur.claude_code.child_policies.v1"


def _deny_reason(output: dict[str, Any]) -> str:
    hook_output = output["hookSpecificOutput"]
    assert hook_output["hookEventName"] == "PreToolUse"
    assert hook_output["permissionDecision"] == "deny"
    return str(hook_output["permissionDecisionReason"])


def _write_policy(
    path: Path,
    *,
    agent_type: str = "Explore",
    allowed_tools: tuple[str, ...] = ("Read",),
    max_tool_calls: int = 2,
    ttl_s: int = 120,
) -> None:
    policy = {
        "schema_version": CHILD_POLICY_SCHEMA,
        "agent_types": {
            agent_type: {
                "child_agent_id": f"claude-code:{agent_type.lower()}",
                "mission": f"perform bounded {agent_type} work",
                "allowed_tools": list(allowed_tools),
                "resource_scope": [str(path.parent), f"{path.parent}/*"],
                "max_tool_calls": max_tool_calls,
                "ttl_s": ttl_s,
            }
        },
    }
    path.write_text(json.dumps(policy), encoding="utf-8")
    path.chmod(0o600)


def _write_multi_type_policy(
    path: Path,
    agent_tools: dict[str, tuple[str, ...]],
) -> None:
    policy = {
        "schema_version": CHILD_POLICY_SCHEMA,
        "agent_types": {
            agent_type: {
                "child_agent_id": f"claude-code:{agent_type.lower()}",
                "mission": f"perform bounded {agent_type} work",
                "allowed_tools": list(allowed_tools),
                "resource_scope": [str(path.parent), f"{path.parent}/*"],
                "max_tool_calls": 3,
                "ttl_s": 120,
            }
            for agent_type, allowed_tools in agent_tools.items()
        },
    }
    path.write_text(json.dumps(policy), encoding="utf-8")
    path.chmod(0o600)


def _configure_runtime(
    tmp_path: Path,
    monkeypatch,
    *,
    parent_max_tool_calls: int = 12,
    write_policy: bool = True,
    child_allowed_tools: tuple[str, ...] = ("Read",),
    child_max_tool_calls: int = 2,
    child_ttl_s: int = 120,
    delegation_allowed: bool = True,
) -> tuple[Path, Path]:
    home = tmp_path / "home"
    keys = home / "keys"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    private_key, _public_key = generate_keypair(keys_dir=keys)
    mission = MissionPassport(
        agent_id="claude-parent",
        mission="coordinate governed Claude children",
        allowed_tools=["Agent", "Task", "Read", "Write"],
        resource_scope=[str(workspace), f"{workspace}/*"],
        cwd=str(workspace),
        max_tool_calls=parent_max_tool_calls,
        max_duration_s=600,
        delegation_allowed=delegation_allowed,
        max_delegation_depth=1 if delegation_allowed else 0,
    )
    token = issue_passport(mission, private_key, ttl_s=600)
    policy_file = workspace / "child-policies.json"
    if write_policy:
        _write_policy(
            policy_file,
            allowed_tools=child_allowed_tools,
            max_tool_calls=child_max_tool_calls,
            ttl_s=child_ttl_s,
        )
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(home / "chains"))
    monkeypatch.setenv("ARDUR_TRACE_ID", "claude-child-binding")
    monkeypatch.setenv("VIBAP_HOME", str(home))
    monkeypatch.setenv(CHILD_POLICY_ENV_VAR, str(policy_file))
    return keys, workspace


def _agent_pre(*, tool_use_id: str, agent_type: str = "Explore") -> dict[str, Any]:
    return {
        "session_id": "claude-session-1",
        "hook_event_name": "PreToolUse",
        "tool_name": "Agent",
        "tool_use_id": tool_use_id,
        "tool_input": {
            "description": "prompt-sentinel-must-not-authorize",
            "prompt": "secret-prompt-sentinel-must-not-persist",
            "subagent_type": agent_type,
        },
    }


def _child_pre(
    *,
    agent_id: str,
    tool_use_id: str,
    tool_name: str,
    tool_input: dict[str, Any],
) -> dict[str, Any]:
    return {
        "session_id": "claude-session-1",
        "hook_event_name": "PreToolUse",
        "agent_id": agent_id,
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "tool_input": tool_input,
    }


def _start(
    *, agent_id: str | None, agent_type: str = "Explore", root: Path | None = None
):
    payload: dict[str, Any] = {
        "session_id": "claude-session-1",
        "hook_event_name": "SubagentStart",
        "agent_type": agent_type,
    }
    if agent_id is not None:
        payload["agent_id"] = agent_id
    if root is not None:
        payload.update(
            {
                "cwd": str(root / "host-private-cwd"),
                "transcript_path": str(root / "parent-private.jsonl"),
                "agent_transcript_path": str(root / "child-private.jsonl"),
            }
        )
    return payload


def _stop(
    *, agent_id: str | None, agent_type: str = "Explore", root: Path | None = None
):
    payload = _start(agent_id=agent_id, agent_type=agent_type, root=root)
    payload["hook_event_name"] = "SubagentStop"
    payload["last_assistant_message"] = "secret-final-message"
    return payload


def test_agent_without_operator_policy_is_denied_before_spawn(tmp_path, monkeypatch):
    keys, _workspace = _configure_runtime(tmp_path, monkeypatch, write_policy=False)

    output = handle_pre_tool_use(
        _agent_pre(tool_use_id="agent-no-policy"), keys_dir=keys
    )

    assert "child policy" in _deny_reason(output).lower()
    start = handle_subagent_start(_start(agent_id="no-policy-child"), keys_dir=keys)
    assert "not bound" in start["hookSpecificOutput"]["additionalContext"].lower()


def test_bound_child_uses_attenuated_policy_and_never_parent_fallback(
    tmp_path, monkeypatch
):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    agent_output = handle_pre_tool_use(
        _agent_pre(tool_use_id="agent-reservation-1"), keys_dir=keys
    )
    assert agent_output["continue"] is True

    start_output = handle_subagent_start(
        _start(agent_id="claude-child-1"), keys_dir=keys
    )
    context = start_output["hookSpecificOutput"]["additionalContext"]
    assert "ardur_child_" in context

    parent_only = handle_pre_tool_use(
        _child_pre(
            agent_id="claude-child-1",
            tool_use_id="child-write-1",
            tool_name="Write",
            tool_input={
                "file_path": str(workspace / "must-not-exist.txt"),
                "content": "x",
            },
        ),
        keys_dir=keys,
    )
    assert "Write" in _deny_reason(parent_only)
    assert not (workspace / "must-not-exist.txt").exists()

    child_read_input = _child_pre(
        agent_id="claude-child-1",
        tool_use_id="child-read-1",
        tool_name="Read",
        tool_input={"file_path": str(workspace / "README.md")},
    )
    permitted = handle_pre_tool_use(child_read_input, keys_dir=keys)
    assert permitted["continue"] is True
    post = dict(child_read_input)
    post["hook_event_name"] = "PostToolUse"
    post["tool_response"] = {"content": "bounded"}
    assert handle_post_tool_use(post, keys_dir=keys) == {"continue": True}

    assert handle_subagent_stop(_stop(agent_id="claude-child-1"), keys_dir=keys) == {
        "continue": True
    }
    closed = handle_pre_tool_use(
        _child_pre(
            agent_id="claude-child-1",
            tool_use_id="child-read-after-stop",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "closed" in _deny_reason(closed).lower()


def test_parent_call_remains_governed_while_child_is_bound(tmp_path, monkeypatch):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    assert (
        handle_pre_tool_use(
            _agent_pre(tool_use_id="agent-parent-compatible"), keys_dir=keys
        )["continue"]
        is True
    )
    handle_subagent_start(
        _start(agent_id="claude-child-parent-compatible"), keys_dir=keys
    )

    parent_read = handle_pre_tool_use(
        {
            "session_id": "claude-session-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "parent-read-1",
            "tool_input": {"file_path": str(workspace / "README.md")},
        },
        keys_dir=keys,
    )

    assert parent_read["continue"] is True


def test_agent_reservation_accounts_for_spawn_call_before_child_budget(
    tmp_path, monkeypatch
):
    keys, _workspace = _configure_runtime(
        tmp_path,
        monkeypatch,
        parent_max_tool_calls=3,
        child_max_tool_calls=3,
    )

    output = handle_pre_tool_use(
        _agent_pre(tool_use_id="agent-over-reserve"), keys_dir=keys
    )

    assert "budget" in _deny_reason(output).lower()
    start = handle_subagent_start(_start(agent_id="over-budget-child"), keys_dir=keys)
    assert "not bound" in start["hookSpecificOutput"]["additionalContext"].lower()


def test_agent_spawn_is_denied_when_parent_delegation_depth_is_disabled(
    tmp_path, monkeypatch
):
    keys, _workspace = _configure_runtime(
        tmp_path,
        monkeypatch,
        delegation_allowed=False,
    )

    output = handle_pre_tool_use(
        _agent_pre(tool_use_id="agent-no-delegation-depth"), keys_dir=keys
    )

    assert "attenuated" in _deny_reason(output).lower()
    start = handle_subagent_start(_start(agent_id="no-depth-child"), keys_dir=keys)
    assert "not bound" in start["hookSpecificOutput"]["additionalContext"].lower()


def test_duplicate_agent_pretool_reuses_one_reservation_without_authority_replay(
    tmp_path, monkeypatch
):
    keys, _workspace = _configure_runtime(tmp_path, monkeypatch)
    dispatch = _agent_pre(tool_use_id="agent-replayed-pretool")

    assert handle_pre_tool_use(dispatch, keys_dir=keys)["continue"] is True
    assert handle_pre_tool_use(dispatch, keys_dir=keys)["continue"] is True

    binding_file = next((tmp_path / "home" / "chains").rglob("child-bindings.json"))
    binding_state = json.loads(binding_file.read_text(encoding="utf-8"))
    assert len(binding_state["reservations"]) == 1
    bound = handle_subagent_start(
        _start(agent_id="replayed-pretool-child"), keys_dir=keys
    )
    assert "ardur_child_" in bound["hookSpecificOutput"]["additionalContext"]
    duplicate_child = handle_subagent_start(
        _start(agent_id="replayed-pretool-extra-child"), keys_dir=keys
    )
    assert (
        "not bound"
        in duplicate_child["hookSpecificOutput"]["additionalContext"].lower()
    )


def test_unreserved_or_replayed_child_identity_never_adopts_parent_authority(
    tmp_path, monkeypatch
):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    start_output = handle_subagent_start(
        _start(agent_id="unreserved-child"), keys_dir=keys
    )
    assert (
        "not bound" in start_output["hookSpecificOutput"]["additionalContext"].lower()
    )

    denied = handle_pre_tool_use(
        _child_pre(
            agent_id="unreserved-child",
            tool_use_id="unreserved-read",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "child binding" in _deny_reason(denied).lower()
    receipt_file = next((tmp_path / "home" / "chains").rglob("receipts.jsonl"))
    claims = jwt.decode(
        receipt_file.read_text(encoding="utf-8").splitlines()[-1],
        options={"verify_signature": False},
    )
    metadata = claims["measurements"]["claude_code"]
    assert metadata["attribution"]["mode"] == "trace_only"
    assert metadata["authority_binding"]["binding_state"] == "unbound"


def test_parallel_same_type_equivalent_reservations_bind_without_authority_swap(
    tmp_path, monkeypatch
):
    keys, _workspace = _configure_runtime(tmp_path, monkeypatch)
    for tool_use_id in ("agent-parallel-a", "agent-parallel-b"):
        assert (
            handle_pre_tool_use(_agent_pre(tool_use_id=tool_use_id), keys_dir=keys)[
                "continue"
            ]
            is True
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                handle_subagent_start,
                _start(agent_id=agent_id),
                keys_dir=keys,
            )
            for agent_id in ("parallel-child-a", "parallel-child-b")
        ]
        outputs = [future.result(timeout=10) for future in futures]
    first_context = outputs[0]["hookSpecificOutput"]["additionalContext"]
    second_context = outputs[1]["hookSpecificOutput"]["additionalContext"]

    assert "ardur_child_" in first_context
    assert "ardur_child_" in second_context
    assert first_context != second_context


def test_parallel_different_type_starts_never_swap_child_authority(
    tmp_path, monkeypatch
):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    policy_file = Path(__import__("os").environ[CHILD_POLICY_ENV_VAR])
    _write_multi_type_policy(
        policy_file,
        {
            "Explore": ("Read",),
            "Plan": ("Write",),
        },
    )
    assert (
        handle_pre_tool_use(
            _agent_pre(tool_use_id="agent-explore", agent_type="Explore"),
            keys_dir=keys,
        )["continue"]
        is True
    )
    assert (
        handle_pre_tool_use(
            _agent_pre(tool_use_id="agent-plan", agent_type="Plan"),
            keys_dir=keys,
        )["continue"]
        is True
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        starts = [
            pool.submit(
                handle_subagent_start,
                _start(agent_id="different-explore", agent_type="Explore"),
                keys_dir=keys,
            ),
            pool.submit(
                handle_subagent_start,
                _start(agent_id="different-plan", agent_type="Plan"),
                keys_dir=keys,
            ),
        ]
        contexts = [
            future.result(timeout=10)["hookSpecificOutput"]["additionalContext"]
            for future in starts
        ]
    assert all("ardur_child_" in context for context in contexts)
    assert contexts[0] != contexts[1]

    explore_write = handle_pre_tool_use(
        _child_pre(
            agent_id="different-explore",
            tool_use_id="different-explore-write",
            tool_name="Write",
            tool_input={"file_path": str(workspace / "explore.txt"), "content": "x"},
        ),
        keys_dir=keys,
    )
    plan_read = handle_pre_tool_use(
        _child_pre(
            agent_id="different-plan",
            tool_use_id="different-plan-read",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "Write" in _deny_reason(explore_write)
    assert "Read" in _deny_reason(plan_read)

    allowed_calls = [
        _child_pre(
            agent_id="different-explore",
            tool_use_id="different-explore-read",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        _child_pre(
            agent_id="different-plan",
            tool_use_id="different-plan-write",
            tool_name="Write",
            tool_input={"file_path": str(workspace / "plan.txt"), "content": "x"},
        ),
    ]
    for child_call in allowed_calls:
        assert handle_pre_tool_use(child_call, keys_dir=keys)["continue"] is True
        post = dict(child_call)
        post["hook_event_name"] = "PostToolUse"
        post["tool_response"] = {"ok": True}
        assert handle_post_tool_use(post, keys_dir=keys) == {"continue": True}


def test_same_type_policy_change_is_ambiguous_and_quarantined(tmp_path, monkeypatch):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    policy_file = Path(__import__("os").environ[CHILD_POLICY_ENV_VAR])
    assert (
        handle_pre_tool_use(_agent_pre(tool_use_id="agent-policy-a"), keys_dir=keys)[
            "continue"
        ]
        is True
    )
    _write_policy(policy_file, allowed_tools=("Write",))
    assert (
        handle_pre_tool_use(_agent_pre(tool_use_id="agent-policy-b"), keys_dir=keys)[
            "continue"
        ]
        is True
    )

    start_output = handle_subagent_start(
        _start(agent_id="ambiguous-child"), keys_dir=keys
    )
    assert (
        "ambiguous" in start_output["hookSpecificOutput"]["additionalContext"].lower()
    )
    denied = handle_pre_tool_use(
        _child_pre(
            agent_id="ambiguous-child",
            tool_use_id="ambiguous-read",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "child binding" in _deny_reason(denied).lower()


def test_missing_agent_id_taints_trace_instead_of_falling_back_to_parent(
    tmp_path, monkeypatch
):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    assert (
        handle_pre_tool_use(_agent_pre(tool_use_id="agent-missing-id"), keys_dir=keys)[
            "continue"
        ]
        is True
    )

    start_output = handle_subagent_start(_start(agent_id=None), keys_dir=keys)
    assert "missing agent_id" in start_output["hookSpecificOutput"]["additionalContext"]
    ambiguous_parent_shaped_event = handle_pre_tool_use(
        {
            "session_id": "claude-session-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "agentless-after-unbound-start",
            "tool_input": {"file_path": str(workspace / "README.md")},
        },
        keys_dir=keys,
    )
    assert "unbound child" in _deny_reason(ambiguous_parent_shaped_event).lower()


def test_child_policy_registry_rejects_wildcard_nested_authority(tmp_path):
    from vibap.claude_code_children import (
        ClaudeChildBindingError,
        load_claude_child_policy_registry,
    )

    policy_file = tmp_path / "child-policies.json"
    _write_policy(policy_file, allowed_tools=("*",))

    try:
        load_claude_child_policy_registry(policy_file)
    except ClaudeChildBindingError as exc:
        assert exc.code == "CHILD_POLICY_INVALID"
    else:
        raise AssertionError("wildcard child policy must fail closed")


def test_unknown_failed_operation_quarantines_bound_child(tmp_path, monkeypatch):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    assert (
        handle_pre_tool_use(_agent_pre(tool_use_id="agent-failure-gap"), keys_dir=keys)[
            "continue"
        ]
        is True
    )
    handle_subagent_start(_start(agent_id="failed-child"), keys_dir=keys)

    handle_post_tool_use_failure(
        {
            "session_id": "claude-session-1",
            "hook_event_name": "PostToolUseFailure",
            "agent_id": "failed-child",
            "tool_name": "Read",
            "tool_use_id": "unknown-operation",
            "tool_input": {"file_path": str(workspace / "README.md")},
            "error": "tool failed",
            "is_interrupt": False,
        },
        keys_dir=keys,
    )

    denied = handle_pre_tool_use(
        _child_pre(
            agent_id="failed-child",
            tool_use_id="after-unknown-failure",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "quarantined" in _deny_reason(denied).lower()


def test_bound_child_missing_tool_use_id_is_evidenced_and_quarantined(
    tmp_path, monkeypatch
):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    assert (
        handle_pre_tool_use(
            _agent_pre(tool_use_id="agent-missing-operation"), keys_dir=keys
        )["continue"]
        is True
    )
    handle_subagent_start(_start(agent_id="missing-operation-child"), keys_dir=keys)

    denied = handle_pre_tool_use(
        {
            **_child_pre(
                agent_id="missing-operation-child",
                tool_use_id="placeholder",
                tool_name="Read",
                tool_input={"file_path": str(workspace / "README.md")},
            ),
            "tool_use_id": "",
        },
        keys_dir=keys,
    )
    assert "tool_use_id" in _deny_reason(denied)

    receipt_file = next((tmp_path / "home" / "chains").rglob("receipts.jsonl"))
    receipt_claims = [
        jwt.decode(line, options={"verify_signature": False})
        for line in receipt_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert receipt_claims[-1]["verdict"] == "violation"
    assert (
        receipt_claims[-1]["measurements"]["claude_code"]["authority_binding"][
            "binding_state"
        ]
        == "quarantined"
    )

    replay = handle_pre_tool_use(
        _child_pre(
            agent_id="missing-operation-child",
            tool_use_id="after-missing-operation",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "quarantined" in _deny_reason(replay).lower()


def test_stop_before_start_and_duplicate_stop_are_monotonic(tmp_path, monkeypatch):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    assert (
        handle_pre_tool_use(_agent_pre(tool_use_id="agent-stop-order"), keys_dir=keys)[
            "continue"
        ]
        is True
    )
    assert handle_subagent_stop(_stop(agent_id="stop-before-start"), keys_dir=keys) == {
        "continue": True
    }
    start_output = handle_subagent_start(
        _start(agent_id="stop-before-start"), keys_dir=keys
    )
    assert (
        "not bound" in start_output["hookSpecificOutput"]["additionalContext"].lower()
    )

    assert (
        handle_pre_tool_use(
            _agent_pre(tool_use_id="agent-duplicate-stop"), keys_dir=keys
        )["continue"]
        is True
    )
    handle_subagent_start(_start(agent_id="duplicate-stop-child"), keys_dir=keys)
    assert handle_subagent_stop(
        _stop(agent_id="duplicate-stop-child"), keys_dir=keys
    ) == {"continue": True}
    assert handle_subagent_stop(
        _stop(agent_id="duplicate-stop-child"), keys_dir=keys
    ) == {"continue": True}
    denied = handle_pre_tool_use(
        _child_pre(
            agent_id="duplicate-stop-child",
            tool_use_id="duplicate-stop-read",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "closed" in _deny_reason(denied).lower()


def test_expired_pending_reservation_does_not_bind_after_restart(tmp_path, monkeypatch):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch, child_ttl_s=1)
    assert (
        handle_pre_tool_use(_agent_pre(tool_use_id="agent-expiring"), keys_dir=keys)[
            "continue"
        ]
        is True
    )
    time.sleep(1.1)

    start_output = handle_subagent_start(
        _start(agent_id="expired-child"), keys_dir=keys
    )
    assert "expired" in start_output["hookSpecificOutput"]["additionalContext"].lower()
    denied = handle_pre_tool_use(
        _child_pre(
            agent_id="expired-child",
            tool_use_id="expired-read",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "child binding" in _deny_reason(denied).lower()


def test_bound_child_without_stop_expires_fail_closed_after_restart(
    tmp_path, monkeypatch
):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch, child_ttl_s=1)
    assert (
        handle_pre_tool_use(
            _agent_pre(tool_use_id="agent-bound-timeout"), keys_dir=keys
        )["continue"]
        is True
    )
    handle_subagent_start(_start(agent_id="bound-timeout-child"), keys_dir=keys)
    time.sleep(1.1)

    denied = handle_pre_tool_use(
        _child_pre(
            agent_id="bound-timeout-child",
            tool_use_id="bound-timeout-read",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )

    assert "expired" in _deny_reason(denied).lower()


def test_lifecycle_evidence_has_enforced_states_without_sensitive_inputs(
    tmp_path, monkeypatch
):
    keys, _workspace = _configure_runtime(tmp_path, monkeypatch)
    assert (
        handle_pre_tool_use(
            _agent_pre(tool_use_id="agent-private-evidence"), keys_dir=keys
        )["continue"]
        is True
    )
    handle_subagent_start(
        _start(agent_id="private-child", root=tmp_path), keys_dir=keys
    )
    handle_subagent_stop(_stop(agent_id="private-child", root=tmp_path), keys_dir=keys)

    receipt_file = next((tmp_path / "home" / "chains").rglob("receipts.jsonl"))
    claims = [
        jwt.decode(line, options={"verify_signature": False})
        for line in receipt_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    receipt_evidence = json.dumps(claims, sort_keys=True)
    assert "secret-prompt-sentinel" not in receipt_evidence
    assert "prompt-sentinel-must-not-authorize" not in receipt_evidence
    lifecycle = [
        item for item in claims if item["tool"] in {"SubagentStart", "SubagentStop"}
    ]
    assert len(lifecycle) == 2
    encoded = json.dumps(lifecycle, sort_keys=True)
    assert "binding_state" in encoded
    assert "inherited_policy" not in encoded
    assert "secret-prompt-sentinel" not in encoded
    assert "secret-final-message" not in encoded
    assert str(tmp_path) not in encoded
    assert "transcript_path" not in encoded
    assert "cwd" not in encoded
    assert "passport_token" not in encoded
    assert "child_token" not in encoded

    state_files = list((tmp_path / "home" / "chains").rglob("child-bindings.json"))
    assert len(state_files) == 1
    assert stat.S_IMODE(state_files[0].stat().st_mode) == 0o600
    durable_text = state_files[0].read_text(encoding="utf-8")
    assert "secret-prompt-sentinel" not in durable_text
    assert "secret-final-message" not in durable_text
    assert str(tmp_path) not in durable_text


def test_failed_bound_child_tool_is_quarantined_without_persisting_error(
    tmp_path, monkeypatch
):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    assert (
        handle_pre_tool_use(_agent_pre(tool_use_id="agent-failed-tool"), keys_dir=keys)[
            "continue"
        ]
        is True
    )
    handle_subagent_start(_start(agent_id="failed-tool-child"), keys_dir=keys)
    child_call = _child_pre(
        agent_id="failed-tool-child",
        tool_use_id="child-read-failure",
        tool_name="Read",
        tool_input={"file_path": str(workspace / "README.md")},
    )
    assert handle_pre_tool_use(child_call, keys_dir=keys)["continue"] is True
    secret_error = f"failed while reading {tmp_path}/host-secret: token=do-not-store"
    failure = dict(child_call)
    failure.update(
        {
            "hook_event_name": "PostToolUseFailure",
            "error": secret_error,
            "is_interrupt": False,
            "duration_ms": 42,
        }
    )

    output = handle_post_tool_use_failure(failure, keys_dir=keys)

    assert output["hookSpecificOutput"]["hookEventName"] == "PostToolUseFailure"
    denied = handle_pre_tool_use(
        _child_pre(
            agent_id="failed-tool-child",
            tool_use_id="child-read-after-failure",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )
    assert "quarantined" in _deny_reason(denied).lower()
    receipt_file = next((tmp_path / "home" / "chains").rglob("receipts.jsonl"))
    receipt_text = receipt_file.read_text(encoding="utf-8")
    assert secret_error not in receipt_text
    failure_evidence = json.dumps(
        [
            jwt.decode(line, options={"verify_signature": False})
            for line in receipt_text.splitlines()
            if line.strip()
            and jwt.decode(line, options={"verify_signature": False})["tool"] == "Read"
            and jwt.decode(line, options={"verify_signature": False})[
                "step_id"
            ].endswith(":post-failure")
        ],
        sort_keys=True,
    )
    assert "host-secret" not in failure_evidence
    assert "do-not-store" not in failure_evidence


def test_malformed_binding_reverse_index_fails_closed_before_tool_execution(
    tmp_path, monkeypatch
):
    keys, workspace = _configure_runtime(tmp_path, monkeypatch)
    assert (
        handle_pre_tool_use(
            _agent_pre(tool_use_id="agent-corrupt-state"), keys_dir=keys
        )["continue"]
        is True
    )
    handle_subagent_start(_start(agent_id="corrupt-state-child"), keys_dir=keys)
    binding_file = next((tmp_path / "home" / "chains").rglob("child-bindings.json"))
    binding_state = json.loads(binding_file.read_text(encoding="utf-8"))
    request_key = next(iter(binding_state["reservations"]))
    binding_state["reservations"][request_key]["binding_key"] = "0" * 64
    binding_file.write_text(json.dumps(binding_state), encoding="utf-8")
    binding_file.chmod(0o600)

    output = handle_pre_tool_use(
        _child_pre(
            agent_id="corrupt-state-child",
            tool_use_id="corrupt-state-read",
            tool_name="Read",
            tool_input={"file_path": str(workspace / "README.md")},
        ),
        keys_dir=keys,
    )

    assert "deny" == output["hookSpecificOutput"]["permissionDecision"]
    assert "receipt chain is unavailable" in _deny_reason(output)

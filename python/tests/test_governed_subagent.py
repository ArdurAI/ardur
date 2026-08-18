from __future__ import annotations

import asyncio
import json
import re
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.governed_subagent import (
    GovernedSubagentAdapter,
    GovernedSubagentConflictError,
    GovernedSubagentError,
    GovernedSubagentHandle,
    GovernedSubagentRequest,
)
from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import Decision, GovernanceProxy


def _parent_runtime(
    tmp_path: Path,
    keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    *,
    name: str = "one",
    max_tool_calls: int = 12,
    ttl_s: int = 300,
) -> tuple[GovernanceProxy, object, GovernedSubagentAdapter]:
    private_key, public_key = keypair
    root = tmp_path / name
    proxy = GovernanceProxy(
        log_path=root / "governance.jsonl",
        receipts_log_path=root / "receipts.jsonl",
        state_dir=root / "state",
        private_key=private_key,
        public_key=public_key,
    )
    mission = MissionPassport(
        agent_id=f"parent-{name}",
        mission="coordinate bounded child work",
        allowed_tools=["read_file", "write_file", "send_email"],
        forbidden_tools=["delete_file"],
        resource_scope=["**"],
        max_tool_calls=max_tool_calls,
        max_duration_s=ttl_s,
        delegation_allowed=True,
        max_delegation_depth=3,
    )
    token = issue_passport(mission, private_key, ttl_s=ttl_s)
    session = proxy.start_session(token)
    adapter = GovernedSubagentAdapter(
        proxy=proxy,
        parent_session=session,
        delegation_private_key=private_key,
    )
    return proxy, session, adapter


def _request(
    request_id: str = "child-request-1",
    *,
    agent_id: str = "reader-child",
    mission: str = "read bounded workspace data",
    allowed_tools: tuple[str, ...] = ("read_file",),
    resource_scope: tuple[str, ...] = ("/workspace/*",),
    max_tool_calls: int = 3,
    ttl_s: int = 120,
    spend_cap=None,
    risk_cap=None,
) -> GovernedSubagentRequest:
    return GovernedSubagentRequest(
        request_id=request_id,
        child_agent_id=agent_id,
        mission=mission,
        allowed_tools=allowed_tools,
        resource_scope=resource_scope,
        max_tool_calls=max_tool_calls,
        ttl_s=ttl_s,
        spend_cap=spend_cap,
        risk_cap=risk_cap,
    )


def _error_code(exc: pytest.ExceptionInfo[GovernedSubagentError]) -> str:
    return exc.value.code


def test_spawn_returns_only_opaque_handle_and_private_digest_state(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    secret_mission = "declarative-mission-marker-never-copy"

    handle = adapter.spawn(_request(mission=secret_mission))

    assert isinstance(handle, GovernedSubagentHandle)
    assert str(handle).startswith("ardur_child_")
    assert "." not in str(handle)
    assert repr(handle) == "GovernedSubagentHandle(<opaque>)"
    state_text = adapter.state_path.read_text(encoding="utf-8")
    state = json.loads(state_text)
    assert secret_mission not in state_text
    assert "child-request-1" not in state_text
    assert "passport_token" not in state_text
    assert "child_token" not in state_text
    assert set(state) == {"schema", "handles", "requests"}
    assert len(state["handles"]) == 1
    durable_record = next(iter(state["handles"].values()))
    assert set(durable_record) == {
        "child_jti",
        "created_at",
        "expires_at",
        "handle",
        "operations",
        "parent_jti",
        "request_fingerprint",
        "request_key",
        "status",
    }
    compact_token = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
    assert not any(
        compact_token.fullmatch(value)
        for value in durable_record.values()
        if isinstance(value, str)
    )
    assert stat.S_IMODE(adapter.state_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(adapter.state_path.stat().st_mode) == 0o600


def test_spawn_retry_returns_same_handle_without_second_reservation(tmp_path, keypair):
    proxy, parent, adapter = _parent_runtime(tmp_path, keypair)
    request = _request(max_tool_calls=2)

    first = adapter.spawn(request)
    second = adapter.spawn(request)

    assert str(second) == str(first)
    snapshot = proxy.lineage_budget_ledger.snapshot(parent.jti)
    assert snapshot["reserved_total"] == 2
    assert len(snapshot["reservations"]) == 1
    assert len(proxy.get_session(parent.jti).delegated_children) == 1


def test_spawn_request_id_conflict_fails_closed(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    adapter.spawn(_request())

    with pytest.raises(GovernedSubagentConflictError) as captured:
        adapter.spawn(_request(mission="different child semantics"))

    assert _error_code(captured) == "SPAWN_CONFLICT"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("spend_cap", {"currency": "USD", "amount": "1.00"}, "SPEND_CAP_UNSUPPORTED"),
        ("risk_cap", {"destructive_targets": 1}, "RISK_CAP_UNSUPPORTED"),
    ],
)
def test_unmerged_cap_surfaces_are_never_silently_ignored(
    tmp_path, keypair, field, value, code
):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)

    with pytest.raises(GovernedSubagentError) as captured:
        adapter.spawn(_request(**{field: value}))

    assert _error_code(captured) == code


def test_child_parent_only_tool_is_signed_deny_before_executor(tmp_path, keypair):
    proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    executor_calls = 0

    def executor():
        nonlocal executor_calls
        executor_calls += 1
        return "must not run"

    result = adapter.run_tool(
        handle,
        operation_id="write-attempt",
        tool_name="write_file",
        arguments={"path": "/workspace/report.md", "content": "x"},
        executor=executor,
    )

    assert result.status == "denied"
    assert result.decision == Decision.DENY
    assert result.executed is False
    assert executor_calls == 0
    receipts = [
        json.loads(line)
        for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert receipts[-1]["verdict"] == "violation"
    assert receipts[-1]["receipt_id"] == result.receipt_id


def test_external_tool_authorization_and_settlement_are_two_phase(tmp_path, keypair):
    proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())

    authorized = adapter.authorize_external_tool(
        handle,
        operation_id="claude-tool-use-1",
        tool_name="read_file",
        arguments={"path": "/workspace/report.md"},
    )

    assert authorized.status == "authorized"
    assert authorized.decision == Decision.PERMIT
    assert authorized.executed is False
    assert adapter.lifecycle_snapshot(handle)["operation_count"] == 1

    settled = adapter.settle_external_tool(
        handle,
        operation_id="claude-tool-use-1",
        result={"content": "bounded result"},
        duration_ms=12.5,
    )

    assert settled.status == "completed"
    assert settled.decision == Decision.PERMIT
    assert settled.executed is True
    assert settled.result_sha256 is not None
    assert (
        proxy.get_session(
            adapter.lifecycle_snapshot(handle)["child_jti"]
        ).tool_call_count
        == 1
    )


def test_external_parent_usage_floor_is_monotonic_and_class_consistent(
    tmp_path, keypair
):
    proxy, parent, _adapter = _parent_runtime(tmp_path, keypair)

    advanced = proxy.synchronize_external_tool_usage_floor(
        parent,
        tool_call_count=4,
        tool_call_count_by_class={"read": 3},
    )
    unchanged = proxy.synchronize_external_tool_usage_floor(
        parent,
        tool_call_count=2,
        tool_call_count_by_class={"read": 1},
    )

    assert advanced["tool_call_count"] == 4
    assert unchanged["tool_call_count"] == 4
    assert unchanged["tool_call_count_by_class"] == {"read": 3}
    with pytest.raises(ValueError, match="merged per-class usage"):
        proxy.synchronize_external_tool_usage_floor(
            parent,
            tool_call_count=4,
            tool_call_count_by_class={"write": 2},
        )
    assert proxy.get_session(parent.jti).tool_call_count_by_class == {"read": 3}


def test_external_parent_usage_floor_cannot_overlap_child_reservation(
    tmp_path, keypair
):
    proxy, parent, adapter = _parent_runtime(
        tmp_path,
        keypair,
        max_tool_calls=12,
    )
    proxy.synchronize_external_tool_usage_floor(parent, tool_call_count=4)
    adapter.spawn(_request(max_tool_calls=3))

    with pytest.raises(PermissionError, match="overlaps delegated"):
        proxy.synchronize_external_tool_usage_floor(parent, tool_call_count=10)

    persisted = proxy.get_session(parent.jti)
    assert persisted.tool_call_count == 4
    assert persisted.delegated_budget_reserved == 3


def test_external_tool_parent_only_capability_is_denied_before_platform_execution(
    tmp_path, keypair
):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())

    denied = adapter.authorize_external_tool(
        handle,
        operation_id="claude-tool-use-parent-only",
        tool_name="write_file",
        arguments={"path": "/workspace/report.md", "content": "x"},
    )

    assert denied.status == "denied"
    assert denied.decision == Decision.DENY
    assert denied.executed is False


def test_external_tool_missing_outcome_quarantines_and_never_replays(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    first = adapter.authorize_external_tool(
        handle,
        operation_id="claude-tool-use-crash",
        tool_name="read_file",
        arguments={"path": "/workspace/report.md"},
    )
    assert first.status == "authorized"

    adapter.quarantine_external_tool(
        handle,
        operation_id="claude-tool-use-crash",
        terminal_code="PLATFORM_OUTCOME_MISSING",
    )

    assert adapter.lifecycle_snapshot(handle)["status"] == "quarantined"
    with pytest.raises(GovernedSubagentError) as captured:
        adapter.authorize_external_tool(
            handle,
            operation_id="claude-tool-use-crash",
            tool_name="read_file",
            arguments={"path": "/workspace/report.md"},
        )
    assert _error_code(captured) == "HANDLE_QUARANTINED"


def test_child_policy_projection_contains_no_bearer_authority(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())

    claims = adapter.child_policy(handle)
    encoded = json.dumps(claims, sort_keys=True)

    assert claims["sub"] == "reader-child"
    assert claims["allowed_tools"] == ["read_file"]
    assert "passport_token" not in encoded
    assert "child_token" not in encoded
    assert not re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", encoded)


def test_child_out_of_scope_resource_is_denied_before_executor(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    called = False

    def executor():
        nonlocal called
        called = True

    result = adapter.run_tool(
        handle,
        operation_id="outside-resource",
        tool_name="read_file",
        arguments={"path": "/private/secret.txt"},
        executor=executor,
    )

    assert result.decision == Decision.DENY
    assert called is False


def test_completed_result_is_returned_but_only_digest_is_persisted(tmp_path, keypair):
    proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    raw_result = "raw-provider-result-never-persist"

    result = adapter.run_tool(
        handle,
        operation_id="read-one",
        tool_name="read_file",
        arguments={"path": "/workspace/input.txt"},
        executor=lambda: raw_result,
    )

    assert result.status == "completed"
    assert result.value == raw_result
    assert result.result_sha256
    assert raw_result not in adapter.state_path.read_text(encoding="utf-8")
    child_jti = adapter.lifecycle_snapshot(handle)["child_jti"]
    child = proxy.get_session(child_jti)
    assert child.events[-1].response == f"executor_result_sha256:{result.result_sha256}"
    assert raw_result not in child.events[-1].response


def test_duplicate_operation_suppresses_executor_replay(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    calls = 0

    def executor():
        nonlocal calls
        calls += 1
        return {"ok": True}

    first = adapter.run_tool(
        handle,
        operation_id="stable-operation",
        tool_name="read_file",
        arguments={"path": "/workspace/input.txt"},
        executor=executor,
    )
    second = adapter.run_tool(
        handle,
        operation_id="stable-operation",
        tool_name="read_file",
        arguments={"path": "/workspace/input.txt"},
        executor=executor,
    )

    assert first.status == "completed"
    assert second.status == "replay_suppressed"
    assert second.executed is False
    assert second.value is None
    assert second.result_sha256 == first.result_sha256
    assert calls == 1


def test_operation_id_conflict_fails_closed_without_second_executor(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    adapter.run_tool(
        handle,
        operation_id="stable-operation",
        tool_name="read_file",
        arguments={"path": "/workspace/one.txt"},
        executor=lambda: "one",
    )

    with pytest.raises(GovernedSubagentConflictError) as captured:
        adapter.run_tool(
            handle,
            operation_id="stable-operation",
            tool_name="read_file",
            arguments={"path": "/workspace/two.txt"},
            executor=lambda: pytest.fail("conflicting executor must not run"),
        )

    assert _error_code(captured) == "OPERATION_CONFLICT"


def test_close_is_monotonic_idempotent_and_never_returns_token(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())

    first = adapter.close(handle)
    second = adapter.close(handle)

    assert first.status == "closed"
    assert first.idempotent is False
    assert second == type(second)(
        status="closed",
        attestation_id=first.attestation_id,
        attestation_sha256=first.attestation_sha256,
        idempotent=True,
    )
    assert "." not in first.attestation_id
    with pytest.raises(GovernedSubagentError) as captured:
        adapter.run_tool(
            handle,
            operation_id="after-close",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=lambda: pytest.fail("closed child must not execute"),
        )
    assert _error_code(captured) == "HANDLE_CLOSED"


def test_close_all_cancels_multiple_children_without_exposing_attestations(
    tmp_path, keypair
):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    first = adapter.spawn(_request("first", agent_id="first", max_tool_calls=1))
    second = adapter.spawn(_request("second", agent_id="second", max_tool_calls=1))

    results = adapter.close_all(cancelled=True)

    assert len(results) == 2
    assert {result.status for result in results} == {"cancelled"}
    assert adapter.lifecycle_snapshot(first)["status"] == "cancelled"
    assert adapter.lifecycle_snapshot(second)["status"] == "cancelled"
    assert all("." not in result.attestation_id for result in results)


def test_handle_is_bound_to_exact_parent_even_in_shared_adapter_state(
    tmp_path, keypair
):
    private_key, public_key = keypair
    shared = tmp_path / "shared"
    proxy = GovernanceProxy(
        log_path=shared / "log.jsonl",
        receipts_log_path=shared / "receipts.jsonl",
        state_dir=shared / "state",
        private_key=private_key,
        public_key=public_key,
    )
    mission = MissionPassport(
        agent_id="parent",
        mission="coordinate",
        allowed_tools=["read_file", "write_file"],
        resource_scope=["**"],
        max_tool_calls=10,
        max_duration_s=300,
        delegation_allowed=True,
        max_delegation_depth=2,
    )
    first_parent = proxy.start_session(issue_passport(mission, private_key, ttl_s=300))
    second_parent = proxy.start_session(issue_passport(mission, private_key, ttl_s=300))
    first = GovernedSubagentAdapter(
        proxy=proxy,
        parent_session=first_parent,
        delegation_private_key=private_key,
    )
    second = GovernedSubagentAdapter(
        proxy=proxy,
        parent_session=second_parent,
        delegation_private_key=private_key,
    )
    handle = first.spawn(_request())

    with pytest.raises(GovernedSubagentError) as captured:
        second.lifecycle_snapshot(handle)

    assert _error_code(captured) == "PARENT_MISMATCH"


@pytest.mark.parametrize(
    ("handle", "code"),
    [
        ("not-a-handle", "HANDLE_INVALID"),
        ("ardur_child_" + ("A" * 43), "HANDLE_UNKNOWN"),
    ],
)
def test_malformed_and_forged_handles_fail_closed(tmp_path, keypair, handle, code):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)

    with pytest.raises(GovernedSubagentError) as captured:
        adapter.lifecycle_snapshot(handle)

    assert _error_code(captured) == code


def test_expired_handle_fails_before_policy_or_executor(tmp_path, keypair, monkeypatch):
    proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    snapshot = adapter.lifecycle_snapshot(handle)
    child = proxy.get_session(snapshot["child_jti"])
    events_before = len(child.events)
    receipts_before = proxy.receipts_log_path.read_bytes()
    monkeypatch.setattr(
        "vibap.governed_subagent.time.time", lambda: snapshot["expires_at"] + 1
    )

    with pytest.raises(GovernedSubagentError) as captured:
        adapter.run_tool(
            handle,
            operation_id="expired-call",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=lambda: pytest.fail("expired child must not execute"),
        )

    assert _error_code(captured) == "HANDLE_EXPIRED"
    assert len(proxy.get_session(snapshot["child_jti"]).events) == events_before
    assert proxy.receipts_log_path.read_bytes() == receipts_before


def test_spawn_recovers_same_handle_after_post_delegation_crash(
    tmp_path,
    keypair,
    monkeypatch,
):
    proxy, parent, adapter = _parent_runtime(tmp_path, keypair)
    request = _request(max_tool_calls=2)
    original_delegate = proxy.delegate_passport

    def crash_after_delegation(*args, **kwargs):
        original_delegate(*args, **kwargs)
        raise RuntimeError("simulated process loss after durable delegation")

    monkeypatch.setattr(proxy, "delegate_passport", crash_after_delegation)
    with pytest.raises(RuntimeError, match="simulated process loss"):
        adapter.spawn(request)
    state = json.loads(adapter.state_path.read_text(encoding="utf-8"))
    pending = next(iter(state["handles"].values()))
    assert pending["status"] == "spawning"
    original_handle = pending["handle"]

    monkeypatch.setattr(proxy, "delegate_passport", original_delegate)
    private_key, _public_key = keypair
    restarted = GovernedSubagentAdapter(
        proxy=proxy,
        parent_session=parent,
        delegation_private_key=private_key,
    )

    recovered = restarted.spawn(request)

    assert str(recovered) == original_handle
    assert restarted.lifecycle_snapshot(recovered)["status"] == "active"
    assert proxy.lineage_budget_ledger.snapshot(parent.jti)["reserved_total"] == 2


def test_externally_closed_child_session_fails_closed(tmp_path, keypair):
    proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    child_jti = adapter.lifecycle_snapshot(handle)["child_jti"]
    proxy.end_session(child_jti)

    with pytest.raises(GovernedSubagentError) as captured:
        adapter.run_tool(
            handle,
            operation_id="closed-session-call",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=lambda: pytest.fail("closed session must not execute"),
        )

    assert _error_code(captured) == "HANDLE_CLOSED"


def test_executor_exception_quarantines_child_without_refund_or_replay(
    tmp_path, keypair
):
    proxy, parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request(max_tool_calls=2))

    with pytest.raises(RuntimeError, match="side effect may have started"):
        adapter.run_tool(
            handle,
            operation_id="uncertain-side-effect",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=lambda: (_ for _ in ()).throw(
                RuntimeError("side effect may have started")
            ),
        )

    assert adapter.lifecycle_snapshot(handle)["status"] == "quarantined"
    assert proxy.lineage_budget_ledger.snapshot(parent.jti)["reserved_total"] == 2
    with pytest.raises(GovernedSubagentError) as captured:
        adapter.run_tool(
            handle,
            operation_id="another-operation",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=lambda: pytest.fail("quarantined child must not execute"),
        )
    assert _error_code(captured) == "HANDLE_QUARANTINED"


def test_hostile_result_repr_is_never_invoked_and_child_is_quarantined(
    tmp_path,
    keypair,
):
    proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())

    class HostileResult:
        def __repr__(self):
            pytest.fail("result repr must never execute")

    with pytest.raises(GovernedSubagentError) as captured:
        adapter.run_tool(
            handle,
            operation_id="hostile-result",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=HostileResult,
        )

    assert _error_code(captured) == "RESULT_UNSERIALIZABLE"
    assert adapter.lifecycle_snapshot(handle)["status"] == "quarantined"
    child_jti = adapter.lifecycle_snapshot(handle)["child_jti"]
    assert proxy.get_session(child_jti).events[-1].response == (
        "executor_outcome:result_unserializable"
    )


def test_async_cancellation_quarantines_child(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())

    async def cancel_executor():
        raise asyncio.CancelledError

    async def run():
        await adapter.arun_tool(
            handle,
            operation_id="async-cancel",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=cancel_executor,
        )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run())
    assert adapter.lifecycle_snapshot(handle)["status"] == "quarantined"


def test_parallel_spawn_cannot_oversubscribe_lineage_budget(tmp_path, keypair):
    proxy, parent, adapter = _parent_runtime(tmp_path, keypair, max_tool_calls=6)

    def spawn(index: int):
        return adapter.spawn(
            _request(
                f"parallel-{index}",
                agent_id=f"child-{index}",
                max_tool_calls=2,
            )
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(spawn, index) for index in range(12)]
    accepted = 0
    denied = 0
    for future in futures:
        try:
            future.result()
            accepted += 1
        except PermissionError:
            denied += 1

    assert accepted == 3
    assert denied == 9
    assert proxy.lineage_budget_ledger.snapshot(parent.jti)["reserved_total"] == 6


def test_distinct_children_can_execute_in_parallel(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair, max_tool_calls=4)
    first = adapter.spawn(_request("first", agent_id="first", max_tool_calls=1))
    second = adapter.spawn(_request("second", agent_id="second", max_tool_calls=1))
    barrier = threading.Barrier(2, timeout=5)

    def execute(handle, operation_id):
        return adapter.run_tool(
            handle,
            operation_id=operation_id,
            tool_name="read_file",
            arguments={"path": f"/workspace/{operation_id}.txt"},
            executor=lambda: (barrier.wait(), operation_id)[1],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda pair: execute(*pair),
                [(first, "first-op"), (second, "second-op")],
            )
        )

    assert {result.value for result in results} == {"first-op", "second-op"}


def test_same_child_rejects_overlapping_operation_and_close(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    entered = threading.Event()
    release = threading.Event()

    def blocking_executor():
        entered.set()
        assert release.wait(timeout=5)
        return "done"

    with ThreadPoolExecutor(max_workers=2) as pool:
        running = pool.submit(
            adapter.run_tool,
            handle,
            operation_id="blocking",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=blocking_executor,
        )
        assert entered.wait(timeout=5)
        with pytest.raises(GovernedSubagentError) as second_call:
            adapter.run_tool(
                handle,
                operation_id="overlap",
                tool_name="read_file",
                arguments={"path": "/workspace/other.txt"},
                executor=lambda: pytest.fail("overlapping executor must not run"),
            )
        with pytest.raises(GovernedSubagentError) as close_call:
            adapter.close(handle)
        release.set()
        assert running.result(timeout=5).status == "completed"

    assert _error_code(second_call) == "CHILD_BUSY"
    assert _error_code(close_call) == "CHILD_BUSY"


def test_restart_spawn_rehydrates_same_handle_without_child_passport(tmp_path, keypair):
    proxy, parent, first = _parent_runtime(tmp_path, keypair)
    request = _request()
    handle = first.spawn(request)
    private_key, _public_key = keypair
    restarted = GovernedSubagentAdapter(
        proxy=proxy,
        parent_session=parent.jti,
        delegation_private_key=private_key,
    )

    replay = restarted.spawn(request)

    assert str(replay) == str(handle)
    assert "passport_token" not in restarted.state_path.read_text(encoding="utf-8")


def test_expired_operation_lease_is_quarantined_on_restart(tmp_path, keypair):
    proxy, parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    with adapter._state_transaction() as state:
        _digest, record = adapter._resolve_record(state, handle)
        record["operations"]["f" * 64] = {
            "fingerprint": "e" * 64,
            "tool_name": "read_file",
            "arguments_sha256": "d" * 64,
            "status": "executing",
            "owner_id": "c" * 32,
            "started_at": 1.0,
            "lease_expires_at": 1.0,
            "decision": Decision.PERMIT.value,
        }
    private_key, _public_key = keypair

    restarted = GovernedSubagentAdapter(
        proxy=proxy,
        parent_session=parent,
        delegation_private_key=private_key,
    )

    assert restarted.lifecycle_snapshot(handle)["status"] == "quarantined"
    with pytest.raises(GovernedSubagentError) as captured:
        restarted.run_tool(
            handle,
            operation_id="after-restart",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=lambda: pytest.fail("uncertain child must not execute"),
        )
    assert _error_code(captured) == "HANDLE_QUARANTINED"


def test_corrupt_adapter_state_fails_closed(tmp_path, keypair):
    proxy, parent, adapter = _parent_runtime(tmp_path, keypair)
    adapter.spawn(_request())
    adapter.state_path.write_text("{not-json", encoding="utf-8")
    private_key, _public_key = keypair

    with pytest.raises(GovernedSubagentError) as captured:
        GovernedSubagentAdapter(
            proxy=proxy,
            parent_session=parent,
            delegation_private_key=private_key,
        )

    assert _error_code(captured) == "STATE_UNAVAILABLE"


def test_unknown_durable_state_field_fails_closed(tmp_path, keypair):
    proxy, parent, adapter = _parent_runtime(tmp_path, keypair)
    adapter.spawn(_request())
    payload = json.loads(adapter.state_path.read_text(encoding="utf-8"))
    next(iter(payload["handles"].values()))["passport_backup"] = "not-allowed"
    adapter.state_path.write_text(json.dumps(payload), encoding="utf-8")
    private_key, _public_key = keypair

    with pytest.raises(GovernedSubagentError) as captured:
        GovernedSubagentAdapter(
            proxy=proxy,
            parent_session=parent,
            delegation_private_key=private_key,
        )

    assert _error_code(captured) == "STATE_UNAVAILABLE"


def test_close_all_continues_after_one_child_cleanup_failure(
    tmp_path,
    keypair,
    monkeypatch,
):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    first = adapter.spawn(_request("first", agent_id="first", max_tool_calls=1))
    second = adapter.spawn(_request("second", agent_id="second", max_tool_calls=1))
    original_cancel = adapter.cancel
    attempted: list[str] = []

    def flaky_cancel(handle):
        attempted.append(str(handle))
        if str(handle) == str(first):
            raise GovernedSubagentError("TEST_FAILURE", "simulated close failure")
        return original_cancel(handle)

    monkeypatch.setattr(adapter, "cancel", flaky_cancel)
    with pytest.raises(GovernedSubagentError) as captured:
        adapter.close_all(cancelled=True)

    assert _error_code(captured) == "TEST_FAILURE"
    assert len(attempted) == 2
    assert set(attempted) == {str(first), str(second)}
    assert adapter.lifecycle_snapshot(second)["status"] == "cancelled"


def test_evidence_projection_omits_authority_tokens_and_raw_result(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    adapter.run_tool(
        handle,
        operation_id="evidence-read",
        tool_name="read_file",
        arguments={"path": "/workspace/input.txt"},
        executor=lambda: "private-result-marker",
    )
    adapter.close(handle)

    evidence = adapter.export_session_evidence(handle)
    encoded = json.dumps(evidence, sort_keys=True)

    assert "passport_token" not in encoded
    assert "attestation_token" not in encoded
    assert "child_token" not in encoded
    assert "private-result-marker" not in encoded
    assert evidence["passport_claims"]["parent_jti"]
    # This trusted export is signed non-authorizing evidence required by the
    # offline verifier, not a child passport or a model-visible return value.
    signed_evidence, claims = adapter.export_attestation_evidence(handle)
    assert signed_evidence.count(".") == 2
    assert claims["passport_jti"] == evidence["passport_claims"]["jti"]


def test_attestation_export_rejects_closure_state_mismatch(tmp_path, keypair):
    _proxy, _parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    adapter.close(handle)
    with adapter._state_transaction() as state:
        _digest, record = adapter._resolve_record(
            state,
            handle,
            allow_terminal=True,
        )
        record["attestation_sha256"] = "0" * 64

    with pytest.raises(GovernedSubagentError) as captured:
        adapter.export_attestation_evidence(handle)

    assert _error_code(captured) == "STATE_UNAVAILABLE"


def test_parent_closure_blocks_new_child_execution(tmp_path, keypair):
    proxy, parent, adapter = _parent_runtime(tmp_path, keypair)
    handle = adapter.spawn(_request())
    proxy.end_session(parent)

    with pytest.raises(GovernedSubagentError) as captured:
        adapter.run_tool(
            handle,
            operation_id="parent-closed",
            tool_name="read_file",
            arguments={"path": "/workspace/input.txt"},
            executor=lambda: pytest.fail("closed parent must block execution"),
        )

    assert _error_code(captured) == "PARENT_CLOSED"

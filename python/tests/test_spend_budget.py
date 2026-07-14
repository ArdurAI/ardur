from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from vibap.passport import (
    MissionPassport,
    derive_child_passport,
    issue_passport,
    verify_passport,
)
from vibap.metrics import ArdurMetrics
from vibap.proxy import Decision, GovernanceProxy
from vibap.receipt import verify_receipt
from vibap.spend_budget import (
    FileSpendBudgetLedger,
    SpendBudgetConflictError,
    SpendBudgetError,
    SpendQuote,
    SpendReservationRequest,
    StaticSpendQuoteStore,
    normalize_spend_budget,
)


def _policy(
    *,
    lineage_id: str = "lineage-1",
    token_session: int = 100,
    token_agent: int = 100,
    token_lineage: int = 100,
    money_session: int = 1_000,
    money_agent: int = 1_000,
    money_lineage: int = 1_000,
) -> dict:
    return {
        "version": 1,
        "currency": "USD",
        "metered_tools": ["llm_generate"],
        "ceilings": {
            "tokens": {
                "session": token_session,
                "agent": token_agent,
                "lineage": token_lineage,
            },
            "currency_micros": {
                "session": money_session,
                "agent": money_agent,
                "lineage": money_lineage,
            },
        },
        "lineage_id": lineage_id,
    }


def _mission_policy(**kwargs) -> dict:
    policy = _policy(**kwargs)
    policy.pop("lineage_id")
    return policy


def _quote(
    *,
    quote_id: str = "quote-1",
    valid_from: int | None = None,
    valid_until: int | None = None,
) -> SpendQuote:
    now = int(time.time())
    return SpendQuote(
        quote_id=quote_id,
        tool_name="llm_generate",
        model="operator-model-v1",
        currency="USD",
        input_micros_per_million_tokens=1_000_000,
        output_micros_per_million_tokens=2_000_000,
        valid_from=now - 60 if valid_from is None else valid_from,
        valid_until=now + 3600 if valid_until is None else valid_until,
    )


def _request(
    request_id: str,
    *,
    input_tokens: int = 10,
    output_tokens: int = 10,
    quote_id: str = "quote-1",
) -> SpendReservationRequest:
    return SpendReservationRequest(
        request_id=request_id,
        quote_id=quote_id,
        model="operator-model-v1",
        max_input_tokens=input_tokens,
        max_output_tokens=output_tokens,
    )


def test_policy_rejects_float_duplicate_tools_and_incomplete_scopes() -> None:
    float_policy = _policy()
    float_policy["ceilings"]["tokens"]["session"] = 1.5
    with pytest.raises(SpendBudgetError, match="non-negative integer"):
        normalize_spend_budget(float_policy, require_lineage_id=True)

    duplicate = _policy()
    duplicate["metered_tools"] = ["llm_generate", "llm_generate"]
    with pytest.raises(SpendBudgetError, match="duplicates"):
        normalize_spend_budget(duplicate, require_lineage_id=True)

    incomplete = _policy()
    del incomplete["ceilings"]["currency_micros"]["lineage"]
    with pytest.raises(SpendBudgetError, match="session, agent, and lineage"):
        normalize_spend_budget(incomplete, require_lineage_id=True)


def test_quote_uses_integer_ceiling_arithmetic_and_validity() -> None:
    quote = _quote()
    assert quote.reserve_amounts(1, 1) == {
        "tokens": 2,
        "currency_micros": 3,
    }

    store = StaticSpendQuoteStore([quote])
    assert (
        store.resolve(
            quote.quote_id,
            tool_name=quote.tool_name,
            model=quote.model,
            currency=quote.currency,
        ).digest
        == quote.digest
    )

    with pytest.raises(SpendBudgetError) as exc:
        store.resolve(
            quote.quote_id,
            tool_name=quote.tool_name,
            model="provider-selected-model",
            currency=quote.currency,
        )
    assert exc.value.reason_code == "spend_quote_scope_mismatch"


def test_reservation_breach_denies_without_mutating_scope_totals(tmp_path) -> None:
    ledger = FileSpendBudgetLedger(tmp_path)
    result = ledger.reserve(
        policy=_policy(token_lineage=19),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("too-large"),
        quote=_quote(),
    )

    assert result.accepted is False
    assert result.reason_code == "spend_lineage_tokens_exhausted"
    snapshot = ledger.snapshot("lineage-1")
    assert snapshot["reservations"] == {}
    assert all(
        totals["reserved"] == {"tokens": 0, "currency_micros": 0}
        for totals in snapshot["scopes"].values()
    )


def test_concurrent_siblings_cannot_oversubscribe_lineage(tmp_path) -> None:
    policy = _policy(token_session=1_000, token_agent=1_000, token_lineage=50)
    quote = _quote()

    def attempt(index: int) -> bool:
        ledger = FileSpendBudgetLedger(tmp_path)
        result = ledger.reserve(
            policy=policy,
            session_id=f"session-{index}",
            agent_id=f"agent-{index}",
            request=_request(f"sibling-{index}", input_tokens=5, output_tokens=5),
            quote=quote,
        )
        return result.accepted

    with ThreadPoolExecutor(max_workers=16) as pool:
        accepted = list(pool.map(attempt, range(32)))

    assert sum(accepted) == 5
    snapshot = FileSpendBudgetLedger(tmp_path).snapshot("lineage-1")
    lineage_scope = next(
        totals
        for scope_ref, totals in snapshot["scopes"].items()
        if any(
            record["scope_refs"]["lineage"] == scope_ref
            for record in snapshot["reservations"].values()
        )
    )
    assert lineage_scope["reserved"]["tokens"] == 50


def test_duplicate_active_request_is_fail_closed_and_conflict_is_rejected(
    tmp_path,
) -> None:
    ledger = FileSpendBudgetLedger(tmp_path)
    first = ledger.reserve(
        policy=_policy(),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("retry-1"),
        quote=_quote(),
    )
    replay = ledger.reserve(
        policy=_policy(),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("retry-1"),
        quote=_quote(),
    )

    assert first.accepted is True
    assert replay.accepted is False
    assert replay.idempotent is True
    assert replay.reason_code == "spend_request_already_reserved"

    with pytest.raises(SpendBudgetConflictError) as exc:
        ledger.reserve(
            policy=_policy(),
            session_id="session-1",
            agent_id="agent-1",
            request=_request("retry-1", output_tokens=11),
            quote=_quote(),
        )
    assert exc.value.reason_code == "spend_request_conflict"


def test_settlement_refunds_only_verified_unused_and_replay_is_idempotent(
    tmp_path,
) -> None:
    ledger = FileSpendBudgetLedger(tmp_path)
    ledger.reserve(
        policy=_policy(),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("settle-1"),
        quote=_quote(),
    )
    proof = "a" * 64
    settled = ledger.settle(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="settle-1",
        actual_input_tokens=4,
        actual_output_tokens=3,
        usage_proof_digest=proof,
    )
    replay = ledger.settle(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="settle-1",
        actual_input_tokens=4,
        actual_output_tokens=3,
        usage_proof_digest=proof,
    )

    assert settled.operation == "settle"
    assert settled.actual == {"tokens": 7, "currency_micros": 10}
    assert settled.refunded == {"tokens": 13, "currency_micros": 20}
    assert replay.idempotent is True

    with pytest.raises(SpendBudgetConflictError) as exc:
        ledger.settle(
            lineage_id="lineage-1",
            session_id="session-1",
            request_id="settle-1",
            actual_input_tokens=4,
            actual_output_tokens=4,
            usage_proof_digest=proof,
        )
    assert exc.value.reason_code == "spend_settlement_conflict"


def test_release_refund_replay_is_idempotent(tmp_path) -> None:
    ledger = FileSpendBudgetLedger(tmp_path)
    ledger.reserve(
        policy=_policy(),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("release-replay"),
        quote=_quote(),
    )

    first = ledger.cancel(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="release-replay",
        reason_code="spend_action_not_permitted",
    )
    replay = ledger.cancel(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="release-replay",
        reason_code="spend_action_not_permitted",
    )

    assert first.operation == "release"
    assert first.refunded == first.reserved
    assert replay.idempotent is True
    assert replay.refunded == first.refunded


def test_missing_usage_quarantines_then_trusted_reconciliation_settles(
    tmp_path,
) -> None:
    first = FileSpendBudgetLedger(tmp_path)
    first.reserve(
        policy=_policy(),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("crash-1"),
        quote=_quote(),
    )
    quarantined = first.settle(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="crash-1",
        actual_input_tokens=0,
        actual_output_tokens=0,
        usage_proof_digest=None,
    )

    assert quarantined.operation == "quarantine"
    assert quarantined.reserved["tokens"] == 20

    reloaded = FileSpendBudgetLedger(tmp_path)
    reconciled = reloaded.settle(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="crash-1",
        actual_input_tokens=2,
        actual_output_tokens=2,
        usage_proof_digest="b" * 64,
    )
    assert reconciled.operation == "settle"
    assert reconciled.reconciled is True
    assert reloaded.snapshot("lineage-1")["quarantined_reservations"] == {}


def test_failed_reconciliation_does_not_claim_reconciled(tmp_path) -> None:
    ledger = FileSpendBudgetLedger(tmp_path)
    ledger.reserve(
        policy=_policy(),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("failed-reconcile"),
        quote=_quote(),
    )
    first = ledger.quarantine(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="failed-reconcile",
        reason_code="spend_settlement_evidence_missing",
    )
    second = ledger.settle(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="failed-reconcile",
        actual_input_tokens=0,
        actual_output_tokens=0,
        usage_proof_digest=None,
    )

    assert first.reconciled is False
    assert second.operation == "quarantine"
    assert second.reconciled is False


def test_expired_terminal_records_are_pruned_before_capacity_check(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("vibap.spend_budget.MAX_LEDGER_RECORDS", 3)
    ledger = FileSpendBudgetLedger(tmp_path)
    denied_policy = _policy(token_lineage=0)
    old_quote = _quote(valid_from=0, valid_until=10)
    for index in range(3):
        result = ledger.reserve(
            policy=denied_policy,
            session_id="session-1",
            agent_id="agent-1",
            request=_request(f"old-reject-{index}"),
            quote=old_quote,
            now=5,
        )
        assert result.accepted is False

    fresh = ledger.reserve(
        policy=denied_policy,
        session_id="session-1",
        agent_id="agent-1",
        request=_request("new-reject"),
        quote=_quote(valid_from=10, valid_until=20),
        now=11,
    )

    assert fresh.accepted is False
    snapshot = ledger.snapshot("lineage-1")
    assert len(snapshot["closed_reservations"]) == 1


@pytest.mark.parametrize("tamper", ["negative", "accounting_mismatch"])
def test_malformed_or_inconsistent_ledger_state_fails_closed(tmp_path, tamper) -> None:
    ledger = FileSpendBudgetLedger(tmp_path)
    ledger.reserve(
        policy=_policy(),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("tamper-state"),
        quote=_quote(),
    )
    path = ledger._path("lineage-1")
    payload = json.loads(path.read_text(encoding="utf-8"))
    scope_ref = next(iter(payload["scopes"]))
    if tamper == "negative":
        payload["scopes"][scope_ref]["reserved"]["tokens"] = -1
    else:
        payload["scopes"][scope_ref]["reserved"]["tokens"] += 1
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SpendBudgetError) as exc:
        FileSpendBudgetLedger(tmp_path).snapshot("lineage-1")
    assert exc.value.reason_code in {
        "spend_ledger_invalid",
        "spend_ledger_accounting_mismatch",
    }


def test_stale_reservation_is_quarantined_without_refund_after_restart(
    tmp_path,
) -> None:
    ledger = FileSpendBudgetLedger(tmp_path)
    ledger.reserve(
        policy=_policy(),
        session_id="session-1",
        agent_id="agent-1",
        request=_request("stale-1"),
        quote=_quote(valid_from=0, valid_until=1_000),
        now=100,
    )

    results = FileSpendBudgetLedger(tmp_path).quarantine_stale(
        lineage_id="lineage-1",
        session_id="session-1",
        older_than_s=10,
        now=111,
    )
    snapshot = FileSpendBudgetLedger(tmp_path).snapshot("lineage-1")

    assert len(results) == 1
    assert results[0].reason_code == "spend_reservation_stale"
    assert snapshot["reservations"] == {}
    assert len(snapshot["quarantined_reservations"]) == 1
    assert any(
        totals["reserved"]["tokens"] == 20 for totals in snapshot["scopes"].values()
    )


def test_sibling_session_cannot_close_or_stale_another_reservation(tmp_path) -> None:
    ledger = FileSpendBudgetLedger(tmp_path)
    ledger.reserve(
        policy=_policy(),
        session_id="session-a",
        agent_id="agent-a",
        request=_request("owned-by-a"),
        quote=_quote(valid_from=0, valid_until=1_000),
        now=100,
    )

    with pytest.raises(SpendBudgetConflictError) as exc:
        ledger.settle(
            lineage_id="lineage-1",
            session_id="session-b",
            request_id="owned-by-a",
            actual_input_tokens=1,
            actual_output_tokens=1,
            usage_proof_digest="e" * 64,
        )
    assert exc.value.reason_code == "spend_reservation_session_mismatch"

    assert (
        ledger.quarantine_stale(
            lineage_id="lineage-1",
            session_id="session-b",
            older_than_s=0,
            now=101,
        )
        == []
    )
    quarantined = ledger.quarantine_stale(
        lineage_id="lineage-1",
        session_id="session-a",
        older_than_s=0,
        now=101,
    )
    assert len(quarantined) == 1


def test_root_issuance_binds_lineage_and_child_inherits_authority(
    private_key,
    public_key,
) -> None:
    parent = MissionPassport(
        agent_id="parent",
        mission="coordinate",
        allowed_tools=["llm_generate"],
        resource_scope=["**"],
        max_tool_calls=10,
        delegation_allowed=True,
        max_delegation_depth=1,
        spend_budget=_mission_policy(),
    )
    parent_token = issue_passport(parent, private_key, ttl_s=300)
    parent_claims = verify_passport(parent_token, public_key)
    child_token = derive_child_passport(
        parent_token,
        public_key,
        private_key,
        "child",
        ["llm_generate"],
        "run bounded generation",
        child_max_tool_calls=2,
        parent_calls_remaining=10,
    )
    child_claims = verify_passport(
        child_token,
        public_key,
        parent_token=parent_token,
    )

    assert parent_claims["spend_budget"]["lineage_id"] == parent_claims["jti"]
    assert child_claims["spend_budget"] == parent_claims["spend_budget"]


def test_root_cannot_preselect_lineage_or_override_spend_with_extra_claims(
    private_key,
) -> None:
    preselected = MissionPassport(
        agent_id="root",
        mission="bounded root",
        allowed_tools=["llm_generate"],
        resource_scope=["**"],
        spend_budget=_policy(lineage_id="attacker-selected-lineage"),
    )
    with pytest.raises(ValueError, match="root spend_budget must omit lineage_id"):
        issue_passport(preselected, private_key, ttl_s=60)

    normal = MissionPassport(
        agent_id="root",
        mission="bounded root",
        allowed_tools=["llm_generate"],
        resource_scope=["**"],
        spend_budget=_mission_policy(),
    )
    with pytest.raises(ValueError, match="must not override"):
        issue_passport(
            normal,
            private_key,
            ttl_s=60,
            extra_claims={"spend_budget": _policy(lineage_id="override")},
        )


def test_direct_child_spend_policy_must_carry_inherited_lineage(private_key) -> None:
    child = MissionPassport(
        agent_id="child",
        mission="bounded child",
        allowed_tools=["llm_generate"],
        resource_scope=["**"],
        parent_jti="parent-jti",
        spend_budget=_mission_policy(),
    )
    with pytest.raises(ValueError, match="must inherit the parent lineage_id"):
        issue_passport(child, private_key, ttl_s=60)


def _spend_proxy(tmp_path, public_key, private_key, session_keys_dir, policy) -> tuple:
    quote = _quote()
    proxy = GovernanceProxy(
        log_path=tmp_path / "governance.jsonl",
        receipts_log_path=tmp_path / "receipts.jsonl",
        state_dir=tmp_path / "state",
        keys_dir=session_keys_dir,
        public_key=public_key,
        private_key=private_key,
        spend_quote_store=StaticSpendQuoteStore([quote]),
    )
    mission = MissionPassport(
        agent_id="metered-agent",
        mission="bounded model call",
        allowed_tools=["llm_generate"],
        resource_scope=["**"],
        max_tool_calls=10,
        spend_budget=policy,
    )
    token = issue_passport(mission, private_key, ttl_s=300)
    return proxy, proxy.start_session(token)


def test_proxy_denies_cap_breach_before_executor_and_signs_denial(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
) -> None:
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(token_session=19),
    )
    executor_calls: list[dict] = []

    def executor(arguments: dict) -> None:
        executor_calls.append(arguments)

    decision, reason = proxy.evaluate_tool_call(
        session,
        "llm_generate",
        {"input_hash": "bounded"},
        spend_request=_request("deny-before-provider"),
    )
    if decision == Decision.PERMIT:
        executor({"input_hash": "bounded"})

    assert decision == Decision.DENY
    assert reason == "spend_session_tokens_exhausted"
    assert executor_calls == []
    entry = json.loads(proxy.receipts_log_path.read_text().splitlines()[-1])
    claims = verify_receipt(entry["jwt"], proxy.receipt_public_key)
    assert claims["budget_delta"]["operation"] == "reject"
    assert claims["budget_delta"]["requested"]["tokens"] == 20
    assert claims["budget_delta"]["reserved"]["tokens"] == 0
    assert "deny-before-provider" not in entry["jwt"]


def test_proxy_permit_and_settlement_emit_verifiable_chained_receipts(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
) -> None:
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(),
    )
    request = _request("provider-call-1")
    decision, _ = proxy.evaluate_tool_call(
        session,
        "llm_generate",
        {"input_hash": "not-a-prompt"},
        spend_request=request,
    )
    assert decision == Decision.PERMIT

    result = proxy.settle_spend(
        session,
        request_id=request.request_id,
        actual_input_tokens=4,
        actual_output_tokens=3,
        usage_proof_digest="c" * 64,
    )

    assert result.operation == "settle"
    entries = [
        json.loads(line)
        for line in proxy.receipts_log_path.read_text().splitlines()
        if line.strip()
    ]
    assert len(entries) == 2
    first = verify_receipt(entries[0]["jwt"], proxy.receipt_public_key)
    second = verify_receipt(entries[1]["jwt"], proxy.receipt_public_key)
    assert first["budget_delta"]["operation"] == "reserve"
    assert second["budget_delta"]["operation"] == "settle"
    assert second["parent_receipt_hash"] is not None
    assert second["budget_delta"]["actual"] == {
        "tokens": 7,
        "currency_micros": 10,
    }
    assert request.request_id not in entries[1]["jwt"]
    assert proxy._session_no_out_of_scope_permits(proxy.get_session(session.jti))


@pytest.mark.parametrize(
    "failure_point",
    [
        "_apply_mic_conformance_checks",
        "_persist_session",
        "_build_receipt_log_entry",
    ],
)
def test_proxy_compensates_accepted_reservation_on_exception(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
    monkeypatch,
    failure_point,
) -> None:
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(),
    )
    monkeypatch.setattr(
        proxy,
        failure_point,
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("injected")),
    )

    with pytest.raises(RuntimeError, match="injected"):
        proxy.evaluate_tool_call(
            session,
            "llm_generate",
            {"input_hash": "bounded"},
            spend_request=_request(f"exception-{failure_point}"),
        )

    lineage_id = session.passport_claims["spend_budget"]["lineage_id"]
    snapshot = proxy.spend_budget_ledger.snapshot(lineage_id)
    assert snapshot["reservations"] == {}
    assert len(snapshot["closed_reservations"]) == 1
    record = next(iter(snapshot["closed_reservations"].values()))
    assert record["operation"] == "release"
    assert record["reason_code"] == "spend_evaluation_failed"


def test_proxy_compensation_failure_preserves_conservative_reservation(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
    monkeypatch,
) -> None:
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(),
    )
    monkeypatch.setattr(
        proxy,
        "_apply_mic_conformance_checks",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("injected")),
    )
    monkeypatch.setattr(
        proxy.spend_budget_ledger,
        "cancel",
        lambda **kwargs: (_ for _ in ()).throw(OSError("disk unavailable")),
    )

    with pytest.raises(SpendBudgetError) as exc:
        proxy.evaluate_tool_call(
            session,
            "llm_generate",
            {"input_hash": "bounded"},
            spend_request=_request("compensation-failure"),
        )

    assert exc.value.reason_code == "spend_compensation_failed"
    lineage_id = session.passport_claims["spend_budget"]["lineage_id"]
    snapshot = proxy.spend_budget_ledger.snapshot(lineage_id)
    assert len(snapshot["reservations"]) == 1


def test_proxy_compensation_metrics_cannot_mask_original_failure(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
    monkeypatch,
) -> None:
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(),
    )
    monkeypatch.setattr(
        proxy,
        "_apply_mic_conformance_checks",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("original")),
    )
    monkeypatch.setattr(
        proxy,
        "_record_spend_close_metrics",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("metrics")),
    )

    with pytest.raises(RuntimeError, match="original"):
        proxy.evaluate_tool_call(
            session,
            "llm_generate",
            {"input_hash": "bounded"},
            spend_request=_request("metrics-failure"),
        )

    lineage_id = session.passport_claims["spend_budget"]["lineage_id"]
    assert proxy.spend_budget_ledger.snapshot(lineage_id)["reservations"] == {}


def test_proxy_requires_spend_closure_before_finalization_and_freezes_chain(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
) -> None:
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(),
    )
    request = _request("finalization-gate")
    decision, _ = proxy.evaluate_tool_call(
        session,
        "llm_generate",
        {"input_hash": "bounded"},
        spend_request=request,
    )
    assert decision == Decision.PERMIT

    with pytest.raises(PermissionError, match="spend_reservations_unresolved"):
        proxy.end_session(session)

    proxy.quarantine_spend(
        session,
        request_id=request.request_id,
        reason_code="spend_settlement_evidence_missing",
    )
    proxy.end_session(session)

    with pytest.raises(PermissionError, match="session already finalized"):
        proxy.quarantine_stale_spend(session, older_than_s=0)
    with pytest.raises(PermissionError, match="session already finalized"):
        proxy.quarantine_spend(session, request_id=request.request_id)
    with pytest.raises(PermissionError, match="session already finalized"):
        proxy.settle_spend(
            session,
            request_id=request.request_id,
            actual_input_tokens=1,
            actual_output_tokens=1,
            usage_proof_digest="d" * 64,
        )


@pytest.mark.parametrize(
    ("spend_request", "expected_reason"),
    [
        (_request("missing-quote", quote_id="unknown"), "spend_quote_unknown"),
        (None, "spend_reservation_missing"),
    ],
)
def test_proxy_missing_quote_or_request_fails_closed_with_signed_reason(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
    spend_request,
    expected_reason,
) -> None:
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(),
    )

    decision, reason = proxy.evaluate_tool_call(
        session,
        "llm_generate",
        {"input_hash": "bounded"},
        spend_request=spend_request,
    )

    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == expected_reason
    entry = json.loads(proxy.receipts_log_path.read_text().splitlines()[-1])
    claims = verify_receipt(entry["jwt"], proxy.receipt_public_key)
    assert claims["reason"] == expected_reason
    assert claims["public_denial_reason"] == "insufficient_evidence"


def test_proxy_expired_quote_fails_closed(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
) -> None:
    now = int(time.time())
    proxy = GovernanceProxy(
        log_path=tmp_path / "governance.jsonl",
        receipts_log_path=tmp_path / "receipts.jsonl",
        state_dir=tmp_path / "state",
        keys_dir=session_keys_dir,
        public_key=public_key,
        private_key=private_key,
        spend_quote_store=StaticSpendQuoteStore(
            [_quote(valid_from=now - 100, valid_until=now - 1)]
        ),
    )
    mission = MissionPassport(
        agent_id="metered-agent",
        mission="bounded model call",
        allowed_tools=["llm_generate"],
        resource_scope=["**"],
        spend_budget=_mission_policy(),
    )
    session = proxy.start_session(issue_passport(mission, private_key, ttl_s=300))

    decision, reason = proxy.evaluate_tool_call(
        session,
        "llm_generate",
        {"input_hash": "bounded"},
        spend_request=_request("expired-quote"),
    )
    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == "spend_quote_expired"


def test_proxy_missing_settlement_evidence_quarantines_and_signs_receipt(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
) -> None:
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(),
    )
    request = _request("missing-usage-proof")
    decision, _ = proxy.evaluate_tool_call(
        session,
        "llm_generate",
        {"input_hash": "bounded"},
        spend_request=request,
    )
    assert decision == Decision.PERMIT

    result = proxy.settle_spend(
        session,
        request_id=request.request_id,
        actual_input_tokens=0,
        actual_output_tokens=0,
        usage_proof_digest=None,
    )

    assert result.operation == "quarantine"
    assert result.reason_code == "spend_settlement_evidence_missing"
    entry = json.loads(proxy.receipts_log_path.read_text().splitlines()[-1])
    claims = verify_receipt(entry["jwt"], proxy.receipt_public_key)
    assert claims["verdict"] == "insufficient_evidence"
    assert claims["budget_delta"]["operation"] == "quarantine"
    assert claims["budget_delta"]["reserved"]["tokens"] == 20
    assert request.request_id not in entry["jwt"]


def test_spend_metrics_are_bounded_and_exclude_identifiers(
    tmp_path,
    public_key,
    private_key,
    session_keys_dir,
    monkeypatch,
) -> None:
    isolated_metrics = ArdurMetrics()
    monkeypatch.setattr("vibap.proxy.ardur_metrics", isolated_metrics)
    proxy, session = _spend_proxy(
        tmp_path,
        public_key,
        private_key,
        session_keys_dir,
        _mission_policy(),
    )
    request = _request("private-metric-request")

    decision, _ = proxy.evaluate_tool_call(
        session,
        "llm_generate",
        {"input_hash": "bounded"},
        spend_request=request,
    )
    assert decision == Decision.PERMIT
    proxy.settle_spend(
        session,
        request_id=request.request_id,
        actual_input_tokens=4,
        actual_output_tokens=3,
        usage_proof_digest="f" * 64,
    )

    rendered = isolated_metrics.render()
    assert (
        'ardur_spend_events_total{operation="reserve",outcome="spend_reserved"} 1'
        in rendered
    )
    assert (
        'ardur_spend_events_total{operation="settle",outcome="spend_settled"} 1'
        in rendered
    )
    assert 'ardur_spend_amount_total{operation="reserve",unit="tokens"} 20' in rendered
    assert 'ardur_spend_amount_total{operation="settle",unit="tokens"} 7' in rendered
    assert "private-metric-request" not in rendered
    assert session.jti not in rendered
    assert session.passport_claims["sub"] not in rendered


def test_non_metered_passport_remains_backward_compatible(
    proxy,
    example_mission,
    private_key,
) -> None:
    session = proxy.start_session(
        issue_passport(example_mission, private_key, ttl_s=60)
    )
    decision, reason = proxy.evaluate_tool_call(
        session,
        "read_file",
        {"path": "README.md"},
    )
    assert decision == Decision.PERMIT
    assert reason == "within scope"
    assert session.events[-1].budget_delta["resource"] == "tool_call"

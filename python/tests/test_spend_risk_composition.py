from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import Decision, GovernanceProxy, GovernanceSession
from vibap.receipt import verify_receipt
from vibap.risk_budget import ToolRiskContract, ToolRiskRegistry
from vibap.spend_budget import (
    SpendQuote,
    SpendReservationRequest,
    StaticSpendQuoteStore,
)

_TOOL = "delete_objects"
_ZERO_SPEND = {"tokens": 0, "currency_micros": 0}


def _contract() -> ToolRiskContract:
    return ToolRiskContract.from_schema(
        _TOOL,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 10,
                },
                "bytes": {"type": "integer", "minimum": 0},
                "irreversibility": {
                    "type": "string",
                    "enum": ["reversible", "compensatable", "irreversible"],
                },
            },
            "required": ["targets", "bytes", "irreversibility"],
            "additionalProperties": False,
        },
        {
            "version": 1,
            "mandatory_facts": [
                "objects_affected",
                "bytes_affected",
                "irreversibility",
                "destination_risk",
            ],
            "extractors": {
                "objects_affected": {"kind": "array_length", "pointer": "/targets"},
                "bytes_affected": {"kind": "integer", "pointer": "/bytes"},
                "irreversibility": {"kind": "enum", "pointer": "/irreversibility"},
                "destination_risk": {"kind": "constant", "value": "trusted_service"},
            },
        },
    )


def _risk_policy(contract: ToolRiskContract, *, ceiling: int) -> dict:
    return {
        "version": 1,
        "tools": {
            _TOOL: {
                "contract_digest": contract.digest,
                "max_facts": {
                    "objects_affected": 5,
                    "bytes_affected": 500,
                    "irreversibility": "compensatable",
                    "destination_risk": "trusted_service",
                },
            }
        },
        "ceilings": {
            "objects_affected": {
                "session": ceiling,
                "agent": ceiling,
                "lineage": ceiling,
            },
            "bytes_affected": {
                "session": ceiling * 100,
                "agent": ceiling * 100,
                "lineage": ceiling * 100,
            },
        },
    }


def _spend_policy(*, token_ceiling: int) -> dict:
    return {
        "version": 1,
        "currency": "USD",
        "metered_tools": [_TOOL],
        "ceilings": {
            "tokens": {
                "session": token_ceiling,
                "agent": token_ceiling,
                "lineage": token_ceiling,
            },
            "currency_micros": {
                "session": 100,
                "agent": 100,
                "lineage": 100,
            },
        },
    }


def _quote() -> SpendQuote:
    now = int(time.time())
    return SpendQuote(
        quote_id="quote-composed",
        tool_name=_TOOL,
        model="operator-model-v1",
        currency="USD",
        input_micros_per_million_tokens=1_000_000,
        output_micros_per_million_tokens=1_000_000,
        valid_from=now - 60,
        valid_until=now + 3600,
    )


def _spend_request(request_id: str) -> SpendReservationRequest:
    return SpendReservationRequest(
        request_id=request_id,
        quote_id="quote-composed",
        model="operator-model-v1",
        max_input_tokens=2,
        max_output_tokens=2,
    )


def _arguments(*, count: int = 1) -> dict:
    return {
        "targets": [f"object-{index}" for index in range(count)],
        "bytes": count * 10,
        "irreversibility": "compensatable",
    }


def _combined_proxy(
    tmp_path: Path,
    private_key,
    session_keys_dir: Path,
    *,
    risk_ceiling: int = 5,
    spend_ceiling: int = 20,
    forbidden: bool = False,
) -> tuple[GovernanceProxy, GovernanceSession]:
    contract = _contract()
    registry = ToolRiskRegistry()
    registry.register(contract)
    proxy = GovernanceProxy(
        log_path=tmp_path / "governance.jsonl",
        receipts_log_path=tmp_path / "receipts.jsonl",
        state_dir=tmp_path / "state",
        keys_dir=session_keys_dir,
        public_key=private_key.public_key(),
        private_key=private_key,
        risk_registry=registry,
        spend_quote_store=StaticSpendQuoteStore([_quote()]),
    )
    mission = MissionPassport(
        agent_id="composed-agent",
        mission="bounded destructive provider call",
        allowed_tools=[_TOOL],
        forbidden_tools=[_TOOL] if forbidden else [],
        resource_scope=["**"],
        max_tool_calls=10,
        risk_budget=_risk_policy(contract, ceiling=risk_ceiling),
        spend_budget=_spend_policy(token_ceiling=spend_ceiling),
    )
    session = proxy.start_session(issue_passport(mission, private_key, ttl_s=300))
    return proxy, session


def _assert_exact_zero_authority(proxy: GovernanceProxy, session) -> None:
    spend_lineage = session.passport_claims["spend_budget"]["lineage_id"]
    spend_snapshot = proxy.spend_budget_ledger.snapshot(spend_lineage)
    assert spend_snapshot["reservations"] == {}
    for totals in spend_snapshot["scopes"].values():
        assert totals["reserved"] == _ZERO_SPEND
        assert totals["spent"] == _ZERO_SPEND

    risk_lineage = session.passport_claims["risk_budget"]["lineage_id"]
    risk_snapshot = proxy.risk_budget_ledger.snapshot(risk_lineage)
    for totals in risk_snapshot["accounts"].values():
        assert totals["reserved"] == 0
        assert totals["spent"] == 0


def test_denial_after_both_reservations_restores_exact_authority_and_receipts_both(
    tmp_path: Path,
    private_key,
    session_keys_dir: Path,
) -> None:
    proxy, session = _combined_proxy(
        tmp_path,
        private_key,
        session_keys_dir,
        forbidden=True,
    )

    decision, _ = proxy.evaluate_tool_call(
        session,
        _TOOL,
        _arguments(),
        risk_request_id="risk-both-denied",
        spend_request=_spend_request("spend-both-denied"),
    )

    assert decision == Decision.DENY
    _assert_exact_zero_authority(proxy, session)
    event = session.events[-1]
    assert event.budget_delta is not None
    assert event.budget_delta["operation"] == "release"
    assert event.budget_delta["remaining"]["session"]["tokens"] == 20
    assert event.risk_budget_remaining["objects_affected.session"] == 5
    entry = json.loads(
        proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()[-1]
    )
    claims = verify_receipt(entry["jwt"], proxy.receipt_public_key)
    assert claims["budget_delta"]["resource"] == "spend"
    assert claims["budget_remaining"]["objects_affected.session"] == 5
    assert claims["budget_remaining"]["spend.session.tokens"] == 20


def test_spend_denial_releases_earlier_risk_reservation(
    tmp_path: Path,
    private_key,
    session_keys_dir: Path,
) -> None:
    proxy, session = _combined_proxy(
        tmp_path,
        private_key,
        session_keys_dir,
        spend_ceiling=3,
    )

    decision, reason = proxy.evaluate_tool_call(
        session,
        _TOOL,
        _arguments(),
        risk_request_id="risk-before-spend-denial",
        spend_request=_spend_request("spend-denied"),
    )

    assert (decision, reason) == (Decision.DENY, "spend_session_tokens_exhausted")
    _assert_exact_zero_authority(proxy, session)
    event = session.events[-1]
    assert event.budget_delta is not None
    assert event.budget_delta["operation"] == "reject"
    assert event.risk_budget_remaining["objects_affected.session"] == 5


def test_unified_release_recovers_spend_if_a_later_risk_check_denies(
    tmp_path: Path,
    private_key,
    session_keys_dir: Path,
) -> None:
    proxy, session = _combined_proxy(
        tmp_path,
        private_key,
        session_keys_dir,
        risk_ceiling=1,
    )
    claims = session.passport_claims
    spend_request = _spend_request("spend-before-risk-denial")
    reservations = {}
    spend_result = proxy._reserve_spend_if_required(
        session,
        _TOOL,
        claims,
        spend_request,
        reservations,
    )
    assert spend_result is not None and spend_result.accepted
    risk_result = proxy._risk_preflight(
        session,
        _TOOL,
        _arguments(count=2),
        claims,
        "later-risk-denial",
    )
    assert not risk_result.accepted

    _, first_release = proxy._release_pre_action_reservations(
        reservations,
        spend_reason_code="spend_action_not_permitted",
    )
    _, second_release = proxy._release_pre_action_reservations(
        reservations,
        spend_reason_code="spend_action_not_permitted",
    )

    assert first_release is not None and first_release.operation == "release"
    assert second_release is None
    _assert_exact_zero_authority(proxy, session)


def test_risk_gate_denies_while_spend_budget_has_capacity(
    tmp_path: Path,
    private_key,
    session_keys_dir: Path,
) -> None:
    proxy, session = _combined_proxy(
        tmp_path,
        private_key,
        session_keys_dir,
        risk_ceiling=1,
        spend_ceiling=20,
    )

    decision, reason = proxy.evaluate_tool_call(
        session,
        _TOOL,
        _arguments(count=2),
        risk_request_id="risk-over-budget",
        spend_request=_spend_request("spend-has-capacity"),
    )

    assert (decision, reason) == (Decision.DENY, "risk_budget_exhausted")
    spend_lineage = session.passport_claims["spend_budget"]["lineage_id"]
    spend_snapshot = proxy.spend_budget_ledger.snapshot(spend_lineage)
    assert spend_snapshot["reservations"] == {}
    assert spend_snapshot["scopes"] == {}


def test_exception_after_both_reservations_releases_both_ledgers(
    tmp_path: Path,
    private_key,
    session_keys_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy, session = _combined_proxy(tmp_path, private_key, session_keys_dir)
    monkeypatch.setattr(
        proxy,
        "_build_receipt_log_entry",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("injected")),
    )

    with pytest.raises(RuntimeError, match="injected"):
        proxy.evaluate_tool_call(
            session,
            _TOOL,
            _arguments(),
            risk_request_id="risk-exception",
            spend_request=_spend_request("spend-exception"),
        )

    _assert_exact_zero_authority(proxy, session)


def test_exception_immediately_after_risk_reservation_releases_risk(
    tmp_path: Path,
    private_key,
    session_keys_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy, session = _combined_proxy(tmp_path, private_key, session_keys_dir)

    def fail_after_risk_reserve(*, operation: str, outcome: str, **kwargs) -> None:
        if operation == "reserve" and outcome == "accepted":
            raise RuntimeError("risk metric injected")

    monkeypatch.setattr(proxy, "_risk_metric", fail_after_risk_reserve)

    with pytest.raises(RuntimeError, match="risk metric injected"):
        proxy.evaluate_tool_call(
            session,
            _TOOL,
            _arguments(),
            risk_request_id="risk-post-reserve-exception",
            spend_request=_spend_request("spend-not-reached"),
        )

    _assert_exact_zero_authority(proxy, session)

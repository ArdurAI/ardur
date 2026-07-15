from __future__ import annotations

import json
import multiprocessing
import os
import stat
import threading
from pathlib import Path

import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.canonical_json import canonical_json_bytes
from vibap.passport import (
    MissionPassport,
    derive_child_passport,
    issue_passport,
    verify_passport,
)
from vibap.proxy import Decision, GovernanceProxy
from vibap.risk_budget import (
    FileRiskBudgetLedger,
    RiskBudgetConflictError,
    RiskBudgetError,
    RiskBudgetReplayError,
    RiskFactError,
    ToolRiskContract,
    ToolRiskRegistry,
    attenuate_risk_budget,
    normalize_risk_budget,
    validate_action_risk,
)


@pytest.fixture
def delete_contract() -> ToolRiskContract:
    return ToolRiskContract.from_schema(
        "delete_objects",
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


def _policy(contract: ToolRiskContract, *, ceiling: int = 20) -> dict:
    return {
        "version": 1,
        "lineage_id": "lineage-1",
        "tools": {
            contract.tool_name: {
                "contract_digest": contract.digest,
                "max_facts": {
                    "objects_affected": 5,
                    "bytes_affected": 100,
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


def _reserve(
    ledger: FileRiskBudgetLedger,
    *,
    request_id: str,
    objects: int,
    ceiling: int,
    fingerprint: str | None = None,
):
    ceilings = {
        "objects_affected": {
            "session": ceiling,
            "agent": ceiling,
            "lineage": ceiling,
        }
    }
    return ledger.reserve(
        lineage_id="lineage-1",
        session_id="session-1",
        agent_id="agent-1",
        request_id=request_id,
        fingerprint=fingerprint or f"fingerprint-{request_id}",
        numeric_facts={"objects_affected": objects},
        ceilings=ceilings,
        policy_digest="sha256:" + "1" * 64,
        contract_digest="sha256:" + "2" * 64,
        fact_digest="sha256:" + "3" * 64,
        expires_at=2_000_000_000,
    )


def _append_receipt_once_worker(log_path: str, start_event: object) -> None:
    proxy = object.__new__(GovernanceProxy)
    proxy.receipts_log_path = Path(log_path)
    proxy._receipts_log_lock = threading.Lock()
    proxy._last_seen_receipts_lock = threading.Lock()
    proxy._last_seen_receipts = {}
    start_event.wait(timeout=5)
    proxy._log_receipt_once({"receipt_id": "shared-lifecycle-receipt"})


def test_contract_digest_binds_tool_schema_and_extractors(
    delete_contract: ToolRiskContract,
) -> None:
    same = ToolRiskContract.from_schema(
        delete_contract.tool_name,
        delete_contract.input_schema,
        delete_contract.risk_contract,
    )
    changed_schema = dict(delete_contract.input_schema)
    changed_schema["title"] = "different authenticated definition"
    changed = ToolRiskContract.from_schema(
        delete_contract.tool_name,
        changed_schema,
        delete_contract.risk_contract,
    )

    assert same.digest == delete_contract.digest
    assert changed.digest != delete_contract.digest
    assert delete_contract.digest.startswith("sha256:")


def test_contract_extracts_typed_facts_without_trusting_caller_labels(
    delete_contract: ToolRiskContract,
) -> None:
    facts = delete_contract.extract(
        {
            "targets": ["a", "b"],
            "bytes": 80,
            "irreversibility": "compensatable",
        }
    )

    assert facts == {
        "objects_affected": 2,
        "bytes_affected": 80,
        "irreversibility": "compensatable",
        "destination_risk": "trusted_service",
    }


@pytest.mark.parametrize("bad_bytes", [True, 1.5, -1])
def test_contract_rejects_non_exact_or_negative_integers(
    delete_contract: ToolRiskContract,
    bad_bytes: object,
) -> None:
    with pytest.raises(RiskFactError):
        delete_contract.extract(
            {
                "targets": ["a"],
                "bytes": bad_bytes,
                "irreversibility": "reversible",
            }
        )


def test_contract_rejects_external_schema_reference() -> None:
    with pytest.raises(RiskBudgetError, match="external JSON Schema references"):
        ToolRiskContract.from_schema(
            "dangerous",
            {"$ref": "https://attacker.example/schema.json"},
            {
                "version": 1,
                "mandatory_facts": ["objects_affected"],
                "extractors": {"objects_affected": {"kind": "constant", "value": 1}},
            },
        )


def test_contract_rejects_ambiguous_json_pointer_escape() -> None:
    with pytest.raises(RiskBudgetError, match="pointer is invalid"):
        ToolRiskContract.from_schema(
            "dangerous",
            {"type": "object"},
            {
                "version": 1,
                "mandatory_facts": ["objects_affected"],
                "extractors": {
                    "objects_affected": {
                        "kind": "integer",
                        "pointer": "/count~2shadow",
                    }
                },
            },
        )


def test_registry_cannot_replace_or_mutate_contracts_after_freeze(
    delete_contract: ToolRiskContract,
) -> None:
    registry = ToolRiskRegistry()
    registry.register(delete_contract)
    with pytest.raises(RiskBudgetConflictError):
        registry.register(delete_contract)
    registry.freeze()
    with pytest.raises(RuntimeError, match="frozen"):
        registry.register(
            ToolRiskContract.from_schema(
                "other",
                {"type": "object"},
                {
                    "version": 1,
                    "mandatory_facts": ["objects_affected"],
                    "extractors": {
                        "objects_affected": {"kind": "constant", "value": 1}
                    },
                },
            )
        )


def test_contract_nested_views_cannot_mutate_registered_authority(
    delete_contract: ToolRiskContract,
) -> None:
    original_digest = delete_contract.digest
    schema_view = delete_contract.input_schema
    contract_view = delete_contract.risk_contract
    schema_view["properties"]["bytes"]["minimum"] = -100
    contract_view["extractors"]["bytes_affected"]["pointer"] = "/shadow"

    assert delete_contract.digest == original_digest
    assert delete_contract.input_schema["properties"]["bytes"]["minimum"] == 0
    assert (
        delete_contract.risk_contract["extractors"]["bytes_affected"]["pointer"]
        == "/bytes"
    )
    assert (
        delete_contract.extract(
            {
                "targets": ["a"],
                "bytes": 1,
                "irreversibility": "reversible",
            }
        )["bytes_affected"]
        == 1
    )


def test_policy_normalization_is_closed_and_requires_all_numeric_scopes(
    delete_contract: ToolRiskContract,
) -> None:
    policy = _policy(delete_contract)
    assert normalize_risk_budget(policy) == policy

    policy["ceilings"]["objects_affected"].pop("lineage")
    with pytest.raises(RiskBudgetError, match="session, agent, and lineage"):
        normalize_risk_budget(policy)


def test_policy_rejects_noncanonical_uppercase_contract_digest(
    delete_contract: ToolRiskContract,
) -> None:
    policy = _policy(delete_contract)
    policy["tools"][delete_contract.tool_name]["contract_digest"] = (
        delete_contract.digest.upper().replace("SHA256:", "sha256:")
    )

    with pytest.raises(RiskBudgetError, match="lowercase hex"):
        normalize_risk_budget(policy)


def test_policy_rejects_colliding_normalized_tool_names(
    delete_contract: ToolRiskContract,
) -> None:
    policy = _policy(delete_contract)
    policy["tools"][" delete_objects "] = copy = json.loads(
        json.dumps(policy["tools"]["delete_objects"])
    )
    assert copy

    with pytest.raises(RiskBudgetError, match="duplicate normalized tool name"):
        normalize_risk_budget(policy)


def test_child_policy_can_only_reduce_authority(
    delete_contract: ToolRiskContract,
) -> None:
    parent = _policy(delete_contract)
    child = json.loads(json.dumps(parent))
    child["tools"][delete_contract.tool_name]["max_facts"]["objects_affected"] = 2
    child["tools"][delete_contract.tool_name]["max_facts"]["irreversibility"] = (
        "reversible"
    )
    child["ceilings"]["objects_affected"]["session"] = 10
    assert attenuate_risk_budget(parent, child) == child

    escalated = json.loads(json.dumps(child))
    escalated["tools"][delete_contract.tool_name]["max_facts"]["objects_affected"] = 6
    with pytest.raises(PermissionError, match="cap escalation"):
        attenuate_risk_budget(parent, escalated)


def test_child_policy_cannot_switch_lineage(delete_contract: ToolRiskContract) -> None:
    parent = _policy(delete_contract)
    child = json.loads(json.dumps(parent))
    child["lineage_id"] = "attacker-lineage"

    with pytest.raises(PermissionError, match="lineage_id escalation"):
        attenuate_risk_budget(parent, child)


def test_action_check_enforces_contract_digest_and_typed_caps(
    delete_contract: ToolRiskContract,
) -> None:
    facts = delete_contract.extract(
        {
            "targets": ["a", "b"],
            "bytes": 80,
            "irreversibility": "compensatable",
        }
    )
    assert validate_action_risk(_policy(delete_contract), delete_contract, facts) == {
        "objects_affected": 2,
        "bytes_affected": 80,
    }

    facts["irreversibility"] = "irreversible"
    with pytest.raises(RiskBudgetError, match="risk_action_cap_exceeded"):
        validate_action_risk(_policy(delete_contract), delete_contract, facts)


def test_reserve_is_atomic_across_scopes_and_keeps_identifiers_private(
    tmp_path: Path,
) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    result = _reserve(ledger, request_id="request-secret", objects=2, ceiling=3)

    assert result.accepted
    assert result.remaining == {
        "objects_affected.session": 1,
        "objects_affected.agent": 1,
        "objects_affected.lineage": 1,
    }
    snapshot = ledger.snapshot("lineage-1")
    serialized = canonical_json_bytes(snapshot)
    assert b"request-secret" not in serialized
    assert b"session-1" not in serialized
    assert b"agent-1" not in serialized
    assert b"lineage-1" not in serialized
    assert stat.S_IMODE(os.stat(ledger.ledger_dir).st_mode) == 0o700
    ledger_file = next(ledger.ledger_dir.glob("*.json"))
    assert stat.S_IMODE(os.stat(ledger_file).st_mode) == 0o600


def test_same_request_never_reauthorizes_and_conflicting_retry_is_detected(
    tmp_path: Path,
) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    _reserve(ledger, request_id="request-1", objects=1, ceiling=5)

    with pytest.raises(RiskBudgetReplayError, match="already recorded as active"):
        _reserve(ledger, request_id="request-1", objects=1, ceiling=5)
    with pytest.raises(RiskBudgetConflictError, match="different semantics"):
        _reserve(
            ledger,
            request_id="request-1",
            objects=1,
            ceiling=5,
            fingerprint="changed",
        )


def test_sibling_session_cannot_close_or_quarantine_reservation(tmp_path: Path) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    _reserve(ledger, request_id="owned-request", objects=1, ceiling=5)

    with pytest.raises(RiskBudgetConflictError, match="different session"):
        ledger.record_outcome(
            lineage_id="lineage-1",
            session_id="session-2",
            request_id="owned-request",
            outcome="released",
        )
    assert (
        ledger.quarantine_stale(
            lineage_id="lineage-1",
            session_id="session-2",
            stale_before=2_000_000_000,
        )
        == []
    )
    assert (
        ledger.record_outcome(
            lineage_id="lineage-1",
            session_id="session-1",
            request_id="owned-request",
            outcome="released",
        ).status
        == "released"
    )


def test_concurrent_workers_cannot_oversubscribe_lineage_ceiling(
    tmp_path: Path,
) -> None:
    ledgers = [FileRiskBudgetLedger(tmp_path), FileRiskBudgetLedger(tmp_path)]
    barrier = threading.Barrier(2)
    results: list[bool] = []
    failures: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            barrier.wait()
            result = _reserve(
                ledgers[index],
                request_id=f"request-{index}",
                objects=1,
                ceiling=1,
            )
            results.append(result.accepted)
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not failures
    assert sorted(results) == [False, True]


def test_commit_spends_authority_and_release_returns_it(tmp_path: Path) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    _reserve(ledger, request_id="commit", objects=2, ceiling=3)
    committed = ledger.record_outcome(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="commit",
        outcome="committed",
    )
    assert committed.remaining["objects_affected.lineage"] == 1
    assert ledger.record_outcome(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="commit",
        outcome="committed",
    ).idempotent

    _reserve(ledger, request_id="release", objects=1, ceiling=3)
    released = ledger.record_outcome(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="release",
        outcome="released",
    )
    assert released.remaining["objects_affected.lineage"] == 1
    with pytest.raises(RiskBudgetConflictError, match="not reconcilable"):
        ledger.record_outcome(
            lineage_id="lineage-1",
            session_id="session-1",
            request_id="release",
            outcome="committed",
        )


def test_stale_reservation_is_quarantined_without_returning_authority(
    tmp_path: Path,
) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    _reserve(ledger, request_id="stale", objects=2, ceiling=2)

    quarantined = ledger.quarantine_stale(
        lineage_id="lineage-1",
        session_id="session-1",
        stale_before=2_000_000_000,
    )
    assert len(quarantined) == 1
    assert ledger.unresolved_for_session(
        lineage_id="lineage-1", session_id="session-1"
    ) == [result.request_hash for result in quarantined]
    blocked = _reserve(ledger, request_id="next", objects=1, ceiling=2)
    assert not blocked.accepted
    assert blocked.blocking_scope == "session"

    ledger.mark_lifecycle_delivered(
        lineage_id="lineage-1",
        session_id="session-1",
        request_hash=quarantined[0].request_hash,
        lifecycle_id=quarantined[0].lifecycle_id,
        receipt_id="receipt-quarantine",
    )
    reconciled = ledger.record_outcome(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="stale",
        outcome="committed",
    )
    assert reconciled.status == "committed"


def test_pruning_terminal_records_preserves_committed_authority(tmp_path: Path) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    _reserve(ledger, request_id="committed", objects=2, ceiling=3)
    committed = ledger.record_outcome(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="committed",
        outcome="committed",
    )
    _reserve(ledger, request_id="released", objects=1, ceiling=3)
    released = ledger.record_outcome(
        lineage_id="lineage-1",
        session_id="session-1",
        request_id="released",
        outcome="released",
    )
    ledger.mark_lifecycle_delivered(
        lineage_id="lineage-1",
        session_id="session-1",
        request_hash=committed.request_hash,
        lifecycle_id=committed.lifecycle_id,
        receipt_id="receipt-committed",
    )
    ledger.mark_lifecycle_delivered(
        lineage_id="lineage-1",
        session_id="session-1",
        request_hash=released.request_hash,
        lifecycle_id=released.lifecycle_id,
        receipt_id="receipt-released",
    )

    result = ledger.prune_expired(lineage_id="lineage-1", now=2_000_000_001)
    snapshot = ledger.snapshot("lineage-1")
    assert result == {"pruned": 2, "quarantined": 0}
    assert snapshot["reservations"] == {}
    assert len(snapshot["tombstones"]) == 2
    assert all(account["spent"] == 2 for account in snapshot["accounts"].values())
    assert all(
        account["archived_spent"] == 2 for account in snapshot["accounts"].values()
    )
    blocked = _reserve(ledger, request_id="too-large", objects=2, ceiling=3)
    assert not blocked.accepted

    with pytest.raises(RiskBudgetReplayError, match="already archived"):
        _reserve(ledger, request_id="committed", objects=2, ceiling=3)


def test_quarantined_reservation_can_only_reconcile_as_committed(
    tmp_path: Path,
) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    _reserve(ledger, request_id="uncertain", objects=1, ceiling=2)
    quarantined = ledger.quarantine_stale(
        lineage_id="lineage-1",
        session_id="session-1",
        stale_before=2_000_000_000,
    )

    with pytest.raises(RiskBudgetConflictError, match="cannot be released"):
        ledger.record_outcome(
            lineage_id="lineage-1",
            session_id="session-1",
            request_id="uncertain",
            outcome="released",
        )

    ledger.mark_lifecycle_delivered(
        lineage_id="lineage-1",
        session_id="session-1",
        request_hash=quarantined[0].request_hash,
        lifecycle_id=quarantined[0].lifecycle_id,
        receipt_id="receipt-quarantine",
    )
    assert (
        ledger.record_outcome(
            lineage_id="lineage-1",
            session_id="session-1",
            request_id="uncertain",
            outcome="committed",
        ).status
        == "committed"
    )


def test_bounded_quarantine_archives_spend_but_retains_pending_outbox(
    tmp_path: Path,
) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    _reserve(ledger, request_id="abandoned", objects=1, ceiling=2)
    quarantined = ledger.quarantine_stale(
        lineage_id="lineage-1",
        session_id="session-1",
        stale_before=2_000_000_000,
        now=1_900_000_000,
    )

    ledger.prune_expired(lineage_id="lineage-1", now=2_000_000_001)
    snapshot = ledger.snapshot("lineage-1")
    assert snapshot["reservations"] == {}
    tombstone = snapshot["tombstones"][quarantined[0].request_hash]
    assert tombstone["status"] == "quarantined_committed"
    assert tombstone["lifecycle"]["state"] == "pending"
    assert all(account["reserved"] == 0 for account in snapshot["accounts"].values())
    assert all(account["spent"] == 1 for account in snapshot["accounts"].values())
    assert ledger.unresolved_for_session(
        lineage_id="lineage-1", session_id="session-1"
    ) == [quarantined[0].request_hash]

    recovered = ledger.quarantine_stale(
        lineage_id="lineage-1",
        session_id="session-1",
        stale_before=2_000_000_000,
    )
    assert len(recovered) == 1
    assert recovered[0].idempotent is True
    ledger.mark_lifecycle_delivered(
        lineage_id="lineage-1",
        session_id="session-1",
        request_hash=recovered[0].request_hash,
        lifecycle_id=recovered[0].lifecycle_id,
        receipt_id="receipt-recovered-quarantine",
    )
    ledger.prune_expired(
        lineage_id="lineage-1",
        now=tombstone["replay_until"] + 1,
    )
    assert ledger.snapshot("lineage-1")["tombstones"] == {}


def test_ledger_rejects_symlink_substitution(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (state_dir / "risk_budgets").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RiskBudgetError, match="must not be a symlink"):
        FileRiskBudgetLedger(state_dir)


def test_corrupt_ledger_fails_closed(tmp_path: Path) -> None:
    ledger = FileRiskBudgetLedger(tmp_path)
    _reserve(ledger, request_id="request-1", objects=1, ceiling=5)
    ledger_file = next(ledger.ledger_dir.glob("*.json"))
    payload = json.loads(ledger_file.read_text(encoding="utf-8"))
    account = next(iter(payload["accounts"].values()))
    account["reserved"] = 0
    ledger_file.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RiskBudgetError, match="reserved invariant"):
        ledger.snapshot("lineage-1")


def test_root_passport_binds_omitted_risk_lineage_to_signed_jti(
    delete_contract: ToolRiskContract,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    policy = _policy(delete_contract)
    policy.pop("lineage_id")
    mission = MissionPassport(
        agent_id="agent-1",
        mission="delete bounded objects",
        allowed_tools=["delete_objects"],
        risk_budget=policy,
    )

    token = issue_passport(mission, private_key, ttl_s=60)
    claims = verify_passport(token, private_key.public_key())
    assert claims["risk_budget"]["lineage_id"] == claims["jti"]
    assert claims["risk_budget"]["tools"]["delete_objects"]["contract_digest"] == (
        delete_contract.digest
    )


def test_passport_risk_policy_cannot_escape_tool_allowlist(
    delete_contract: ToolRiskContract,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    mission = MissionPassport(
        agent_id="agent-1",
        mission="read only",
        allowed_tools=["read_file"],
        risk_budget=_policy(delete_contract),
    )

    with pytest.raises(ValueError, match="subset of allowed_tools"):
        issue_passport(mission, private_key, ttl_s=60)


def test_extra_claims_cannot_replace_validated_risk_policy(
    delete_contract: ToolRiskContract,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    mission = MissionPassport(
        agent_id="agent-1",
        mission="delete bounded objects",
        allowed_tools=["delete_objects"],
        risk_budget=_policy(delete_contract),
    )

    with pytest.raises(ValueError, match="cannot override"):
        issue_passport(
            mission,
            private_key,
            ttl_s=60,
            extra_claims={"risk_budget": {}},
        )


def test_delegated_passport_attenuates_risk_policy(
    delete_contract: ToolRiskContract,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    parent_policy = _policy(delete_contract)
    parent = issue_passport(
        MissionPassport(
            agent_id="parent",
            mission="coordinate bounded deletion",
            allowed_tools=["delete_objects"],
            delegation_allowed=True,
            max_delegation_depth=1,
            risk_budget=parent_policy,
        ),
        private_key,
        ttl_s=60,
    )
    child_policy = json.loads(json.dumps(parent_policy))
    child_policy["tools"]["delete_objects"]["max_facts"]["objects_affected"] = 2
    child_policy["ceilings"]["objects_affected"]["session"] = 2

    child = derive_child_passport(
        parent,
        private_key.public_key(),
        private_key,
        "child",
        ["delete_objects"],
        "delete two objects",
        child_risk_budget=child_policy,
    )
    claims = verify_passport(child, private_key.public_key(), parent_token=parent)
    assert claims["risk_budget"] == child_policy


def test_ungoverned_parent_cannot_introduce_child_risk_policy(
    delete_contract: ToolRiskContract,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    parent = issue_passport(
        MissionPassport(
            agent_id="parent",
            mission="legacy parent",
            allowed_tools=["delete_objects"],
            delegation_allowed=True,
            max_delegation_depth=1,
        ),
        private_key,
        ttl_s=60,
    )

    with pytest.raises(PermissionError, match="parent has none"):
        derive_child_passport(
            parent,
            private_key.public_key(),
            private_key,
            "child",
            ["delete_objects"],
            "attempt to add policy",
            child_risk_budget=_policy(delete_contract),
        )


def test_absent_risk_policy_preserves_legacy_mission_dict_shape() -> None:
    mission = MissionPassport(
        agent_id="legacy",
        mission="read",
        allowed_tools=["read_file"],
    )

    assert "risk_budget" not in mission.to_dict()
    with pytest.raises(ValueError, match="must be a JSON object"):
        MissionPassport.from_dict(
            {
                "agent_id": "invalid",
                "mission": "read",
                "allowed_tools": ["read_file"],
                "risk_budget": None,
            }
        )


def _governed_proxy(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    keys_dir: Path,
    contract: ToolRiskContract,
) -> GovernanceProxy:
    registry = ToolRiskRegistry()
    registry.register(contract)
    return GovernanceProxy(
        log_path=tmp_path / "governance.jsonl",
        receipts_log_path=tmp_path / "receipts.jsonl",
        state_dir=tmp_path / "state",
        keys_dir=keys_dir,
        public_key=private_key.public_key(),
        private_key=private_key,
        risk_registry=registry,
    )


def _start_governed_session(
    proxy: GovernanceProxy,
    private_key: ec.EllipticCurvePrivateKey,
    contract: ToolRiskContract,
    *,
    forbidden: bool = False,
    ceiling: int = 20,
):
    mission = MissionPassport(
        agent_id="risk-agent",
        mission="bounded object deletion",
        allowed_tools=["delete_objects"],
        forbidden_tools=["delete_objects"] if forbidden else [],
        resource_scope=["**"],
        max_tool_calls=10,
        risk_budget=_policy(contract, ceiling=ceiling),
    )
    return proxy.start_session(issue_passport(mission, private_key, ttl_s=60))


def _safe_delete_arguments(*, count: int = 2, byte_count: int = 80) -> dict:
    return {
        "targets": [f"object-{index}" for index in range(count)],
        "bytes": byte_count,
        "irreversibility": "compensatable",
    }


def test_proxy_requires_request_id_before_governed_action(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(proxy, private_key, delete_contract)

    decision, reason = proxy.evaluate_tool_call(
        session,
        "delete_objects",
        _safe_delete_arguments(),
    )

    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == "risk_request_id_invalid"
    assert session.tool_call_count == 0


def test_proxy_permit_requires_explicit_outcome_and_lifecycle_is_not_tool_counted(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(proxy, private_key, delete_contract)

    decision, reason = proxy.evaluate_tool_call(
        session,
        "delete_objects",
        _safe_delete_arguments(),
        risk_request_id="private-request-1",
    )
    assert (decision, reason) == (Decision.PERMIT, "within scope")
    with pytest.raises(PermissionError, match="risk_budget_outcome_unresolved"):
        proxy.end_session(session)

    outcome = proxy.record_risk_outcome(
        session,
        risk_request_id="private-request-1",
        outcome="committed",
    )
    assert outcome["status"] == "committed"
    assert outcome["receipt_id"]
    proxy.record_tool_result(session, "executor response", 12.5)
    summary = proxy.end_session(session)
    assert summary["total_events"] == 1
    assert summary["permits"] == 1
    assert len(session.events) == 2
    assert session.events[0].response == "executor response"
    assert session.events[0].duration_ms == 12.5
    assert session.events[-1].tool_name == "risk_budget_lifecycle"
    assert session.events[-1].response is None

    receipt_text = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8")
    assert "private-request-1" not in receipt_text
    assert "object-0" not in receipt_text
    receipt_claims = [
        jwt.decode(
            json.loads(line)["jwt"],
            private_key.public_key(),
            algorithms=["ES256"],
            options={"verify_aud": False},
        )
        for line in receipt_text.splitlines()
    ]
    assert all("risk_facts" in claims["measurements"] for claims in receipt_claims)
    assert (
        len(
            {claims["measurements"]["risk_facts"]["value"] for claims in receipt_claims}
        )
        == 1
    )


def test_proxy_outcome_retry_recovers_same_persisted_receipt_after_log_failure(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(proxy, private_key, delete_contract)
    assert (
        proxy.evaluate_tool_call(
            session,
            "delete_objects",
            _safe_delete_arguments(),
            risk_request_id="outbox-retry",
        )[0]
        == Decision.PERMIT
    )

    original_log_once = proxy._log_receipt_once

    def fail_before_append(_entry: dict) -> None:
        raise OSError("simulated receipt log failure")

    monkeypatch.setattr(proxy, "_log_receipt_once", fail_before_append)
    with pytest.raises(OSError, match="simulated receipt log failure"):
        proxy.record_risk_outcome(
            session,
            risk_request_id="outbox-retry",
            outcome="committed",
        )
    snapshot = proxy.risk_budget_ledger.snapshot("lineage-1")
    reservation = next(iter(snapshot["reservations"].values()))
    assert reservation["lifecycle"]["state"] == "pending"

    monkeypatch.setattr(proxy, "_log_receipt_once", original_log_once)
    recovered = proxy.record_risk_outcome(
        session,
        risk_request_id="outbox-retry",
        outcome="committed",
    )
    assert recovered["idempotent"] is True
    assert recovered["receipt_id"]
    lifecycle_events = [
        event for event in session.events if event.reason == "risk_outcome_committed"
    ]
    assert len(lifecycle_events) == 1
    assert (
        lifecycle_events[0].risk_receipt_entry["receipt_id"] == recovered["receipt_id"]
    )
    receipt_lines = [
        json.loads(line)
        for line in (tmp_path / "receipts.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert (
        sum(line["receipt_id"] == recovered["receipt_id"] for line in receipt_lines)
        == 1
    )
    delivered = proxy.risk_budget_ledger.snapshot("lineage-1")
    assert next(iter(delivered["reservations"].values()))["lifecycle"]["state"] == (
        "delivered"
    )


def test_proxy_rejects_mid_session_risk_policy_rotation(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(proxy, private_key, delete_contract)
    original_resolve = proxy._resolve_authoritative_policy_claims
    assert (
        proxy.evaluate_tool_call(
            session,
            "delete_objects",
            _safe_delete_arguments(count=1),
            risk_request_id="snapshot-first",
        )[0]
        == Decision.PERMIT
    )
    proxy.record_risk_outcome(
        session,
        risk_request_id="snapshot-first",
        outcome="committed",
    )
    frozen_snapshot = json.loads(json.dumps(session.risk_policy_snapshot))

    def rotated_policy(claims: dict) -> dict:
        rotated = json.loads(json.dumps(original_resolve(claims)))
        rotated["risk_budget"]["ceilings"]["objects_affected"]["session"] += 1
        return rotated

    monkeypatch.setattr(proxy, "_resolve_authoritative_policy_claims", rotated_policy)
    decision, reason = proxy.evaluate_tool_call(
        session,
        "delete_objects",
        _safe_delete_arguments(count=1),
        risk_request_id="snapshot-second",
    )

    assert (decision, reason) == (
        Decision.INSUFFICIENT_EVIDENCE,
        "risk_policy_invalid",
    )
    assert session.risk_policy_snapshot == frozen_snapshot

    session.risk_policy_snapshot["ceilings"]["objects_affected"]["session"] = 999
    proxy.summarize_session(session)
    assert session.risk_policy_snapshot == frozen_snapshot


def test_proxy_replay_cannot_repermit_after_terminal_outcome(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(proxy, private_key, delete_contract)
    arguments = _safe_delete_arguments()
    assert (
        proxy.evaluate_tool_call(
            session,
            "delete_objects",
            arguments,
            risk_request_id="request-1",
        )[0]
        == Decision.PERMIT
    )
    proxy.record_risk_outcome(
        session,
        risk_request_id="request-1",
        outcome="released",
    )

    decision, reason = proxy.evaluate_tool_call(
        session,
        "delete_objects",
        arguments,
        risk_request_id="request-1",
    )
    assert (decision, reason) == (Decision.DENY, "risk_request_replay")
    assert session.tool_call_count == 1


def test_proxy_quarantine_keeps_authority_until_explicit_reconciliation(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(proxy, private_key, delete_contract)
    assert (
        proxy.evaluate_tool_call(
            session,
            "delete_objects",
            _safe_delete_arguments(),
            risk_request_id="crashed-request",
        )[0]
        == Decision.PERMIT
    )

    assert (
        proxy.quarantine_stale_risk_reservations(
            session,
            stale_after_s=0,
        )
        == 1
    )
    assert session.events[-1].reason == "risk_outcome_quarantined"
    with pytest.raises(PermissionError, match="risk_budget_outcome_unresolved"):
        proxy.end_session(session)

    proxy.record_risk_outcome(
        session,
        risk_request_id="crashed-request",
        outcome="committed",
    )
    summary = proxy.end_session(session)
    assert summary["total_events"] == 1
    assert summary["permits"] == 1


def test_proxy_ordinary_policy_denial_releases_preflight_reservation(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(
        proxy,
        private_key,
        delete_contract,
        forbidden=True,
    )

    decision, _ = proxy.evaluate_tool_call(
        session,
        "delete_objects",
        _safe_delete_arguments(),
        risk_request_id="denied-request",
    )
    assert decision == Decision.DENY
    snapshot = proxy.risk_budget_ledger.snapshot("lineage-1")
    reservation = next(iter(snapshot["reservations"].values()))
    assert reservation["status"] == "released"
    with pytest.raises(ValueError, match="prior permitted tool event"):
        proxy.record_tool_result(session, "must not attach", 1.0)
    assert proxy.end_session(session)["denials"] == 1


def test_receipt_outbox_deduplicates_across_proxy_processes(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipts.jsonl"
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    processes = [
        context.Process(
            target=_append_receipt_once_worker,
            args=(str(receipt_path), start_event),
        )
        for _ in range(4)
    ]
    for process in processes:
        process.start()
    start_event.set()
    for process in processes:
        process.join(timeout=10)

    assert [process.exitcode for process in processes] == [0, 0, 0, 0]
    entries = [
        json.loads(line)
        for line in receipt_path.read_text(encoding="utf-8").splitlines()
    ]
    assert entries == [{"receipt_id": "shared-lifecycle-receipt"}]
    assert stat.S_IMODE(
        os.stat(receipt_path.with_name("receipts.jsonl.lock")).st_mode
    ) == (0o600)


def test_session_finalization_flushes_failed_policy_denial_outbox(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(
        proxy,
        private_key,
        delete_contract,
        forbidden=True,
    )
    original_log_once = proxy._log_receipt_once

    def fail_before_append(_entry: dict) -> None:
        raise OSError("simulated denial receipt log failure")

    monkeypatch.setattr(proxy, "_log_receipt_once", fail_before_append)
    with pytest.raises(OSError, match="simulated denial receipt log failure"):
        proxy.evaluate_tool_call(
            session,
            "delete_objects",
            _safe_delete_arguments(),
            risk_request_id="denial-outbox",
        )
    pending = proxy.risk_budget_ledger.pending_lifecycles_for_session(
        lineage_id="lineage-1",
        session_id=session.jti,
    )
    assert len(pending) == 1
    assert pending[0].status == "released"

    monkeypatch.setattr(proxy, "_log_receipt_once", original_log_once)
    summary = proxy.end_session(session)
    assert summary["denials"] == 1
    assert (
        proxy.risk_budget_ledger.pending_lifecycles_for_session(
            lineage_id="lineage-1",
            session_id=session.jti,
        )
        == []
    )
    receipt_id = next(
        event.risk_receipt_entry["receipt_id"]
        for event in session.events
        if event.risk_lifecycle_id == pending[0].lifecycle_id
    )
    receipt_lines = [
        json.loads(line)
        for line in (tmp_path / "receipts.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert sum(line["receipt_id"] == receipt_id for line in receipt_lines) == 1


def test_proxy_enforces_action_and_cumulative_caps_before_native_permit(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    session = _start_governed_session(
        proxy,
        private_key,
        delete_contract,
        ceiling=2,
    )

    action_cap_decision, action_cap_reason = proxy.evaluate_tool_call(
        session,
        "delete_objects",
        _safe_delete_arguments(count=6),
        risk_request_id="over-action-cap",
    )
    assert (action_cap_decision, action_cap_reason) == (
        Decision.DENY,
        "risk_action_cap_exceeded",
    )
    assert (
        proxy.evaluate_tool_call(
            session,
            "delete_objects",
            _safe_delete_arguments(count=2),
            risk_request_id="fills-budget",
        )[0]
        == Decision.PERMIT
    )

    cumulative_decision, cumulative_reason = proxy.evaluate_tool_call(
        session,
        "delete_objects",
        _safe_delete_arguments(count=1),
        risk_request_id="over-cumulative-cap",
    )
    assert (cumulative_decision, cumulative_reason) == (
        Decision.DENY,
        "risk_budget_exhausted",
    )
    assert session.tool_call_count == 1


def test_proxy_registered_dangerous_tool_cannot_be_omitted_from_opted_in_policy(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    policy = _policy(delete_contract)
    policy["tools"] = {
        "unrelated_tool": {
            "contract_digest": delete_contract.digest,
            "max_facts": policy["tools"]["delete_objects"]["max_facts"],
        }
    }
    mission = MissionPassport(
        agent_id="risk-agent",
        mission="malformed risk coverage",
        allowed_tools=["delete_objects", "unrelated_tool"],
        resource_scope=["**"],
        risk_budget=policy,
    )
    session = proxy.start_session(issue_passport(mission, private_key, ttl_s=60))

    decision, reason = proxy.evaluate_tool_call(
        session,
        "delete_objects",
        _safe_delete_arguments(),
        risk_request_id="request-1",
    )
    assert (decision, reason) == (
        Decision.INSUFFICIENT_EVIDENCE,
        "risk_contract_invalid",
    )


def test_proxy_delegation_persists_attenuated_child_risk_policy(
    tmp_path: Path,
    private_key: ec.EllipticCurvePrivateKey,
    session_keys_dir: Path,
    delete_contract: ToolRiskContract,
) -> None:
    proxy = _governed_proxy(tmp_path, private_key, session_keys_dir, delete_contract)
    parent_policy = _policy(delete_contract)
    parent_token = issue_passport(
        MissionPassport(
            agent_id="parent",
            mission="coordinate bounded deletion",
            allowed_tools=["delete_objects"],
            resource_scope=["**"],
            max_tool_calls=5,
            delegation_allowed=True,
            max_delegation_depth=1,
            risk_budget=parent_policy,
        ),
        private_key,
        ttl_s=60,
    )
    parent_session = proxy.start_session(parent_token)
    child_policy = json.loads(json.dumps(parent_policy))
    child_policy["tools"]["delete_objects"]["max_facts"]["objects_affected"] = 1
    child_policy["ceilings"]["objects_affected"]["session"] = 1

    child_token, child_claims, _ = proxy.delegate_passport(
        parent_token,
        private_key,
        "child",
        ["delete_objects"],
        "delete one object",
        child_max_tool_calls=1,
        child_risk_budget=child_policy,
        delegation_request_id="delegation-1",
    )
    assert child_claims["risk_budget"] == child_policy
    assert (
        verify_passport(
            child_token,
            private_key.public_key(),
            parent_token=parent_token,
        )["risk_budget"]
        == child_policy
    )
    child_record = parent_session.delegated_children[0]
    assert child_record["child_risk_budget"] == child_policy
    assert child_record["delegation_request"]["child_risk_budget"] == child_policy

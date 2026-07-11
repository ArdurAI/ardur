from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.canonical_json import canonical_json_bytes
from vibap.cli import main as cli_main
from vibap.drp import (
    ARDUR_CRITICAL_PATHS,
    DRPEmissionError,
    DRPProfileError,
    DRPVerificationContext,
    DRPVerificationError,
    DRPVerifiedLogEvidence,
    DRPVerifiedReceiptChainEvidence,
    DRPVerifiedRevocationEvidence,
    emit_drp_receipt,
    load_drp_receipt,
    tool_universe_digest,
    validate_drp_receipt,
    verify_drp_chain,
)
from vibap.drp_fixture import (
    PUBLIC_KEY_FILES,
    run_drp_profile_fixture,
    verify_drp_profile_fixture,
    DrpFixtureOutputError,
)


UTC = timezone.utc
DECISION_TIME = datetime(2027, 1, 15, 8, 5, tzinfo=UTC)
INSTRUCTIONS = "Read the approved calendar data for the team."
UNIVERSE = [
    {"operation": "read", "resource": "tool://calendar/team"},
    {"operation": "read", "resource": "tool://calendar/personal"},
    {"operation": "write", "resource": "tool://calendar/team"},
    {"operation": "delete", "resource": "tool://calendar/team"},
]
TOOL_DIGEST = tool_universe_digest(UNIVERSE)
ISSUERS = (
    "spiffe://fixture.test/user/alice",
    "spiffe://fixture.test/orchestrator/calendar",
    "spiffe://fixture.test/agent/calendar-reader",
)
SUBJECTS = (
    ISSUERS[1],
    ISSUERS[2],
    "spiffe://fixture.test/tool/calendar",
)
REPO_ROOT = Path(__file__).resolve().parents[2]


def _sha256_prefixed(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha_dash256_prefixed(value: str) -> str:
    return "sha-256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _token_hash(index: int) -> str:
    return hashlib.sha256(f"aat-token-{index}".encode()).hexdigest()


def _authorization(
    index: int,
    allowed_actions: list[dict[str, str]],
    *,
    parent_receipt_id: str | None = None,
    parent_token_hash: str | None = None,
    mode: str = "bounded",
    max_depth: int = 4,
    not_after: datetime | None = None,
    budget: int | None = None,
) -> dict[str, Any]:
    start = DECISION_TIME - timedelta(minutes=5 - index)
    end = not_after or DECISION_TIME + timedelta(minutes=10 - index)
    redelegation: dict[str, Any] = {
        "mode": mode,
        "depth": index,
        "maxDepth": max_depth,
    }
    if parent_token_hash is not None:
        redelegation["parentTokenHash"] = "sha-256:" + parent_token_hash
    action_budget = budget if budget is not None else 8 // (2**index)
    body: dict[str, Any] = {
        "schemaVersion": "1.0",
        "scope": {
            "allowedActions": allowed_actions,
            "deniedActions": [{"operation": "delete", "resource": "*"}],
        },
        "boundaries": ["deny:delete:*", "x-ardur:cwd:/workspace/project"],
        "timeWindow": {
            "notBefore": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "notAfter": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "operatorInstructionsHash": _sha256_prefixed(INSTRUCTIONS),
        "operatorInstructions": INSTRUCTIONS,
        "toolSchemaHash": TOOL_DIGEST,
        "revocationRequired": True,
        "metadata": {
            "x-ardur": {
                "profile": "ardur.drp.v0.1",
                "critical": sorted(ARDUR_CRITICAL_PATHS),
                "issuer": ISSUERS[index],
                "subject": SUBJECTS[index],
                "audience": "ardur-verifier",
                "delegationGrantId": f"urn:uuid:fixture-grant-{index}",
                "missionRef": {
                    "uri": "https://fixture.test/missions/calendar",
                    "missionDigest": _sha_dash256_prefixed("calendar-mission"),
                },
                "policy": {
                    "version": "fixture-policy-v1",
                    "digest": _sha_dash256_prefixed("fixture-policy-v1"),
                },
                "capabilityTokenRef": {
                    "mediaType": "application/aat+jwt",
                    "sha256": _token_hash(index),
                    "toolManifestDigest": TOOL_DIGEST,
                    "tokenType": "delegation",
                    "holderConfirmation": {"jwkThumbprint": "A" * 43},
                },
                "resourceBounds": {
                    "resources": (
                        ["tool://calendar/*"]
                        if index == 0
                        else ["tool://calendar/team", "tool://calendar/personal"]
                        if index == 1
                        else ["tool://calendar/team"]
                    ),
                    "sideEffectClasses": (
                        ["none", "state_change"] if index < 2 else ["none"]
                    ),
                    "cwd": "/workspace" if index == 0 else "/workspace/project",
                },
                "argumentConstraints": {
                    "tool://calendar/team": {
                        "calendar_id": (
                            {
                                "constraintType": "one_of",
                                "values": ["team", "personal"],
                            }
                            if index == 0
                            else {"constraintType": "exact", "value": "team"}
                        )
                    }
                },
                "budget": {
                    "maxToolCalls": action_budget,
                    "maxToolCallsPerClass": {
                        "none": action_budget,
                        **({"state_change": action_budget // 2} if index < 2 else {}),
                    },
                    "reservedShare": max(action_budget // 2, 1),
                },
                "redelegation": redelegation,
                "revocation": {
                    "ref": f"https://fixture.test/revocations/{index}#idx={index}",
                    "required": True,
                    "cascade": "issuer-policy",
                },
                "delegationLogAnchor": {
                    "backend": "rfc3161-log",
                    "required": True,
                    "subject": "receipt-id",
                },
                "receiptChainAnchor": {
                    "state": "unstarted",
                    "traceId": None,
                    "headReceiptId": None,
                    "headReceiptJwtSha256": None,
                },
            }
        },
    }
    if parent_receipt_id is not None:
        body["parentReceiptId"] = parent_receipt_id
    return body


def _chain(
    *,
    root_mode: str = "bounded",
    root_max_depth: int = 4,
    child_allowed: list[dict[str, str]] | None = None,
    grandchild_allowed: list[dict[str, str]] | None = None,
    root_not_after: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[ec.EllipticCurvePrivateKey]]:
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    root = emit_drp_receipt(
        _authorization(
            0,
            [
                {"operation": "read", "resource": "tool://calendar/team"},
                {"operation": "read", "resource": "tool://calendar/personal"},
                {"operation": "write", "resource": "tool://calendar/team"},
            ],
            mode=root_mode,
            max_depth=root_max_depth,
            not_after=root_not_after,
        ),
        keys[0],
    )
    child = emit_drp_receipt(
        _authorization(
            1,
            child_allowed
            or [
                {"operation": "read", "resource": "tool://calendar/team"},
                {"operation": "read", "resource": "tool://calendar/personal"},
            ],
            parent_receipt_id=root["receiptId"],
            parent_token_hash=_token_hash(0),
        ),
        keys[1],
        parent_orchestrator_private_key=keys[0],
    )
    grandchild = emit_drp_receipt(
        _authorization(
            2,
            grandchild_allowed
            or [{"operation": "read", "resource": "tool://calendar/team"}],
            parent_receipt_id=child["receiptId"],
            parent_token_hash=_token_hash(1),
            mode="none",
        ),
        keys[2],
        parent_orchestrator_private_key=keys[1],
    )
    return [root, child, grandchild], keys


def _context(
    chain: list[dict[str, Any]],
    keys: list[ec.EllipticCurvePrivateKey],
) -> DRPVerificationContext:
    logs: dict[str, DRPVerifiedLogEvidence] = {}
    statuses: dict[str, DRPVerifiedRevocationEvidence] = {}
    instructions: dict[str, str] = {}
    for index, receipt in enumerate(chain):
        receipt_id = receipt["receiptId"]
        ref = receipt["metadata"]["x-ardur"]["revocation"]["ref"]
        logs[receipt_id] = DRPVerifiedLogEvidence(
            receipt_id=receipt_id,
            backend="rfc3161-log",
            subject="receipt-id",
            integrated_at=DECISION_TIME - timedelta(minutes=2 - index / 2),
            proof_ref=f"https://fixture.test/log/{receipt_id}",
            included_before_use=True,
        )
        statuses[ref] = DRPVerifiedRevocationEvidence(
            ref=ref,
            status="active",
            observed_at=DECISION_TIME - timedelta(seconds=5),
            valid_until=DECISION_TIME + timedelta(minutes=5),
            source="https://fixture.test/revocations",
        )
        instructions[receipt_id] = INSTRUCTIONS
    return DRPVerificationContext(
        signer_keys={
            issuer: key.public_key() for issuer, key in zip(ISSUERS, keys, strict=True)
        },
        operator_instructions=instructions,
        tool_universes={TOOL_DIGEST: UNIVERSE},
        log_evidence=logs,
        revocation_evidence=statuses,
        receipt_chain_evidence={},
    )


def _verify(
    chain: list[dict[str, Any]],
    context: DRPVerificationContext,
    **kwargs: Any,
):
    return verify_drp_chain(
        chain,
        action={
            "operation": "read",
            "resource": "tool://calendar/team",
            "arguments": {"calendar_id": "team"},
            "sideEffectClass": "none",
            "cwd": "/workspace/project",
        },
        context=context,
        decision_time=kwargs.pop("decision_time", DECISION_TIME),
        **kwargs,
    )


def _resign(
    chain: list[dict[str, Any]],
    keys: list[ec.EllipticCurvePrivateKey],
    index: int,
    update: Any,
) -> list[dict[str, Any]]:
    body = {
        key: copy.deepcopy(value)
        for key, value in chain[index].items()
        if key
        not in {"receiptId", "canonicalPayload", "signature", "orchestratorSignature"}
    }
    update(body)
    if index:
        body["parentReceiptId"] = chain[index - 1]["receiptId"]
    replacement_receipt = emit_drp_receipt(
        body,
        keys[index],
        parent_orchestrator_private_key=keys[index - 1] if index else None,
    )
    updated = list(chain[:index]) + [replacement_receipt]
    for child_index in range(index + 1, len(chain)):
        child_body = {
            key: copy.deepcopy(value)
            for key, value in chain[child_index].items()
            if key
            not in {
                "receiptId",
                "canonicalPayload",
                "signature",
                "orchestratorSignature",
                "parentReceiptId",
            }
        }
        child_body["parentReceiptId"] = updated[-1]["receiptId"]
        child_body["metadata"]["x-ardur"]["redelegation"]["parentTokenHash"] = (
            "sha-256:"
            + updated[-1]["metadata"]["x-ardur"]["capabilityTokenRef"]["sha256"]
        )
        updated.append(
            emit_drp_receipt(
                child_body,
                keys[child_index],
                parent_orchestrator_private_key=keys[child_index - 1],
            )
        )
    return updated


def test_root_child_grandchild_round_trip() -> None:
    chain, keys = _chain()
    context = _context(chain, keys)

    result = _verify(chain, context)

    assert result.decision == "PERMIT"
    assert result.chain_depth == 2
    assert result.checks == {
        "receipts": 3,
        "signatures": 3,
        "orchestrator_signatures": 2,
        "attenuation_edges": 2,
        "log_evidence": 3,
        "revocation_evidence": 3,
        "receipt_chain_evidence": 0,
    }
    for receipt in chain:
        decoded = base64.urlsafe_b64decode(
            receipt["canonicalPayload"]
            + ("=" * (-len(receipt["canonicalPayload"]) % 4))
        )
        signed_body = {
            key: value
            for key, value in receipt.items()
            if key not in {"canonicalPayload", "signature", "orchestratorSignature"}
        }
        assert decoded == canonical_json_bytes(signed_body)
        assert validate_drp_receipt(receipt) == receipt


def test_no_redelegation_parent_denies_child() -> None:
    chain, keys = _chain(root_mode="none")
    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, _context(chain, keys))
    assert denied.value.code == "REDELEGATION_DENIED"


def test_bounded_redelegation_depth_exhaustion_denies_child() -> None:
    chain, keys = _chain(root_max_depth=1)
    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, _context(chain, keys))
    assert denied.value.code == "REDELEGATION_DENIED"


def test_equal_child_action_set_is_unexportable() -> None:
    same_as_root = [
        {"operation": "read", "resource": "tool://calendar/team"},
        {"operation": "read", "resource": "tool://calendar/personal"},
        {"operation": "write", "resource": "tool://calendar/team"},
    ]
    chain, keys = _chain(child_allowed=same_as_root)
    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, _context(chain, keys))
    assert denied.value.code == "SCOPE_NOT_STRICT_SUBSET"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda body: body["metadata"]["x-ardur"]["resourceBounds"].update(
                {"cwd": "/"}
            ),
            "RESOURCE_BOUND_WIDENING",
        ),
        (
            lambda body: body["metadata"]["x-ardur"]["budget"].update(
                {"maxToolCalls": 99}
            ),
            "BUDGET_WIDENING",
        ),
        (
            lambda body: body["metadata"]["x-ardur"]["argumentConstraints"][
                "tool://calendar/team"
            ].update({"calendar_id": {"constraintType": "exact", "value": "personal"}}),
            "ARGUMENT_CONSTRAINT_WIDENING",
        ),
    ],
)
def test_critical_extension_widening_denies(mutation: Any, expected: str) -> None:
    chain, keys = _chain()
    widened = _resign(chain, keys, 2 if expected != "BUDGET_WIDENING" else 1, mutation)
    with pytest.raises(DRPVerificationError) as denied:
        _verify(widened, _context(widened, keys))
    assert denied.value.code == expected


def test_invalid_oldest_ancestor_is_not_rehabilitated() -> None:
    chain, keys = _chain()
    chain[0]["signature"] = "A" * 86
    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, _context(chain, keys))
    assert denied.value.code == "INVALID_SIGNATURE"


def test_revoked_receipt_denies() -> None:
    chain, keys = _chain()
    context = _context(chain, keys)
    ref = chain[1]["metadata"]["x-ardur"]["revocation"]["ref"]
    statuses = dict(context.revocation_evidence)
    statuses[ref] = replace(statuses[ref], status="revoked")
    context = replace(context, revocation_evidence=statuses)

    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, context)

    assert denied.value.code == "REVOKED"


def test_expired_receipt_denies() -> None:
    chain, keys = _chain(root_not_after=DECISION_TIME - timedelta(seconds=1))
    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, _context(chain, keys))
    assert denied.value.code in {"EXPIRED", "PARENT_SCOPE_VIOLATION"}


def test_required_revocation_denies_offline_mode() -> None:
    chain, keys = _chain()
    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, _context(chain, keys), offline=True)
    assert denied.value.code == "REVOCATION_CHECK_REQUIRED"


def test_missing_or_stale_external_evidence_denies() -> None:
    chain, keys = _chain()
    context = _context(chain, keys)
    context = replace(context, log_evidence={})
    with pytest.raises(DRPVerificationError) as missing:
        _verify(chain, context)
    assert missing.value.code == "INSUFFICIENT_EVIDENCE"

    context = _context(chain, keys)
    ref = chain[0]["metadata"]["x-ardur"]["revocation"]["ref"]
    statuses = dict(context.revocation_evidence)
    statuses[ref] = replace(
        statuses[ref], valid_until=DECISION_TIME - timedelta(seconds=1)
    )
    with pytest.raises(DRPVerificationError) as stale:
        _verify(chain, replace(context, revocation_evidence=statuses))
    assert stale.value.code == "INSUFFICIENT_EVIDENCE"


def test_embedded_key_does_not_bootstrap_trust() -> None:
    chain, keys = _chain()
    context = _context(chain, keys)
    signers = dict(context.signer_keys)
    signers[ISSUERS[0]] = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, replace(context, signer_keys=signers))
    assert denied.value.code == "UNTRUSTED_SIGNER"


def test_noncanonical_payload_and_padded_encoding_deny() -> None:
    chain, keys = _chain()
    context = _context(chain, keys)
    chain[0]["canonicalPayload"] += "="
    with pytest.raises(DRPVerificationError) as denied:
        _verify(chain, context)
    assert denied.value.code in {"SCHEMA_INVALID", "MALFORMED_ENCODING"}


def test_duplicate_json_names_deny_before_schema() -> None:
    with pytest.raises(DRPVerificationError) as denied:
        load_drp_receipt('{"receiptId":"first","receiptId":"second"}')
    assert denied.value.code == "DUPLICATE_JSON_NAME"


def test_emitter_rejects_derived_fields_and_wrong_parent_shape() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    body = _authorization(
        0,
        [{"operation": "read", "resource": "tool://calendar/team"}],
    )
    body["receiptId"] = "rec_" + ("0" * 64)
    with pytest.raises(DRPEmissionError, match="derived fields"):
        emit_drp_receipt(body, key)

    child_body = _authorization(
        1,
        [{"operation": "read", "resource": "tool://calendar/team"}],
        parent_receipt_id="rec_" + ("1" * 64),
        parent_token_hash=_token_hash(0),
    )
    with pytest.raises(DRPEmissionError, match="parent orchestrator key"):
        emit_drp_receipt(child_body, key)


def test_authproof_ae1c56_wire_shape_is_rejected_fail_closed() -> None:
    authproof_reference_shape = {
        "delegationId": "auth-reference",
        "issuedAt": "2026-06-20T17:45:27.031Z",
        "scopeSchema": {
            "version": "1.0",
            "allowedActions": [{"operation": "read", "resource": "documents"}],
            "deniedActions": [],
        },
        "timeWindow": {
            "start": "2026-06-20T17:45:27.031Z",
            "end": "2100-01-01T00:00:00.000Z",
        },
        "signerPublicKey": {"kty": "EC", "crv": "P-256", "x": "A", "y": "A"},
        "signature": "00" * 64,
    }
    with pytest.raises(DRPProfileError, match="schema violation"):
        validate_drp_receipt(authproof_reference_shape)


def test_action_outside_leaf_scope_denies() -> None:
    chain, keys = _chain()
    with pytest.raises(DRPVerificationError) as denied:
        verify_drp_chain(
            chain,
            action={
                "operation": "write",
                "resource": "tool://calendar/team",
                "arguments": {"calendar_id": "team"},
                "sideEffectClass": "state_change",
                "cwd": "/workspace/project",
            },
            context=_context(chain, keys),
            decision_time=DECISION_TIME,
        )
    assert denied.value.code == "ACTION_NOT_IN_SCOPE"


def test_serialized_receipts_round_trip_through_duplicate_safe_loader() -> None:
    chain, keys = _chain()
    serialized = [canonical_json_bytes(receipt) for receipt in chain]
    result = _verify(serialized, _context(chain, keys))
    assert result.receipt_ids == tuple(receipt["receiptId"] for receipt in chain)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda body: body.update({"boundaries": ["deny:delete:*"]}),
            "PARENT_SCOPE_VIOLATION",
        ),
        (
            lambda body: body["metadata"]["x-ardur"].update(
                {"argumentConstraints": {}}
            ),
            "ARGUMENT_CONSTRAINT_WIDENING",
        ),
        (
            lambda body: (
                body.update({"revocationRequired": False}),
                body["metadata"]["x-ardur"]["revocation"].update({"required": False}),
            ),
            "REVOCATION_POLICY_MISMATCH",
        ),
        (
            lambda body: body["metadata"]["x-ardur"].update(
                {"audience": "different-verifier"}
            ),
            "PARENT_SCOPE_VIOLATION",
        ),
    ],
)
def test_child_cannot_drop_cross_edge_authority(mutation: Any, expected: str) -> None:
    chain, keys = _chain()
    changed = _resign(chain, keys, 1, mutation)
    with pytest.raises(DRPVerificationError) as denied:
        _verify(changed, _context(changed, keys))
    assert denied.value.code == expected


@pytest.mark.parametrize("arguments", [{}, {"calendar_id": "personal"}])
def test_leaf_argument_constraints_apply_to_concrete_action(
    arguments: dict[str, str],
) -> None:
    chain, keys = _chain()
    with pytest.raises(DRPVerificationError) as denied:
        verify_drp_chain(
            chain,
            action={
                "operation": "read",
                "resource": "tool://calendar/team",
                "arguments": arguments,
                "sideEffectClass": "none",
                "cwd": "/workspace/project",
            },
            context=_context(chain, keys),
            decision_time=DECISION_TIME,
        )
    assert denied.value.code == "ARGUMENT_CONSTRAINT_VIOLATION"


def test_emitter_rejects_malformed_time_and_constraint() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    body = _authorization(
        0,
        [{"operation": "read", "resource": "tool://calendar/team"}],
    )
    body["timeWindow"]["notAfter"] = body["timeWindow"]["notBefore"]
    with pytest.raises(DRPEmissionError, match="notBefore must precede"):
        emit_drp_receipt(body, key)

    body = _authorization(
        0,
        [{"operation": "read", "resource": "tool://calendar/team"}],
    )
    body["metadata"]["x-ardur"]["argumentConstraints"]["tool://calendar/team"][
        "calendar_id"
    ] = {"constraintType": "exact"}
    with pytest.raises(DRPEmissionError, match="missing"):
        emit_drp_receipt(body, key)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda body: body["metadata"]["x-ardur"]["resourceBounds"].update(
            {"resources": ["tool://calendar/personal"]}
        ),
        lambda body: body["metadata"]["x-ardur"]["resourceBounds"].update(
            {"sideEffectClasses": ["state_change"]}
        ),
        lambda body: body["metadata"]["x-ardur"]["resourceBounds"].update(
            {"cwd": "/workspace/project/child"}
        ),
    ],
)
def test_leaf_resource_bounds_apply_to_concrete_action(mutation: Any) -> None:
    chain, keys = _chain()
    changed = _resign(chain, keys, 2, mutation)

    with pytest.raises(DRPVerificationError) as denied:
        _verify(changed, _context(changed, keys))

    assert denied.value.code == "RESOURCE_BOUND_VIOLATION"


def test_present_receipt_chain_anchor_requires_matching_external_evidence() -> None:
    anchor = {
        "state": "present",
        "traceId": "trace-fixture",
        "headReceiptId": "action-receipt-fixture",
        "headReceiptJwtSha256": "0" * 64,
    }
    chain, keys = _chain()
    changed = _resign(
        chain,
        keys,
        2,
        lambda body: body["metadata"]["x-ardur"].update({"receiptChainAnchor": anchor}),
    )
    context = _context(changed, keys)
    with pytest.raises(DRPVerificationError) as missing:
        _verify(changed, context)
    assert missing.value.code == "INSUFFICIENT_EVIDENCE"

    leaf_id = changed[-1]["receiptId"]
    evidence = DRPVerifiedReceiptChainEvidence(
        receipt_id=leaf_id,
        trace_id=anchor["traceId"],
        head_receipt_id=anchor["headReceiptId"],
        head_receipt_jwt_sha256=anchor["headReceiptJwtSha256"],
        observed_at=DECISION_TIME - timedelta(seconds=1),
        source="https://fixture.test/action-chain",
    )
    result = _verify(
        changed,
        replace(context, receipt_chain_evidence={leaf_id: evidence}),
    )
    assert result.decision == "PERMIT"
    assert result.checks["receipt_chain_evidence"] == 1


@pytest.mark.parametrize(
    "timestamp",
    [
        "2027-01-15Z",
        "2027-01-15 08:00:00Z",
        "2027-W03-5T08:00:00Z",
        "2027-01-15T08:00Z",
        "2027-01-15T08:00:00.1234567Z",
    ],
)
def test_emitter_rejects_non_profile_timestamp_spellings(timestamp: str) -> None:
    body = _authorization(
        0,
        [{"operation": "read", "resource": "tool://calendar/team"}],
    )
    body["timeWindow"]["notBefore"] = timestamp

    with pytest.raises(DRPEmissionError, match="schema violation"):
        emit_drp_receipt(body, ec.generate_private_key(ec.SECP256R1()))


def test_nonfinite_receipt_json_and_nonjson_action_fail_closed() -> None:
    chain, keys = _chain()
    chain[0]["metadata"]["x-ardur"]["argumentConstraints"]["tool://calendar/team"][
        "calendar_id"
    ] = {"constraintType": "range", "min": float("nan")}
    serialized = [json.dumps(receipt, allow_nan=True) for receipt in chain]
    with pytest.raises(DRPVerificationError) as malformed:
        _verify(serialized, _context(chain, keys))
    assert malformed.value.code == "MALFORMED_JSON"

    chain, keys = _chain()
    with pytest.raises(DRPVerificationError) as invalid_action:
        verify_drp_chain(
            chain,
            action={
                "operation": "read",
                "resource": "tool://calendar/team",
                "arguments": {"calendar_id": object()},
                "sideEffectClass": "none",
                "cwd": "/workspace/project",
            },
            context=_context(chain, keys),
            decision_time=DECISION_TIME,
        )
    assert invalid_action.value.code == "INVALID_ACTION"

    with pytest.raises(DRPVerificationError) as non_nfc_action:
        verify_drp_chain(
            chain,
            action={
                "operation": "read",
                "resource": "tool://calendar/team",
                "arguments": {"calendar_id": "e\u0301"},
                "sideEffectClass": "none",
                "cwd": "/workspace/project",
            },
            context=_context(chain, keys),
            decision_time=DECISION_TIME,
        )
    assert non_nfc_action.value.code == "INVALID_ACTION"


def test_action_requires_classification_context_and_size_bound() -> None:
    chain, keys = _chain()
    context = _context(chain, keys)
    with pytest.raises(DRPVerificationError) as missing:
        verify_drp_chain(
            chain,
            action={
                "operation": "read",
                "resource": "tool://calendar/team",
                "arguments": {"calendar_id": "team"},
            },
            context=context,
            decision_time=DECISION_TIME,
        )
    assert missing.value.code == "INVALID_ACTION"

    with pytest.raises(DRPVerificationError) as oversized:
        verify_drp_chain(
            chain,
            action={
                "operation": "read",
                "resource": "tool://calendar/team",
                "arguments": {"calendar_id": "x" * (2 * 1024 * 1024)},
                "sideEffectClass": "none",
                "cwd": "/workspace/project",
            },
            context=context,
            decision_time=DECISION_TIME,
        )
    assert oversized.value.code == "ACTION_TOO_LARGE"


def test_mapping_input_cannot_bypass_receipt_size_limit() -> None:
    with pytest.raises(DRPVerificationError) as denied:
        load_drp_receipt({"oversized": "x" * (2 * 1024 * 1024)})
    assert denied.value.code == "RECEIPT_TOO_LARGE"

    body = _authorization(
        0,
        [{"operation": "read", "resource": "tool://calendar/team"}],
    )
    body["operatorInstructions"] = "x" * (1024 * 1024)
    body["operatorInstructionsHash"] = _sha256_prefixed(body["operatorInstructions"])
    with pytest.raises(DRPEmissionError, match="2 MiB"):
        emit_drp_receipt(body, ec.generate_private_key(ec.SECP256R1()))


def test_public_fixture_persists_only_public_trust_and_self_verifies(
    tmp_path, capsys
) -> None:
    output = tmp_path / "drp-fixture"

    report = run_drp_profile_fixture(output, now=int(DECISION_TIME.timestamp()))

    assert report["ok"] is True
    assert report["private_keys_persisted"] is False
    assert report["verification"]["decision"] == "PERMIT"
    assert verify_drp_profile_fixture(output) == report["verification"]
    assert not list(output.glob("*private*"))
    assert {path.name for path in output.iterdir()} == set(report["artifacts"])
    assert set(PUBLIC_KEY_FILES) <= set(report["artifacts"])
    context = json.loads(
        (output / "ardur-drp-profile-v0.1-context.json").read_text(encoding="utf-8")
    )
    assert "not raw RFC 3161" in context["claim_boundary"]
    assert "independent DRP implementation interoperability" in context["not_claimed"]

    cli_output = tmp_path / "drp-cli-fixture"
    assert cli_main(["drp-profile-fixture", "--output", str(cli_output)]) == 0
    cli_report = json.loads(capsys.readouterr().out)
    assert cli_report["ok"] is True
    assert cli_report["private_keys_persisted"] is False


def test_committed_public_fixture_verifies_and_matches_report() -> None:
    fixture_dir = REPO_ROOT / "docs" / "specs" / "fixtures"
    report = json.loads(
        (fixture_dir / "ardur-drp-profile-v0.1-report.json").read_text(encoding="utf-8")
    )

    assert verify_drp_profile_fixture(fixture_dir) == report["verification"]
    assert report["private_keys_persisted"] is False
    assert "independent DRP implementation interoperability" in report["not_claimed"]


def test_fixture_io_rejects_ambiguous_json_and_unexpected_output(
    tmp_path: Path,
) -> None:
    fixture_dir = REPO_ROOT / "docs" / "specs" / "fixtures"
    ambiguous = tmp_path / "ambiguous"
    shutil.copytree(fixture_dir, ambiguous)
    context_path = ambiguous / "ardur-drp-profile-v0.1-context.json"
    context_text = context_path.read_text(encoding="utf-8")
    context_path.write_text(
        context_text.replace(
            '"decision_time":',
            '"decision_time":"2027-01-15T08:00:00Z","decision_time":',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate name"):
        verify_drp_profile_fixture(ambiguous)

    dirty_output = tmp_path / "dirty-output"
    dirty_output.mkdir()
    dirty_output.chmod(0o755)
    (dirty_output / "private-key.pem").write_text("not a real key", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected entries"):
        run_drp_profile_fixture(dirty_output, now=int(DECISION_TIME.timestamp()))
    assert dirty_output.stat().st_mode & 0o777 == 0o755


# --- --output validation (empty / whitespace / existing-file / symlink) ---


def test_drp_fixture_output_existing_regular_file_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    existing_file = tmp_path / "existing-file.txt"
    existing_file.write_text("not a directory", encoding="utf-8")

    code = cli_main(["drp-profile-fixture", "--output", str(existing_file)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "drp_profile_fixture_output_not_directory"
    assert report["condition"] == "drp_profile_fixture_output_not_directory"
    assert "[Errno" not in captured.out
    assert str(existing_file) not in captured.out
    assert str(existing_file) not in json.dumps(report)
    assert report["next_steps"]
    assert all("<" in step["command"] and ">" in step["command"] for step in report["next_steps"])


def test_drp_fixture_output_empty_string_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    code = cli_main(["drp-profile-fixture", "--output", ""])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "drp_profile_fixture_output_empty"
    assert report["condition"] == "drp_profile_fixture_output_empty"
    assert report["next_steps"]
    assert not any(tmp_path.iterdir()), "no fixtures written to CWD on empty --output"


def test_drp_fixture_output_whitespace_only_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    code = cli_main(["drp-profile-fixture", "--output", "   "])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "drp_profile_fixture_output_empty"
    assert report["condition"] == "drp_profile_fixture_output_empty"
    assert report["next_steps"]
    assert not any(tmp_path.iterdir()), "no fixtures written on whitespace-only --output"


def test_drp_fixture_output_validation_raises_specialized_error(tmp_path: Path) -> None:
    existing_file = tmp_path / "blocking-file"
    existing_file.write_text("x", encoding="utf-8")

    with pytest.raises(DrpFixtureOutputError) as exc_info:
        run_drp_profile_fixture(existing_file)
    assert exc_info.value.condition == "drp_profile_fixture_output_not_directory"
    assert str(existing_file) not in exc_info.value.detail

    with pytest.raises(DrpFixtureOutputError) as empty_info:
        run_drp_profile_fixture("")
    assert empty_info.value.condition == "drp_profile_fixture_output_empty"


def test_drp_fixture_output_directory_symlink_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    real_dir = tmp_path / "real-dir"
    real_dir.mkdir()
    symlink_dir = tmp_path / "symlink-dir"
    symlink_dir.symlink_to(real_dir)

    code = cli_main(["drp-profile-fixture", "--output", str(symlink_dir)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert report["ok"] is False
    assert report["error"] == "drp_profile_fixture_output_symlink"
    assert report["condition"] == "drp_profile_fixture_output_symlink"
    assert str(symlink_dir) not in json.dumps(report)


def test_drp_fixture_output_dangling_symlink_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dangling = tmp_path / "dangling-dir"
    dangling.symlink_to(tmp_path / "nonexistent-target")

    code = cli_main(["drp-profile-fixture", "--output", str(dangling)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert report["ok"] is False
    assert report["error"] == "drp_profile_fixture_output_symlink"
    assert report["condition"] == "drp_profile_fixture_output_symlink"


def test_drp_fixture_output_valid_new_dir_behavior_preserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    new_dir = tmp_path / "fresh-output-dir"

    code = cli_main(
        ["drp-profile-fixture", "--output", str(new_dir)]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["ok"] is True
    assert (new_dir / "ardur-drp-profile-v0.1-report.json").is_file()


def test_drp_fixture_output_existing_empty_dir_behavior_preserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    existing_dir = tmp_path / "existing-dir"
    existing_dir.mkdir()

    code = cli_main(
        ["drp-profile-fixture", "--output", str(existing_dir)]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["ok"] is True
    assert (existing_dir / "ardur-drp-profile-v0.1-report.json").is_file()

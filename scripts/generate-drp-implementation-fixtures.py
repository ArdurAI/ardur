#!/usr/bin/env python3
"""Generate the public DRP implementation fixture bundle with ephemeral keys."""

from __future__ import annotations

import argparse
import copy
import os
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.canonical_json import canonical_json_bytes
from vibap.drp import emit_drp_receipt
from vibap.drp_conformance import (
    BUNDLE_SCHEMA_VERSION,
    run_drp_conformance_bundle,
    write_drp_conformance_report,
)
from vibap.drp_fixture import (
    ISSUERS,
    _external_context_document,
    _fixture_chain,
)


UTC = timezone.utc
DECISION_TIME = datetime(2027, 1, 15, 8, 0, tzinfo=UTC)
ACTION = {
    "operation": "read",
    "resource": "tool://calendar/team",
    "arguments": {"calendar_id": "team"},
    "sideEffectClass": "none",
    "cwd": "/workspace/project",
}


def _atomic_public_write(path: Path, value: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise ValueError(f"fixture output must not be a symlink: {path}")
    if not path.parent.is_dir():
        raise ValueError(f"fixture output parent must exist: {path.parent}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(canonical_json_bytes(dict(value)) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            # Successful replacement consumes the temporary path.
            pass


def _resign_from(
    chain: Sequence[Mapping[str, Any]],
    keys: Sequence[ec.EllipticCurvePrivateKey],
    index: int,
    update: Callable[[dict[str, Any]], None],
) -> list[dict[str, Any]]:
    body = {
        name: copy.deepcopy(value)
        for name, value in chain[index].items()
        if name
        not in {"receiptId", "canonicalPayload", "signature", "orchestratorSignature"}
    }
    update(body)
    if index:
        body["parentReceiptId"] = chain[index - 1]["receiptId"]
    replacement = emit_drp_receipt(
        body,
        keys[index],
        parent_orchestrator_private_key=keys[index - 1] if index else None,
    )
    updated = [copy.deepcopy(value) for value in chain[:index]] + [replacement]
    for child_index in range(index + 1, len(chain)):
        child_body = {
            name: copy.deepcopy(value)
            for name, value in chain[child_index].items()
            if name
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


def _public_keys(
    keys: Sequence[ec.EllipticCurvePrivateKey],
) -> dict[str, str]:
    return {
        issuer: key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
        for issuer, key in zip(ISSUERS, keys, strict=True)
    }


def _context(
    chain: list[dict[str, Any]],
    keys: Sequence[ec.EllipticCurvePrivateKey],
    decision_time: datetime,
    tool_digest: str,
) -> dict[str, Any]:
    source = _external_context_document(chain, decision_time, tool_digest)
    return {
        "signer_keys": _public_keys(keys),
        "operator_instructions": source["operator_instructions"],
        "tool_universes": source["tool_universes"],
        "log_evidence": source["log_evidence"],
        "revocation_evidence": source["revocation_evidence"],
        "receipt_chain_evidence": [],
    }


def _scenario(
    scenario_id: str,
    description: str,
    risk_class: str,
    chain: list[dict[str, Any]],
    context: dict[str, Any],
    decision_time: datetime,
    decision: str,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "description": description,
        "risk_class": risk_class,
        "receipts": copy.deepcopy(chain),
        "context": copy.deepcopy(context),
        "action": copy.deepcopy(ACTION),
        "decision_time": decision_time.isoformat().replace("+00:00", "Z"),
        "offline": False,
        "expected": {
            "decision": decision,
            "reason_code": reason_code,
            "receipt_id": chain[-1].get("receiptId"),
        },
    }


def build_bundle() -> dict[str, Any]:
    valid, keys, tool_digest = _fixture_chain(DECISION_TIME)
    valid_context = _context(valid, keys, DECISION_TIME, tool_digest)

    widening = _resign_from(
        valid,
        keys,
        1,
        lambda body: body["metadata"]["x-ardur"]["resourceBounds"].update({"cwd": "/"}),
    )
    no_redelegation = _resign_from(
        valid,
        keys,
        0,
        lambda body: body["metadata"]["x-ardur"]["redelegation"].update(
            {"mode": "none"}
        ),
    )
    depth_exhausted = _resign_from(
        valid,
        keys,
        0,
        lambda body: body["metadata"]["x-ardur"]["redelegation"].update(
            {"maxDepth": 1}
        ),
    )
    expired_time = DECISION_TIME + timedelta(minutes=11)
    expired_context = _context(valid, keys, expired_time, tool_digest)
    revoked_context = copy.deepcopy(valid_context)
    child_ref = valid[1]["metadata"]["x-ardur"]["revocation"]["ref"]
    for status in revoked_context["revocation_evidence"]:
        if status["ref"] == child_ref:
            status["status"] = "revoked"

    authproof_legacy = {
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
    empty_context = {
        "signer_keys": {},
        "operator_instructions": {},
        "tool_universes": {},
        "log_evidence": [],
        "revocation_evidence": [],
        "receipt_chain_evidence": [],
    }

    scenarios = [
        _scenario(
            "DRP-VALID-CHAIN",
            "A valid root-child-grandchild profile chain permits the bounded action.",
            "authorization_validity",
            valid,
            valid_context,
            DECISION_TIME,
            "PERMIT",
            "verified",
        ),
        _scenario(
            "DRP-DENY-RESOURCE-WIDENING",
            "A correctly signed child that widens cwd authority beyond its parent denies.",
            "authority_widening",
            widening,
            _context(widening, keys, DECISION_TIME, tool_digest),
            DECISION_TIME,
            "DENY",
            "RESOURCE_BOUND_WIDENING",
        ),
        _scenario(
            "DRP-DENY-EXPIRED",
            "A valid chain evaluated after the root time window denies.",
            "temporal_validity",
            valid,
            expired_context,
            expired_time,
            "DENY",
            "EXPIRED",
        ),
        _scenario(
            "DRP-DENY-REVOKED",
            "A chain with fresh authenticated revoked status for the child denies.",
            "revocation",
            valid,
            revoked_context,
            DECISION_TIME,
            "DENY",
            "REVOKED",
        ),
        _scenario(
            "DRP-DENY-NO-REDELEGATION",
            "A child under a parent that signs mode none denies.",
            "redelegation",
            no_redelegation,
            _context(no_redelegation, keys, DECISION_TIME, tool_digest),
            DECISION_TIME,
            "DENY",
            "REDELEGATION_DENIED",
        ),
        _scenario(
            "DRP-DENY-DEPTH-EXHAUSTED",
            "A child at its parent signed maximum delegation depth denies.",
            "redelegation",
            depth_exhausted,
            _context(depth_exhausted, keys, DECISION_TIME, tool_digest),
            DECISION_TIME,
            "DENY",
            "REDELEGATION_DENIED",
        ),
        {
            "scenario_id": "DRP-DENY-AUTHPROOF-AE1C56-WIRE",
            "description": (
                "The AuthProof SDK ae1c56 legacy wire fails the draft-10-pinned "
                "profile schema closed."
            ),
            "risk_class": "wire_compatibility",
            "receipts": [authproof_legacy],
            "context": empty_context,
            "action": copy.deepcopy(ACTION),
            "decision_time": DECISION_TIME.isoformat().replace("+00:00", "Z"),
            "offline": False,
            "expected": {
                "decision": "DENY",
                "reason_code": "SCHEMA_INVALID",
                "receipt_id": None,
            },
        },
    ]
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_id": "ardur-drp-v0.1-draft-10-implementation-fixtures",
        "draft": {
            "name": "draft-nelson-agent-delegation-receipts",
            "revision": "10",
            "source": (
                "https://datatracker.ietf.org/doc/"
                "draft-nelson-agent-delegation-receipts/10/"
            ),
            "status": "active-individual-internet-draft",
        },
        "profile": "ardur.drp.v0.1",
        "claim_boundary": (
            "Ardur implementation self-test; not IETF or independent "
            "conformance evidence"
        ),
        "not_claimed": [
            "generic DRP compatibility",
            "IETF conformance",
            "independent implementation interoperability",
            "raw RFC 3161 proof verification",
        ],
        "verifier": {
            "implementation": "ardur",
            "profile": "ardur.drp.v0.1",
            "evidence_class": "implementation-self-test",
        },
        "external_implementations": [
            {
                "name": "authproof-sdk",
                "source": "https://github.com/Commonguy25/authproof-sdk",
                "revision": "ae1c56da7f55965c229d1b0a638d5390b4882123",
                "relationship": "draft-author",
                "status": "incompatible-wire",
                "evidence": (
                    "Legacy fields, signatures, identifiers, and time-window shape "
                    "do not satisfy the draft-10-pinned Ardur profile schema."
                ),
            },
            {
                "name": "independent-verifier",
                "source": None,
                "revision": None,
                "relationship": "independent",
                "status": "not-demonstrated",
                "evidence": (
                    "No independently maintained compatible verifier was identified "
                    "or passed against this bundle."
                ),
            },
        ],
        "scenarios": scenarios,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate signed public DRP implementation fixtures."
    )
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    bundle = build_bundle()
    _atomic_public_write(args.bundle, bundle)
    report = run_drp_conformance_bundle(args.bundle)
    if not report["ok"]:
        raise RuntimeError("generated DRP implementation fixture bundle did not pass")
    write_drp_conformance_report(args.report, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

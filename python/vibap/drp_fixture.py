"""Generate and verify the public Ardur DRP Profile v0.1 implementation fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .canonical_json import canonical_json_bytes
from .drp import (
    ARDUR_CRITICAL_PATHS,
    DRPVerificationContext,
    DRPVerifiedLogEvidence,
    DRPVerifiedRevocationEvidence,
    _parse_time,
    emit_drp_receipt,
    tool_universe_digest,
    tool_universe_document,
    verify_drp_chain,
)


FIXTURE_SCHEMA_VERSION = "ardur.drp_profile_fixture.v0.1"
INSTRUCTIONS = "Read the approved calendar data for the team."
UNIVERSE = [
    {"operation": "read", "resource": "tool://calendar/team"},
    {"operation": "read", "resource": "tool://calendar/personal"},
    {"operation": "write", "resource": "tool://calendar/team"},
    {"operation": "delete", "resource": "tool://calendar/team"},
]
ISSUERS = (
    "spiffe://fixture.ardur.dev/user/alice",
    "spiffe://fixture.ardur.dev/orchestrator/calendar",
    "spiffe://fixture.ardur.dev/agent/calendar-reader",
)
SUBJECTS = (
    ISSUERS[1],
    ISSUERS[2],
    "spiffe://fixture.ardur.dev/tool/calendar",
)
PUBLIC_KEY_FILES = (
    "ardur-drp-profile-v0.1-root-public.pem",
    "ardur-drp-profile-v0.1-child-public.pem",
    "ardur-drp-profile-v0.1-grandchild-public.pem",
)
ARTIFACT_FILES = (
    "ardur-drp-profile-v0.1-chain.json",
    "ardur-drp-profile-v0.1-context.json",
    *PUBLIC_KEY_FILES,
    "ardur-drp-profile-v0.1-report.json",
)
MAX_FIXTURE_DOCUMENT_BYTES = 8 * 1024 * 1024


def _atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"fixture artifact must not be a symlink: {path.name}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_json(path: Path, value: Any) -> None:
    _atomic_write(path, canonical_json_bytes(value) + b"\n")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError(f"fixture JSON contains duplicate name {name!r}")
        value[name] = item
    return value


def _reject_nonfinite(token: str) -> None:
    raise ValueError(f"fixture JSON contains non-finite number {token}")


def _load_fixture_document(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_FIXTURE_DOCUMENT_BYTES:
        raise ValueError(f"fixture document exceeds 8 MiB: {path.name}")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid fixture JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"fixture document must be an object: {path.name}")
    return value


def _digest(value: str, *, dash: bool = False) -> str:
    prefix = "sha-256:" if dash else "sha256:"
    return prefix + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _token_hash(index: int) -> str:
    return hashlib.sha256(f"public-fixture-aat-{index}".encode()).hexdigest()


def _authorization(
    index: int,
    allowed_actions: list[dict[str, str]],
    decision_time: datetime,
    tool_digest: str,
    *,
    parent_receipt_id: str | None = None,
    parent_token_hash: str | None = None,
    mode: str = "bounded",
) -> dict[str, Any]:
    redelegation: dict[str, Any] = {
        "mode": mode,
        "depth": index,
        "maxDepth": 4,
    }
    if parent_token_hash is not None:
        redelegation["parentTokenHash"] = "sha-256:" + parent_token_hash
    budget = 8 // (2**index)
    authorization: dict[str, Any] = {
        "schemaVersion": "1.0",
        "scope": {
            "allowedActions": allowed_actions,
            "deniedActions": [{"operation": "delete", "resource": "*"}],
        },
        "boundaries": ["deny:delete:*", "x-ardur:cwd:/workspace/project"],
        "timeWindow": {
            "notBefore": (decision_time - timedelta(minutes=5 - index)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "notAfter": (decision_time + timedelta(minutes=10 - index)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        },
        "operatorInstructionsHash": _digest(INSTRUCTIONS),
        "operatorInstructions": INSTRUCTIONS,
        "toolSchemaHash": tool_digest,
        "revocationRequired": True,
        "metadata": {
            "x-ardur": {
                "profile": "ardur.drp.v0.1",
                "critical": sorted(ARDUR_CRITICAL_PATHS),
                "issuer": ISSUERS[index],
                "subject": SUBJECTS[index],
                "audience": "ardur-verifier",
                "delegationGrantId": f"urn:uuid:public-fixture-grant-{index}",
                "missionRef": {
                    "uri": "https://fixture.ardur.dev/missions/calendar",
                    "missionDigest": _digest("calendar-mission", dash=True),
                },
                "policy": {
                    "version": "fixture-policy-v1",
                    "digest": _digest("fixture-policy-v1", dash=True),
                },
                "capabilityTokenRef": {
                    "mediaType": "application/aat+jwt",
                    "sha256": _token_hash(index),
                    "toolManifestDigest": tool_digest,
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
                    "maxToolCalls": budget,
                    "maxToolCallsPerClass": {
                        "none": budget,
                        **({"state_change": budget // 2} if index < 2 else {}),
                    },
                    "reservedShare": max(budget // 2, 1),
                },
                "redelegation": redelegation,
                "revocation": {
                    "ref": (
                        f"https://fixture.ardur.dev/revocations/{index}#idx={index}"
                    ),
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
        authorization["parentReceiptId"] = parent_receipt_id
    return authorization


def _fixture_chain(
    decision_time: datetime,
) -> tuple[list[dict[str, Any]], list[ec.EllipticCurvePrivateKey], str]:
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    tool_digest = tool_universe_digest(UNIVERSE)
    root = emit_drp_receipt(
        _authorization(
            0,
            [
                {"operation": "read", "resource": "tool://calendar/team"},
                {"operation": "read", "resource": "tool://calendar/personal"},
                {"operation": "write", "resource": "tool://calendar/team"},
            ],
            decision_time,
            tool_digest,
        ),
        keys[0],
    )
    child = emit_drp_receipt(
        _authorization(
            1,
            [
                {"operation": "read", "resource": "tool://calendar/team"},
                {"operation": "read", "resource": "tool://calendar/personal"},
            ],
            decision_time,
            tool_digest,
            parent_receipt_id=root["receiptId"],
            parent_token_hash=_token_hash(0),
        ),
        keys[1],
        parent_orchestrator_private_key=keys[0],
    )
    grandchild = emit_drp_receipt(
        _authorization(
            2,
            [{"operation": "read", "resource": "tool://calendar/team"}],
            decision_time,
            tool_digest,
            parent_receipt_id=child["receiptId"],
            parent_token_hash=_token_hash(1),
            mode="none",
        ),
        keys[2],
        parent_orchestrator_private_key=keys[1],
    )
    return [root, child, grandchild], keys, tool_digest


def _external_context_document(
    chain: list[dict[str, Any]], decision_time: datetime, tool_digest: str
) -> dict[str, Any]:
    log_evidence = []
    revocation_evidence = []
    operator_instructions: dict[str, str] = {}
    for index, receipt in enumerate(chain):
        receipt_id = receipt["receiptId"]
        ref = receipt["metadata"]["x-ardur"]["revocation"]["ref"]
        operator_instructions[receipt_id] = INSTRUCTIONS
        log_evidence.append(
            {
                "receipt_id": receipt_id,
                "backend": "rfc3161-log",
                "subject": "receipt-id",
                "integrated_at": (decision_time - timedelta(minutes=2 - index / 2))
                .isoformat()
                .replace("+00:00", "Z"),
                "proof_ref": f"https://fixture.ardur.dev/log/{receipt_id}",
                "included_before_use": True,
            }
        )
        revocation_evidence.append(
            {
                "ref": ref,
                "status": "active",
                "observed_at": (decision_time - timedelta(seconds=5))
                .isoformat()
                .replace("+00:00", "Z"),
                "valid_until": (decision_time + timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
                "source": "https://fixture.ardur.dev/revocations",
            }
        )
    return {
        "schema_version": "ardur.drp_preverified_context_fixture.v0.1",
        "claim_boundary": (
            "synthetic preverified facts for the Ardur verifier API; "
            "not raw RFC 3161 or independent conformance evidence"
        ),
        "decision_time": decision_time.isoformat().replace("+00:00", "Z"),
        "action": {
            "operation": "read",
            "resource": "tool://calendar/team",
            "arguments": {"calendar_id": "team"},
            "sideEffectClass": "none",
            "cwd": "/workspace/project",
        },
        "operator_instructions": operator_instructions,
        "tool_universes": {tool_digest: UNIVERSE},
        "log_evidence": log_evidence,
        "revocation_evidence": revocation_evidence,
        "not_claimed": [
            "raw RFC 3161 proof verification",
            "independent DRP implementation interoperability",
            "IETF conformance",
            "current non-revocation outside the fixture decision time",
        ],
    }


def _load_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError(f"{path.name} is not an EC public key")
    return key


def verify_drp_profile_fixture(directory: str | Path) -> dict[str, Any]:
    root = Path(directory).expanduser()
    bundle = _load_fixture_document(root / "ardur-drp-profile-v0.1-chain.json")
    context_doc = _load_fixture_document(root / "ardur-drp-profile-v0.1-context.json")
    keys = [_load_public_key(root / name) for name in PUBLIC_KEY_FILES]
    logs = {
        value["receipt_id"]: DRPVerifiedLogEvidence(
            receipt_id=value["receipt_id"],
            backend=value["backend"],
            subject=value["subject"],
            integrated_at=_parse_time(value["integrated_at"], "integrated_at"),
            proof_ref=value["proof_ref"],
            included_before_use=value["included_before_use"],
        )
        for value in context_doc["log_evidence"]
    }
    statuses = {
        value["ref"]: DRPVerifiedRevocationEvidence(
            ref=value["ref"],
            status=value["status"],
            observed_at=_parse_time(value["observed_at"], "observed_at"),
            valid_until=_parse_time(value["valid_until"], "valid_until"),
            source=value["source"],
        )
        for value in context_doc["revocation_evidence"]
    }
    context = DRPVerificationContext(
        signer_keys={issuer: key for issuer, key in zip(ISSUERS, keys, strict=True)},
        operator_instructions=context_doc["operator_instructions"],
        tool_universes=context_doc["tool_universes"],
        log_evidence=logs,
        revocation_evidence=statuses,
        receipt_chain_evidence={},
    )
    return verify_drp_chain(
        bundle["receipts"],
        action=context_doc["action"],
        context=context,
        decision_time=_parse_time(context_doc["decision_time"], "decision_time"),
    ).as_dict()


class DrpFixtureOutputError(ValueError):
    """Raised when the ``--output`` argument fails pre-validation.

    A ``ValueError`` subclass so it is still caught by the generic handler in
    ``main()`` / ``cmd_drp_profile_fixture()``, but distinct enough for the CLI
    to emit a structured, sanitized failure response instead of the raw
    exception text.
    """

    def __init__(self, detail: str, *, condition: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.condition = condition


def run_drp_profile_fixture(
    output: str | Path, *, now: int | None = None
) -> dict[str, Any]:
    output_raw = str(output)
    output_str = output_raw.strip()
    if not output_str:
        raise DrpFixtureOutputError(
            "fixture output path must not be empty or whitespace-only",
            condition="drp_profile_fixture_output_empty",
        )
    output_path = Path(output_str).expanduser()
    if output_path.is_symlink():
        raise DrpFixtureOutputError(
            "fixture output directory must not be a symlink",
            condition="drp_profile_fixture_output_symlink",
        )
    if output_path.exists() and not output_path.is_dir():
        raise DrpFixtureOutputError(
            "fixture output path must be a directory, not a regular file",
            condition="drp_profile_fixture_output_not_directory",
        )
    output_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not output_path.is_dir():
        raise ValueError("fixture output path must be a directory")
    entries = list(output_path.iterdir())
    unexpected = {path.name for path in entries} - set(ARTIFACT_FILES)
    if unexpected:
        raise ValueError(
            f"fixture output directory contains unexpected entries: {sorted(unexpected)}"
        )
    unsafe = sorted(
        path.name for path in entries if path.is_symlink() or not path.is_file()
    )
    if unsafe:
        raise ValueError(f"fixture artifacts must be regular files: {unsafe}")
    output_path.chmod(0o700)
    timestamp = int(time.time() if now is None else now)
    decision_time = datetime.fromtimestamp(timestamp, timezone.utc)
    chain, keys, tool_digest = _fixture_chain(decision_time)
    bundle = {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "claim_boundary": "synthetic Ardur DRP profile implementation fixture",
        "tool_universe": tool_universe_document(UNIVERSE),
        "receipts": chain,
    }
    context = _external_context_document(chain, decision_time, tool_digest)
    _write_json(output_path / "ardur-drp-profile-v0.1-chain.json", bundle)
    _write_json(output_path / "ardur-drp-profile-v0.1-context.json", context)
    for name, key in zip(PUBLIC_KEY_FILES, keys, strict=True):
        _atomic_write(
            output_path / name,
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
    verification = verify_drp_profile_fixture(output_path)
    report = {
        "ok": True,
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "private_keys_persisted": False,
        "verification": verification,
        "artifacts": list(ARTIFACT_FILES),
        "not_claimed": context["not_claimed"],
    }
    _write_json(output_path / "ardur-drp-profile-v0.1-report.json", report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic Ardur DRP profile implementation fixture."
    )
    parser.add_argument("--output", type=str, required=True)
    args = parser.parse_args(argv)
    try:
        report = run_drp_profile_fixture(args.output)
    except DrpFixtureOutputError as exc:
        print(
            json.dumps(
                {"ok": False, "error": exc.condition, "condition": exc.condition},
                sort_keys=True,
            )
        )
        return 1
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

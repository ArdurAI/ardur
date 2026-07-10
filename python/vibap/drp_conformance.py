"""Run portable Ardur DRP implementation fixtures without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import best_match

from ._specs import (
    drp_conformance_bundle_v01_schema,
    drp_implementation_fixture_report_v01_schema,
)
from .canonical_json import canonical_json_bytes
from .drp import (
    DRPVerificationContext,
    DRPVerificationError,
    DRPVerifiedLogEvidence,
    DRPVerifiedReceiptChainEvidence,
    DRPVerifiedRevocationEvidence,
    _parse_time,
    verify_drp_chain,
)


BUNDLE_SCHEMA_VERSION = "ardur.drp_implementation_fixture_bundle.v0.1"
REPORT_SCHEMA_VERSION = "ardur.drp_implementation_fixture_report.v0.1"
EVIDENCE_CLASS = "implementation-self-test"
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 1_000_000


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError(f"bundle JSON contains duplicate name {name!r}")
        value[name] = item
    return value


def _reject_nonfinite(token: str) -> None:
    raise ValueError(f"bundle JSON contains non-finite number {token}")


def _assert_json_bounds_and_nfc(value: Any) -> None:
    stack: list[tuple[Any, str, int]] = [(value, "$", 0)]
    nodes = 0
    while stack:
        item, path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("bundle exceeds the JSON node limit")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("bundle exceeds the JSON nesting-depth limit")
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise ValueError(f"bundle string is not Unicode NFC at {path}")
        elif isinstance(item, Mapping):
            for name, child in item.items():
                if unicodedata.normalize("NFC", name) != name:
                    raise ValueError(f"bundle object name is not Unicode NFC at {path}")
                stack.append((child, f"{path}.{name}", depth + 1))
        elif isinstance(item, list):
            stack.extend(
                (child, f"{path}[{index}]", depth + 1)
                for index, child in enumerate(item)
            )


def _schema_error(error: Any) -> str:
    if error is None:
        return "unknown schema violation"
    path = "$" + "".join(
        f"[{part}]" if isinstance(part, int) else f".{part}" for part in error.path
    )
    return f"{path}: {error.message}"


def _validate_bundle(value: dict[str, Any]) -> dict[str, Any]:
    _assert_json_bounds_and_nfc(value)
    schema = drp_conformance_bundle_v01_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    error = best_match(validator.iter_errors(value))
    if error is not None:
        raise ValueError(f"bundle schema violation: {_schema_error(error)}")
    scenario_ids = [scenario["scenario_id"] for scenario in value["scenarios"]]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("bundle scenario_id values must be unique")
    external_names = [entry["name"] for entry in value["external_implementations"]]
    if len(external_names) != len(set(external_names)):
        raise ValueError("external implementation names must be unique")
    return value


def load_drp_conformance_bundle(path: str | Path) -> dict[str, Any]:
    """Load a bounded, duplicate-safe fixture bundle and validate its schema."""

    bundle_path = Path(path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(bundle_path, flags)
    except OSError as exc:
        raise ValueError("bundle path must be a regular file, not a symlink") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("bundle path must be a regular file, not a symlink")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_BUNDLE_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("bundle exceeds the 32 MiB input limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("bundle is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("bundle must be a JSON object")
    return _validate_bundle(value)


def _unique_map(
    values: Sequence[Mapping[str, Any]], key: str, label: str
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for value in values:
        identity = value[key]
        if identity in indexed:
            raise ValueError(f"scenario contains duplicate {label} {identity!r}")
        indexed[identity] = value
    return indexed


def _signer_keys(values: Mapping[str, str]) -> dict[str, ec.EllipticCurvePublicKey]:
    result: dict[str, ec.EllipticCurvePublicKey] = {}
    for issuer, encoded in values.items():
        try:
            key = serialization.load_pem_public_key(encoded.encode("ascii"))
        except (UnicodeEncodeError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid public trust key for issuer {issuer!r}") from exc
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ValueError(f"trust key for issuer {issuer!r} is not P-256")
        result[issuer] = key
    return result


def _verification_context(value: Mapping[str, Any]) -> DRPVerificationContext:
    logs = _unique_map(value["log_evidence"], "receipt_id", "log receipt_id")
    statuses = _unique_map(value["revocation_evidence"], "ref", "revocation ref")
    chains = _unique_map(
        value["receipt_chain_evidence"], "receipt_id", "receipt-chain receipt_id"
    )
    return DRPVerificationContext(
        signer_keys=_signer_keys(value["signer_keys"]),
        operator_instructions=dict(value["operator_instructions"]),
        tool_universes={
            digest: list(actions) for digest, actions in value["tool_universes"].items()
        },
        log_evidence={
            receipt_id: DRPVerifiedLogEvidence(
                receipt_id=item["receipt_id"],
                backend=item["backend"],
                subject=item["subject"],
                integrated_at=_parse_time(item["integrated_at"], "integrated_at"),
                proof_ref=item["proof_ref"],
                included_before_use=item["included_before_use"],
            )
            for receipt_id, item in logs.items()
        },
        revocation_evidence={
            ref: DRPVerifiedRevocationEvidence(
                ref=item["ref"],
                status=item["status"],
                observed_at=_parse_time(item["observed_at"], "observed_at"),
                valid_until=_parse_time(item["valid_until"], "valid_until"),
                source=item["source"],
            )
            for ref, item in statuses.items()
        },
        receipt_chain_evidence={
            receipt_id: DRPVerifiedReceiptChainEvidence(
                receipt_id=item["receipt_id"],
                trace_id=item["trace_id"],
                head_receipt_id=item["head_receipt_id"],
                head_receipt_jwt_sha256=item["head_receipt_jwt_sha256"],
                observed_at=_parse_time(item["observed_at"], "observed_at"),
                source=item["source"],
            )
            for receipt_id, item in chains.items()
        },
    )


def _raw_leaf_receipt_id(receipts: Sequence[Mapping[str, Any]]) -> str | None:
    value = receipts[-1].get("receiptId")
    return value if isinstance(value, str) else None


def _run_scenario(scenario: Mapping[str, Any]) -> dict[str, Any]:
    context = _verification_context(scenario["context"])
    receipt_id = _raw_leaf_receipt_id(scenario["receipts"])
    checks: dict[str, int] | None = None
    try:
        result = verify_drp_chain(
            scenario["receipts"],
            action=scenario["action"],
            context=context,
            decision_time=_parse_time(scenario["decision_time"], "decision_time"),
            offline=scenario["offline"],
        )
    except DRPVerificationError as exc:
        decision = "DENY"
        reason_code = exc.code
    else:
        decision = result.decision
        reason_code = result.reason
        receipt_id = result.leaf_receipt_id
        checks = dict(result.checks)
    expected = scenario["expected"]
    passed = (
        decision == expected["decision"]
        and reason_code == expected["reason_code"]
        and receipt_id == expected["receipt_id"]
    )
    return {
        "scenario_id": scenario["scenario_id"],
        "description": scenario["description"],
        "risk_class": scenario["risk_class"],
        "decision": decision,
        "reason_code": reason_code,
        "receipt_id": receipt_id,
        "receipt_id_status": (
            "verified"
            if decision == "PERMIT"
            else "untrusted-input"
            if receipt_id is not None
            else "absent"
        ),
        "expected_decision": expected["decision"],
        "expected_reason_code": expected["reason_code"],
        "expected_receipt_id": expected["receipt_id"],
        "verifier_status": "pass" if passed else "fail",
        "evidence_class": EVIDENCE_CLASS,
        "checks": checks,
    }


def run_drp_conformance_bundle(path: str | Path) -> dict[str, Any]:
    """Run every committed scenario and return a deterministic report."""

    bundle = load_drp_conformance_bundle(path)
    scenarios = [_run_scenario(scenario) for scenario in bundle["scenarios"]]
    failures = sum(item["verifier_status"] != "pass" for item in scenarios)
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "bundle_schema_version": bundle["schema_version"],
        "bundle_id": bundle["bundle_id"],
        "bundle_sha256": hashlib.sha256(canonical_json_bytes(bundle)).hexdigest(),
        "draft": dict(bundle["draft"]),
        "profile": bundle["profile"],
        "evidence_class": EVIDENCE_CLASS,
        "ok": failures == 0,
        "summary": {
            "total": len(scenarios),
            "passed": len(scenarios) - failures,
            "failed": failures,
        },
        "scenarios": scenarios,
        "external_implementations": list(bundle["external_implementations"]),
        "not_claimed": list(bundle["not_claimed"]),
    }
    schema = drp_implementation_fixture_report_v01_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    error = best_match(validator.iter_errors(report))
    if error is not None:
        raise ValueError(f"generated report schema violation: {_schema_error(error)}")
    return report


def write_drp_conformance_report(path: str | Path, report: Mapping[str, Any]) -> None:
    """Atomically write a canonical report without following a target symlink."""

    output = Path(path).expanduser()
    if output.is_symlink():
        raise ValueError("report output must not be a symlink")
    if not output.parent.is_dir():
        raise ValueError("report output parent must be an existing directory")
    temporary = output.with_name(f".{output.name}.{os.getpid()}.{time.time_ns()}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(canonical_json_bytes(dict(report)) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a portable Ardur DRP implementation fixture bundle."
    )
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_drp_conformance_bundle(args.bundle)
        if args.output is not None:
            write_drp_conformance_report(args.output, report)
    except (OSError, TypeError, ValueError) as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    print(canonical_json_bytes(report).decode("utf-8"))
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

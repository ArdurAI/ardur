"""Ardur's fail-closed profile for DRP draft-10 authorization objects.

The embedded JWK and signed metadata are untrusted inputs. Verification needs
an explicit context containing independently trusted signer bindings, current
operator instructions, the finite tool universe, preverified delegation-log
evidence, and fresh revocation evidence.
"""

from __future__ import annotations

import base64
import copy
import fnmatch
import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from jsonschema import Draft202012Validator, ValidationError

from ._specs import ardur_drp_profile_v01_schema
from .canonical_json import canonical_json_bytes


DRP_SCHEMA_VERSION = "1.0"
ARDUR_DRP_PROFILE = "ardur.drp.v0.1"
TOOL_UNIVERSE_SCHEMA_VERSION = "ardur.drp.tool_universe.v0.1"
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_ACTION_BYTES = 2 * 1024 * 1024
MAX_CHAIN_LENGTH = 32

ARDUR_CRITICAL_PATHS = frozenset(
    {
        "/metadata/x-ardur/missionRef",
        "/metadata/x-ardur/policy",
        "/metadata/x-ardur/capabilityTokenRef",
        "/metadata/x-ardur/resourceBounds",
        "/metadata/x-ardur/argumentConstraints",
        "/metadata/x-ardur/budget",
        "/metadata/x-ardur/redelegation",
        "/metadata/x-ardur/revocation",
        "/metadata/x-ardur/delegationLogAnchor",
        "/metadata/x-ardur/receiptChainAnchor",
    }
)

_DERIVED_FIELDS = frozenset(
    {"receiptId", "canonicalPayload", "signature", "orchestratorSignature"}
)
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_CONSTRAINT_TYPES = frozenset(
    {
        "exact",
        "pattern",
        "range",
        "one_of",
        "not_one_of",
        "contains",
        "subset",
        "regex",
        "cel",
        "wildcard",
        "all",
        "any",
        "not",
    }
)


class DRPProfileError(ValueError):
    """Base error for malformed profile inputs."""


class DRPEmissionError(DRPProfileError):
    """Raised when a requested authorization object cannot be emitted."""


class DRPVerificationError(DRPProfileError):
    """A bounded fail-closed verification result."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail

    def as_dict(self) -> dict[str, Any]:
        return {"decision": "DENY", "reason": self.code, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class DRPVerifiedLogEvidence:
    """Facts produced by an independently trusted log/TSA proof verifier."""

    receipt_id: str
    backend: str
    subject: Literal["receipt-id"]
    integrated_at: datetime
    proof_ref: str
    included_before_use: bool


@dataclass(frozen=True, slots=True)
class DRPVerifiedRevocationEvidence:
    """Fresh revocation facts produced by an authenticated status verifier."""

    ref: str
    status: Literal["active", "revoked", "unknown"]
    observed_at: datetime
    valid_until: datetime
    source: str


@dataclass(frozen=True, slots=True)
class DRPVerifiedReceiptChainEvidence:
    """Facts produced by an independently trusted action-chain verifier."""

    receipt_id: str
    trace_id: str
    head_receipt_id: str
    head_receipt_jwt_sha256: str
    observed_at: datetime
    source: str


@dataclass(frozen=True, slots=True)
class DRPVerificationContext:
    """External trust and current-state inputs for one verification decision."""

    signer_keys: Mapping[str, ec.EllipticCurvePublicKey]
    operator_instructions: Mapping[str, str]
    tool_universes: Mapping[str, Sequence[Mapping[str, str]]]
    log_evidence: Mapping[str, DRPVerifiedLogEvidence]
    revocation_evidence: Mapping[str, DRPVerifiedRevocationEvidence]
    receipt_chain_evidence: Mapping[str, DRPVerifiedReceiptChainEvidence]


@dataclass(frozen=True, slots=True)
class DRPVerificationResult:
    decision: Literal["PERMIT"]
    reason: Literal["verified"]
    profile: str
    receipt_ids: tuple[str, ...]
    leaf_receipt_id: str
    chain_depth: int
    action: dict[str, Any]
    verified_at: str
    checks: dict[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "profile": self.profile,
            "receipt_ids": list(self.receipt_ids),
            "leaf_receipt_id": self.leaf_receipt_id,
            "chain_depth": self.chain_depth,
            "action": dict(self.action),
            "verified_at": self.verified_at,
            "checks": dict(self.checks),
        }


def _deny(code: str, detail: str) -> None:
    raise DRPVerificationError(code, detail)


def _require_private_key(key: Any, label: str) -> ec.EllipticCurvePrivateKey:
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise TypeError(f"{label} must be an ES256 P-256 private key")
    return key


def _require_public_key(key: Any, label: str) -> ec.EllipticCurvePublicKey:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise TypeError(f"{label} must be an ES256 P-256 public key")
    return key


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: Any, label: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or _BASE64URL_RE.fullmatch(value) is None
    ):
        _deny("MALFORMED_ENCODING", f"{label} must be unpadded base64url")
    try:
        return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except ValueError as exc:
        raise DRPVerificationError(
            "MALFORMED_ENCODING", f"{label} is not valid base64url"
        ) from exc


def _public_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    numbers = _require_public_key(key, "signer public key").public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": _b64url_encode(numbers.y.to_bytes(32, "big")),
    }


def _public_key_from_jwk(value: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    if set(value) != {"kty", "crv", "x", "y"}:
        _deny("UNTRUSTED_SIGNER", "publicKey must contain only kty, crv, x, and y")
    if value.get("kty") != "EC" or value.get("crv") != "P-256":
        _deny("UNTRUSTED_SIGNER", "publicKey must be an EC P-256 JWK")
    x = _b64url_decode(value.get("x"), "publicKey.x")
    y = _b64url_decode(value.get("y"), "publicKey.y")
    if len(x) != 32 or len(y) != 32:
        _deny("UNTRUSTED_SIGNER", "P-256 JWK coordinates must be 32 bytes")
    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError as exc:
        raise DRPVerificationError(
            "UNTRUSTED_SIGNER", "publicKey is not a valid P-256 point"
        ) from exc


def _same_public_key(
    left: ec.EllipticCurvePublicKey, right: ec.EllipticCurvePublicKey
) -> bool:
    return left.public_numbers() == right.public_numbers()


def _sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return _b64url_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _verify_signature(
    public_key: ec.EllipticCurvePublicKey,
    signature: Any,
    message: bytes,
    label: str,
) -> None:
    raw = _b64url_decode(signature, label)
    if len(raw) != 64:
        _deny("INVALID_SIGNATURE", f"{label} must decode to a 64-byte ES256 signature")
    der = encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    try:
        public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise DRPVerificationError(
            "INVALID_SIGNATURE", f"{label} did not verify"
        ) from exc


def _normalize_nfc(value: Any, path: str = "$") -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize_nfc(item, f"{path}[]") for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise DRPEmissionError(f"{path} contains a non-string JSON object key")
            key = unicodedata.normalize("NFC", raw_key)
            if key in normalized:
                raise DRPEmissionError(
                    f"{path} contains object names that collide after NFC normalization"
                )
            normalized[key] = _normalize_nfc(raw_value, f"{path}.{key}")
        return normalized
    return copy.deepcopy(value)


def _assert_nfc(value: Any, path: str = "$") -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            _deny("NON_CANONICAL_JSON", f"{path} is not Unicode NFC")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_nfc(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or unicodedata.normalize("NFC", key) != key:
                _deny("NON_CANONICAL_JSON", f"{path} contains a non-NFC object name")
            _assert_nfc(item, f"{path}.{key}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DRPVerificationError(
                "DUPLICATE_JSON_NAME", f"JSON object contains duplicate name {key!r}"
            )
        result[key] = value
    return result


def load_drp_receipt(value: str | bytes | Mapping[str, Any]) -> dict[str, Any]:
    """Load one receipt while rejecting oversized or duplicate-name JSON."""

    if isinstance(value, Mapping):
        receipt = copy.deepcopy(dict(value))
        try:
            encoded = canonical_json_bytes(receipt)
        except (TypeError, ValueError) as exc:
            raise DRPVerificationError(
                "MALFORMED_JSON", "DRP receipt contains a non-canonical JSON value"
            ) from exc
        if len(encoded) > MAX_RECEIPT_BYTES:
            _deny("RECEIPT_TOO_LARGE", "DRP receipt exceeds the 2 MiB input limit")
        return receipt
    raw = value.encode("utf-8") if isinstance(value, str) else value
    if not isinstance(raw, bytes):
        raise TypeError("DRP receipt must be a JSON object, UTF-8 text, or bytes")
    if len(raw) > MAX_RECEIPT_BYTES:
        _deny("RECEIPT_TOO_LARGE", "DRP receipt exceeds the 2 MiB input limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DRPVerificationError(
            "MALFORMED_JSON", "DRP receipt must be UTF-8"
        ) from exc
    try:
        parsed = json.loads(text, object_pairs_hook=_object_without_duplicates)
    except DRPVerificationError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise DRPVerificationError(
            "MALFORMED_JSON", "invalid DRP receipt JSON"
        ) from exc
    if not isinstance(parsed, dict):
        _deny("MALFORMED_JSON", "DRP receipt must be a JSON object")
    try:
        canonical_json_bytes(parsed)
    except (TypeError, ValueError) as exc:
        raise DRPVerificationError(
            "MALFORMED_JSON", "DRP receipt contains a non-canonical JSON value"
        ) from exc
    return parsed


def _schema_error(exc: ValidationError) -> str:
    path = "$"
    for part in exc.absolute_path:
        path += f"[{part}]" if isinstance(part, int) else f".{part}"
    return f"{path}: {exc.message}"


def _x_ardur(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return dict(receipt["metadata"]["x-ardur"])


def _validate_constraint(value: Mapping[str, Any], depth: int = 1) -> None:
    if depth > 16:
        _deny(
            "UNSUPPORTED_CRITICAL_EXTENSION", "argument constraint nesting exceeds 16"
        )
    constraint_type = value.get("constraintType")
    if constraint_type not in _CONSTRAINT_TYPES:
        _deny(
            "UNSUPPORTED_CRITICAL_EXTENSION",
            f"unsupported argument constraint type {constraint_type!r}",
        )
    required_members = {
        "exact": ("value",),
        "pattern": ("value",),
        "one_of": ("values",),
        "not_one_of": ("excluded",),
        "contains": ("required",),
        "subset": ("allowed",),
        "regex": ("pattern",),
        "cel": ("expression",),
        "all": ("constraints",),
        "any": ("constraints",),
        "not": ("constraint",),
    }
    missing = [
        name for name in required_members.get(constraint_type, ()) if name not in value
    ]
    if missing:
        _deny(
            "UNSUPPORTED_CRITICAL_EXTENSION",
            f"{constraint_type} constraint is missing {missing}",
        )
    if constraint_type == "range":
        if "min" not in value and "max" not in value:
            _deny(
                "UNSUPPORTED_CRITICAL_EXTENSION",
                "range constraint requires min or max",
            )
        if "min" in value and "max" in value and value["min"] > value["max"]:
            _deny(
                "UNSUPPORTED_CRITICAL_EXTENSION",
                "range constraint min exceeds max",
            )
    if (
        constraint_type in {"one_of", "all", "any"}
        and not value[required_members[constraint_type][0]]
    ):
        _deny(
            "UNSUPPORTED_CRITICAL_EXTENSION",
            f"{constraint_type} constraint must not be empty",
        )
    if constraint_type in {"cel", "regex"}:
        _deny(
            "UNSUPPORTED_CRITICAL_EXTENSION",
            f"{constraint_type} argument constraints are not implemented safely "
            "by the Python profile",
        )
    for child in value.get("constraints", []):
        _validate_constraint(child, depth + 1)
    inner = value.get("constraint")
    if inner is not None:
        _validate_constraint(inner, depth + 1)


def validate_drp_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the strict portable shape before cryptographic verification."""

    receipt = copy.deepcopy(dict(value))
    try:
        encoded = canonical_json_bytes(receipt)
    except (TypeError, ValueError) as exc:
        raise DRPVerificationError(
            "MALFORMED_JSON", "DRP receipt contains a non-canonical JSON value"
        ) from exc
    if len(encoded) > MAX_RECEIPT_BYTES:
        _deny("RECEIPT_TOO_LARGE", "DRP receipt exceeds the 2 MiB input limit")
    try:
        Draft202012Validator(ardur_drp_profile_v01_schema()).validate(receipt)
    except ValidationError as exc:
        raise DRPProfileError(
            f"DRP profile schema violation: {_schema_error(exc)}"
        ) from exc
    _assert_nfc(receipt)
    extension = _x_ardur(receipt)
    critical = extension["critical"]
    if len(critical) != len(set(critical)):
        _deny("UNSUPPORTED_CRITICAL_EXTENSION", "critical paths must be unique")
    critical_set = frozenset(critical)
    unknown = critical_set - ARDUR_CRITICAL_PATHS
    missing = ARDUR_CRITICAL_PATHS - critical_set
    if unknown:
        _deny(
            "UNSUPPORTED_CRITICAL_EXTENSION",
            f"unknown critical paths: {sorted(unknown)}",
        )
    if missing:
        _deny(
            "UNSUPPORTED_CRITICAL_EXTENSION",
            f"missing critical paths: {sorted(missing)}",
        )
    instructions = receipt["operatorInstructions"]
    expected_hash = "sha256:" + hashlib.sha256(instructions.encode("utf-8")).hexdigest()
    if receipt["operatorInstructionsHash"] != expected_hash:
        _deny(
            "INSTRUCTION_HASH_MISMATCH",
            "operatorInstructionsHash does not bind operatorInstructions",
        )
    if (
        receipt["toolSchemaHash"]
        != extension["capabilityTokenRef"]["toolManifestDigest"]
    ):
        _deny(
            "TOOL_UNIVERSE_MISMATCH",
            "toolSchemaHash does not match capabilityTokenRef.toolManifestDigest",
        )
    if receipt["revocationRequired"] is not extension["revocation"]["required"]:
        _deny(
            "REVOCATION_POLICY_MISMATCH",
            "revocationRequired does not match the critical revocation policy",
        )
    for tool_constraints in extension["argumentConstraints"].values():
        for constraint in tool_constraints.values():
            _validate_constraint(constraint)
    chain_anchor = extension["receiptChainAnchor"]
    if chain_anchor["state"] == "unstarted" and any(
        chain_anchor.get(name) is not None
        for name in ("traceId", "headReceiptId", "headReceiptJwtSha256")
    ):
        _deny(
            "RECEIPT_CHAIN_MISMATCH",
            "an unstarted receipt chain must not claim a trace or chain head",
        )
    not_before = _parse_time(receipt["timeWindow"]["notBefore"], "timeWindow.notBefore")
    not_after = _parse_time(receipt["timeWindow"]["notAfter"], "timeWindow.notAfter")
    if not_before >= not_after:
        _deny("INVALID_TIME_WINDOW", "timeWindow.notBefore must precede notAfter")
    redelegation = extension["redelegation"]
    if redelegation["depth"] > redelegation["maxDepth"]:
        _deny("PARENT_SCOPE_VIOLATION", "redelegation depth exceeds maxDepth")
    return receipt


def _pre_id_body(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in receipt.items()
        if key not in _DERIVED_FIELDS
    }


def _signed_body(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in receipt.items()
        if key not in {"canonicalPayload", "signature", "orchestratorSignature"}
    }


def emit_drp_receipt(
    authorization: Mapping[str, Any],
    signer_private_key: ec.EllipticCurvePrivateKey,
    *,
    parent_orchestrator_private_key: ec.EllipticCurvePrivateKey | None = None,
) -> dict[str, Any]:
    """Emit one deterministic Ardur DRP profile receipt."""

    signer = _require_private_key(signer_private_key, "signer key")
    body = _normalize_nfc(authorization)
    if not isinstance(body, dict):
        raise DRPEmissionError("authorization must be a JSON object")
    supplied_derived = _DERIVED_FIELDS.intersection(body)
    if supplied_derived:
        raise DRPEmissionError(
            f"authorization must omit derived fields: {sorted(supplied_derived)}"
        )
    expected_jwk = _public_jwk(signer.public_key())
    supplied_jwk = body.get("publicKey")
    if supplied_jwk is not None and supplied_jwk != expected_jwk:
        raise DRPEmissionError("authorization publicKey does not match signer key")
    body["publicKey"] = expected_jwk
    has_parent = "parentReceiptId" in body
    if has_parent and parent_orchestrator_private_key is None:
        raise DRPEmissionError("child receipt requires the parent orchestrator key")
    if not has_parent and parent_orchestrator_private_key is not None:
        raise DRPEmissionError(
            "root receipt must not receive a parent orchestrator key"
        )
    receipt_id = "rec_" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    signed_body = {**body, "receiptId": receipt_id}
    canonical_payload = canonical_json_bytes(signed_body)
    receipt = {
        **signed_body,
        "canonicalPayload": _b64url_encode(canonical_payload),
        "signature": _sign(signer, canonical_payload),
    }
    if has_parent:
        parent_signer = _require_private_key(
            parent_orchestrator_private_key, "parent orchestrator key"
        )
        binding = (
            f"orchestrator-delegation:{body['parentReceiptId']}:{receipt_id}"
        ).encode("ascii")
        receipt["orchestratorSignature"] = _sign(parent_signer, binding)
    try:
        return validate_drp_receipt(receipt)
    except DRPProfileError as exc:
        raise DRPEmissionError(str(exc)) from exc


def _validate_canonical_and_signature(
    receipt: Mapping[str, Any], trusted_key: ec.EllipticCurvePublicKey
) -> None:
    receipt_id = receipt["receiptId"]
    expected_id = (
        "rec_" + hashlib.sha256(canonical_json_bytes(_pre_id_body(receipt))).hexdigest()
    )
    if receipt_id != expected_id:
        _deny("RECEIPT_ID_MISMATCH", "receiptId does not match the profile pre-ID body")
    expected_payload = canonical_json_bytes(_signed_body(receipt))
    decoded_payload = _b64url_decode(receipt["canonicalPayload"], "canonicalPayload")
    if decoded_payload != expected_payload:
        _deny(
            "NON_CANONICAL_JSON",
            "canonicalPayload does not exactly match the RFC 8785 signed body",
        )
    embedded = _public_key_from_jwk(receipt["publicKey"])
    if not _same_public_key(embedded, trusted_key):
        _deny(
            "UNTRUSTED_SIGNER",
            "embedded publicKey does not match the externally trusted issuer binding",
        )
    _verify_signature(trusted_key, receipt["signature"], decoded_payload, "signature")


def _as_utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _deny("INSUFFICIENT_EVIDENCE", f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _parse_time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC_RE.fullmatch(value) is None:
        _deny(
            "INVALID_TIME_WINDOW",
            f"{label} must use RFC 3339 UTC with at most six fractional digits",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DRPVerificationError(
            "INVALID_TIME_WINDOW", f"{label} is not a valid RFC 3339 timestamp"
        ) from exc
    return parsed.astimezone(timezone.utc)


def tool_universe_document(
    actions: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    """Return the canonical finite action universe bound by toolSchemaHash."""

    normalized: set[tuple[str, str]] = set()
    for index, raw in enumerate(actions):
        if not isinstance(raw, Mapping) or set(raw) != {"operation", "resource"}:
            raise DRPProfileError(
                f"tool universe action {index} must contain only operation and resource"
            )
        operation = raw.get("operation")
        resource = raw.get("resource")
        if (
            not isinstance(operation, str)
            or not operation
            or not isinstance(resource, str)
            or not resource
        ):
            raise DRPProfileError(
                f"tool universe action {index} fields must be non-empty strings"
            )
        if "*" in operation or "*" in resource:
            raise DRPProfileError(
                "tool universe entries must be concrete, not wildcarded"
            )
        normalized.add((operation, resource))
    if not normalized:
        raise DRPProfileError("tool universe must contain at least one concrete action")
    return {
        "schemaVersion": TOOL_UNIVERSE_SCHEMA_VERSION,
        "actions": [
            {"operation": operation, "resource": resource}
            for operation, resource in sorted(normalized)
        ],
    }


def tool_universe_digest(actions: Sequence[Mapping[str, str]]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(tool_universe_document(actions))
        ).hexdigest()
    )


def _scope_pattern_matches(pattern: Mapping[str, str], action: tuple[str, str]) -> bool:
    operation = pattern["operation"]
    resource = pattern["resource"]
    for value, label in ((operation, "operation"), (resource, "resource")):
        if "*" in value and value != "*":
            _deny(
                "UNSUPPORTED_SCOPE_PATTERN",
                f"base DRP {label} supports only an exact value or the full '*' wildcard",
            )
    return (operation == "*" or operation == action[0]) and (
        resource == "*" or resource == action[1]
    )


def _effective_scope(
    receipt: Mapping[str, Any],
    context: DRPVerificationContext,
) -> tuple[set[tuple[str, str]], set[tuple[str, str]], set[str]]:
    digest = receipt["toolSchemaHash"]
    universe_input = context.tool_universes.get(digest)
    if universe_input is None:
        _deny(
            "INSUFFICIENT_EVIDENCE",
            f"trusted finite tool universe is missing for {digest}",
        )
    try:
        universe_doc = tool_universe_document(universe_input)
    except DRPProfileError as exc:
        raise DRPVerificationError("TOOL_UNIVERSE_MISMATCH", str(exc)) from exc
    actual_digest = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(universe_doc)).hexdigest()
    )
    if actual_digest != digest:
        _deny("TOOL_UNIVERSE_MISMATCH", "trusted tool universe digest mismatch")
    universe = {
        (entry["operation"], entry["resource"]) for entry in universe_doc["actions"]
    }
    allowed = {
        action
        for pattern in receipt["scope"]["allowedActions"]
        for action in universe
        if _scope_pattern_matches(pattern, action)
    }
    denied = {
        action
        for pattern in receipt["scope"]["deniedActions"]
        for action in universe
        if _scope_pattern_matches(pattern, action)
    }
    if not allowed:
        _deny("SCOPE_EMPTY", "allowedActions matches no action in the trusted universe")
    resources = {resource for _operation, resource in universe}
    return allowed - denied, denied, resources


def _resource_pattern_set(patterns: Sequence[str], universe: set[str]) -> set[str]:
    result: set[str] = set()
    for pattern in patterns:
        if any(character in pattern for character in "?[]"):
            _deny(
                "UNSUPPORTED_CRITICAL_EXTENSION",
                f"unsupported resource-bound pattern {pattern!r}",
            )
        if "*" in pattern and (pattern.count("*") != 1 or not pattern.endswith("*")):
            _deny(
                "UNSUPPORTED_CRITICAL_EXTENSION",
                f"resource-bound wildcard must be one trailing '*': {pattern!r}",
            )
        matched = {
            resource for resource in universe if fnmatch.fnmatchcase(resource, pattern)
        }
        if not matched:
            _deny(
                "RESOURCE_BOUND_UNRESOLVED",
                f"resource bound {pattern!r} matches no trusted resource",
            )
        result.update(matched)
    return result


def _contained_cwd(parent: str, child: str) -> bool:
    parent_path = PurePosixPath(parent)
    child_path = PurePosixPath(child)
    if not parent_path.is_absolute() or not child_path.is_absolute():
        return False
    if ".." in parent_path.parts or ".." in child_path.parts:
        return False
    return child_path == parent_path or parent_path in child_path.parents


def _json_value_set(values: Sequence[Any]) -> set[bytes]:
    return {canonical_json_bytes(value) for value in values}


def _number_in_range(value: Any, constraint: Mapping[str, Any]) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    minimum = constraint.get("min")
    maximum = constraint.get("max")
    if minimum is not None:
        if value < minimum or (
            value == minimum and constraint.get("minInclusive") is False
        ):
            return False
    if maximum is not None:
        if value > maximum or (
            value == maximum and constraint.get("maxInclusive") is False
        ):
            return False
    return True


def _range_contains(parent: Mapping[str, Any], child: Mapping[str, Any]) -> bool:
    parent_min = parent.get("min")
    child_min = child.get("min")
    parent_max = parent.get("max")
    child_max = child.get("max")
    if parent_min is not None and (
        child_min is None
        or child_min < parent_min
        or (
            child_min == parent_min
            and parent.get("minInclusive") is False
            and child.get("minInclusive") is not False
        )
    ):
        return False
    if parent_max is not None and (
        child_max is None
        or child_max > parent_max
        or (
            child_max == parent_max
            and parent.get("maxInclusive") is False
            and child.get("maxInclusive") is not False
        )
    ):
        return False
    return True


def _constraint_subsumes(parent: Mapping[str, Any], child: Mapping[str, Any]) -> bool:
    if canonical_json_bytes(parent) == canonical_json_bytes(child):
        return True
    parent_type = parent["constraintType"]
    child_type = child["constraintType"]
    if parent_type == "wildcard":
        return True
    if child_type == "exact":
        value = child.get("value")
        if parent_type == "one_of":
            return canonical_json_bytes(value) in _json_value_set(
                parent.get("values", [])
            )
        if parent_type == "not_one_of":
            return canonical_json_bytes(value) not in _json_value_set(
                parent.get("excluded", [])
            )
        if parent_type == "range":
            return _number_in_range(value, parent)
        if parent_type == "pattern" and isinstance(value, str):
            pattern = parent.get("value")
            return isinstance(pattern, str) and fnmatch.fnmatchcase(value, pattern)
    if parent_type == child_type == "one_of":
        return _json_value_set(child.get("values", [])) <= _json_value_set(
            parent.get("values", [])
        )
    if parent_type == child_type == "not_one_of":
        return _json_value_set(parent.get("excluded", [])) <= _json_value_set(
            child.get("excluded", [])
        )
    if parent_type == child_type == "contains":
        return _json_value_set(parent.get("required", [])) <= _json_value_set(
            child.get("required", [])
        )
    if parent_type == child_type == "subset":
        return _json_value_set(child.get("allowed", [])) <= _json_value_set(
            parent.get("allowed", [])
        )
    if parent_type == child_type == "range":
        return _range_contains(parent, child)
    return False


def _verify_argument_constraints(
    parent: Mapping[str, Any],
    child: Mapping[str, Any],
    child_allowed_resources: set[str],
) -> None:
    for tool, parent_arguments in parent.items():
        if parent_arguments and tool in child_allowed_resources and not child.get(tool):
            _deny(
                "ARGUMENT_CONSTRAINT_WIDENING",
                f"child drops the closed argument map for still-authorized tool {tool}",
            )
    for tool, child_arguments in child.items():
        parent_arguments = parent.get(tool)
        if parent_arguments is None or not parent_arguments:
            continue
        if not set(child_arguments) <= set(parent_arguments):
            _deny(
                "ARGUMENT_CONSTRAINT_WIDENING",
                f"child introduces an argument allowed by no closed parent map for {tool}",
            )
        for argument, child_constraint in child_arguments.items():
            if not _constraint_subsumes(parent_arguments[argument], child_constraint):
                _deny(
                    "ARGUMENT_CONSTRAINT_WIDENING",
                    f"child constraint widens or is not provably narrower for {tool}.{argument}",
                )


def _check_constraint(value: Any, constraint: Mapping[str, Any]) -> bool:
    constraint_type = constraint["constraintType"]
    if constraint_type == "exact":
        return canonical_json_bytes(value) == canonical_json_bytes(
            constraint.get("value")
        )
    if constraint_type == "pattern":
        pattern = constraint.get("value")
        return (
            isinstance(value, str)
            and isinstance(pattern, str)
            and fnmatch.fnmatchcase(value, pattern)
        )
    if constraint_type == "range":
        return _number_in_range(value, constraint)
    if constraint_type == "one_of":
        return canonical_json_bytes(value) in _json_value_set(
            constraint.get("values", [])
        )
    if constraint_type == "not_one_of":
        return canonical_json_bytes(value) not in _json_value_set(
            constraint.get("excluded", [])
        )
    if constraint_type == "contains":
        if not isinstance(value, list):
            return False
        actual = _json_value_set(value)
        return _json_value_set(constraint.get("required", [])) <= actual
    if constraint_type == "subset":
        if not isinstance(value, list):
            return False
        return _json_value_set(value) <= _json_value_set(constraint.get("allowed", []))
    if constraint_type == "regex":
        pattern = constraint.get("pattern")
        if not isinstance(value, str) or not isinstance(pattern, str):
            return False
        try:
            return re.fullmatch(pattern, value) is not None
        except re.error:
            return False
    if constraint_type == "wildcard":
        return True
    if constraint_type == "all":
        return all(
            _check_constraint(value, child)
            for child in constraint.get("constraints", [])
        )
    if constraint_type == "any":
        return any(
            _check_constraint(value, child)
            for child in constraint.get("constraints", [])
        )
    if constraint_type == "not":
        return not _check_constraint(value, constraint["constraint"])
    return False


def _verify_action_arguments(
    leaf: Mapping[str, Any],
    resource: str,
    arguments: Mapping[str, Any],
) -> None:
    constraints = _x_ardur(leaf)["argumentConstraints"].get(resource, {})
    if not constraints:
        return
    if set(arguments) != set(constraints):
        _deny(
            "ARGUMENT_CONSTRAINT_VIOLATION",
            "action arguments do not match the leaf closed-world constraint map",
        )
    for name, constraint in constraints.items():
        if not _check_constraint(arguments[name], constraint):
            _deny(
                "ARGUMENT_CONSTRAINT_VIOLATION",
                f"action argument {name!r} violates the leaf constraint",
            )


def _verify_budget(parent: Mapping[str, Any], child: Mapping[str, Any]) -> None:
    if child["maxToolCalls"] > parent["maxToolCalls"]:
        _deny("BUDGET_WIDENING", "child maxToolCalls exceeds parent")
    if child["reservedShare"] > parent["reservedShare"]:
        _deny("BUDGET_WIDENING", "child reservedShare exceeds parent")
    parent_classes = parent["maxToolCallsPerClass"]
    child_classes = child["maxToolCallsPerClass"]
    if parent_classes and not set(child_classes) <= set(parent_classes):
        _deny("BUDGET_WIDENING", "child introduces an unbounded side-effect class")
    for name, value in child_classes.items():
        if name in parent_classes and value > parent_classes[name]:
            _deny(
                "BUDGET_WIDENING",
                f"child budget for side-effect class {name!r} exceeds parent",
            )


def _verify_external_evidence(
    receipt: Mapping[str, Any],
    context: DRPVerificationContext,
    decision_time: datetime,
    *,
    offline: bool,
) -> None:
    receipt_id = receipt["receiptId"]
    extension = _x_ardur(receipt)
    log_policy = extension["delegationLogAnchor"]
    log = context.log_evidence.get(receipt_id)
    if log is None:
        _deny(
            "INSUFFICIENT_EVIDENCE",
            f"pre-action delegation-log/TSA evidence missing for {receipt_id}",
        )
    integrated_at = _as_utc(log.integrated_at, "log integrated_at")
    if (
        log.receipt_id != receipt_id
        or log.backend != log_policy["backend"]
        or log.subject != log_policy["subject"]
        or not log.proof_ref
        or not log.included_before_use
    ):
        _deny(
            "INSUFFICIENT_EVIDENCE",
            f"delegation-log evidence does not satisfy signed policy for {receipt_id}",
        )
    not_before = _parse_time(receipt["timeWindow"]["notBefore"], "timeWindow.notBefore")
    not_after = _parse_time(receipt["timeWindow"]["notAfter"], "timeWindow.notAfter")
    if integrated_at < not_before or integrated_at > decision_time:
        _deny(
            "INVALID_LOG_TIME",
            f"log integration for {receipt_id} was outside the pre-action window",
        )
    if decision_time > not_after:
        _deny("EXPIRED", f"receipt {receipt_id} expired before the decision")
    if offline and receipt["revocationRequired"]:
        _deny(
            "REVOCATION_CHECK_REQUIRED",
            f"receipt {receipt_id} requires online revocation verification",
        )
    revocation_ref = extension["revocation"]["ref"]
    status = context.revocation_evidence.get(revocation_ref)
    if status is None:
        _deny(
            "INSUFFICIENT_EVIDENCE",
            f"revocation evidence missing for {revocation_ref}",
        )
    observed_at = _as_utc(status.observed_at, "revocation observed_at")
    valid_until = _as_utc(status.valid_until, "revocation valid_until")
    if (
        status.ref != revocation_ref
        or not status.source
        or observed_at > decision_time
        or valid_until < decision_time
    ):
        _deny(
            "INSUFFICIENT_EVIDENCE",
            f"revocation evidence is mismatched or stale for {receipt_id}",
        )
    if status.status == "revoked":
        _deny("REVOKED", f"receipt {receipt_id} is revoked")
    if status.status != "active":
        _deny("INSUFFICIENT_EVIDENCE", f"revocation state is unknown for {receipt_id}")
    chain_anchor = extension["receiptChainAnchor"]
    if chain_anchor["state"] == "present":
        chain = context.receipt_chain_evidence.get(receipt_id)
        if chain is None:
            _deny(
                "INSUFFICIENT_EVIDENCE",
                f"verified action-chain evidence missing for {receipt_id}",
            )
        observed_at = _as_utc(chain.observed_at, "receipt-chain observed_at")
        if (
            chain.receipt_id != receipt_id
            or chain.trace_id != chain_anchor["traceId"]
            or chain.head_receipt_id != chain_anchor["headReceiptId"]
            or chain.head_receipt_jwt_sha256 != chain_anchor["headReceiptJwtSha256"]
            or observed_at > decision_time
            or not chain.source
        ):
            _deny(
                "RECEIPT_CHAIN_MISMATCH",
                f"action-chain evidence does not satisfy the signed anchor for {receipt_id}",
            )


def _verify_receipt(
    receipt: Mapping[str, Any],
    context: DRPVerificationContext,
    decision_time: datetime,
    *,
    offline: bool,
) -> tuple[set[tuple[str, str]], set[tuple[str, str]], set[str]]:
    issuer = _x_ardur(receipt)["issuer"]
    trusted_key = context.signer_keys.get(issuer)
    if trusted_key is None:
        _deny("UNTRUSTED_SIGNER", f"no trusted signer binding for issuer {issuer!r}")
    try:
        public_key = _require_public_key(trusted_key, f"trusted key for {issuer}")
    except TypeError as exc:
        raise DRPVerificationError("UNTRUSTED_SIGNER", str(exc)) from exc
    _validate_canonical_and_signature(receipt, public_key)
    current_instructions = context.operator_instructions.get(receipt["receiptId"])
    if current_instructions is None:
        _deny(
            "INSUFFICIENT_EVIDENCE",
            f"current operator instructions missing for {receipt['receiptId']}",
        )
    current_hash = (
        "sha256:"
        + hashlib.sha256(
            unicodedata.normalize("NFC", current_instructions).encode("utf-8")
        ).hexdigest()
    )
    if (
        current_hash != receipt["operatorInstructionsHash"]
        or unicodedata.normalize("NFC", current_instructions)
        != receipt["operatorInstructions"]
    ):
        _deny(
            "INSTRUCTION_HASH_MISMATCH",
            f"operator instruction drift detected for {receipt['receiptId']}",
        )
    scope = _effective_scope(receipt, context)
    _verify_external_evidence(receipt, context, decision_time, offline=offline)
    return scope


def _verify_edge(
    parent: Mapping[str, Any],
    child: Mapping[str, Any],
    parent_scope: tuple[set[tuple[str, str]], set[tuple[str, str]], set[str]],
    child_scope: tuple[set[tuple[str, str]], set[tuple[str, str]], set[str]],
    context: DRPVerificationContext,
) -> None:
    parent_id = parent["receiptId"]
    child_id = child["receiptId"]
    if child.get("parentReceiptId") != parent_id:
        _deny("MISSING_ANCESTOR", f"{child_id} does not bind its immediate parent")
    parent_extension = _x_ardur(parent)
    child_extension = _x_ardur(child)
    parent_redelegation = parent_extension["redelegation"]
    child_redelegation = child_extension["redelegation"]
    if parent_redelegation["mode"] != "bounded":
        _deny("REDELEGATION_DENIED", f"parent {parent_id} forbids re-delegation")
    if child_redelegation["depth"] != parent_redelegation["depth"] + 1:
        _deny("PARENT_SCOPE_VIOLATION", "child depth is not parent depth plus one")
    if child_redelegation["depth"] >= parent_redelegation["maxDepth"]:
        _deny("REDELEGATION_DENIED", "parent delegation depth is exhausted")
    if child_redelegation["maxDepth"] > parent_redelegation["maxDepth"]:
        _deny("PARENT_SCOPE_VIOLATION", "child maxDepth exceeds parent maxDepth")
    if child_extension["issuer"] != parent_extension["subject"]:
        _deny("PARENT_SCOPE_VIOLATION", "child issuer is not the parent subject")
    expected_parent_token = (
        "sha-256:" + parent_extension["capabilityTokenRef"]["sha256"]
    )
    if child_redelegation.get("parentTokenHash") != expected_parent_token:
        _deny(
            "PARENT_SCOPE_VIOLATION",
            "child parentTokenHash does not bind the parent capability token",
        )
    parent_key = context.signer_keys.get(parent_extension["issuer"])
    if parent_key is None:
        _deny("UNTRUSTED_SIGNER", "trusted parent orchestrator key is missing")
    binding = f"orchestrator-delegation:{parent_id}:{child_id}".encode("ascii")
    _verify_signature(
        _require_public_key(parent_key, "trusted parent orchestrator key"),
        child["orchestratorSignature"],
        binding,
        "orchestratorSignature",
    )
    parent_start = _parse_time(
        parent["timeWindow"]["notBefore"], "parent timeWindow.notBefore"
    )
    parent_end = _parse_time(
        parent["timeWindow"]["notAfter"], "parent timeWindow.notAfter"
    )
    child_start = _parse_time(
        child["timeWindow"]["notBefore"], "child timeWindow.notBefore"
    )
    child_end = _parse_time(
        child["timeWindow"]["notAfter"], "child timeWindow.notAfter"
    )
    if child_start < parent_start or child_end > parent_end:
        _deny("PARENT_SCOPE_VIOLATION", "child time window exceeds parent")
    if child["toolSchemaHash"] != parent["toolSchemaHash"]:
        _deny(
            "TOOL_UNIVERSE_MISMATCH",
            "profile v0.1 requires one authenticated universe across the chain",
        )
    parent_allowed, parent_denied, parent_resources = parent_scope
    child_allowed, child_denied, child_resources = child_scope
    if not child_allowed < parent_allowed:
        _deny(
            "SCOPE_NOT_STRICT_SUBSET",
            "child effective allowed-action set is not a strict proper subset",
        )
    if not parent_denied <= child_denied:
        _deny("PARENT_SCOPE_VIOLATION", "child does not preserve parent denials")
    if not set(parent["boundaries"]) <= set(child["boundaries"]):
        _deny("PARENT_SCOPE_VIOLATION", "child does not preserve parent boundaries")
    if parent_resources != child_resources:
        _deny("TOOL_UNIVERSE_MISMATCH", "chain resolved different resource universes")
    for field in ("audience", "missionRef", "policy"):
        if child_extension[field] != parent_extension[field]:
            _deny("PARENT_SCOPE_VIOLATION", f"child changes critical {field}")
    parent_bounds = parent_extension["resourceBounds"]
    child_bounds = child_extension["resourceBounds"]
    if not set(child_bounds["sideEffectClasses"]) <= set(
        parent_bounds["sideEffectClasses"]
    ):
        _deny("RESOURCE_BOUND_WIDENING", "child adds a side-effect class")
    parent_bound_set = _resource_pattern_set(
        parent_bounds["resources"], parent_resources
    )
    child_bound_set = _resource_pattern_set(child_bounds["resources"], child_resources)
    if not child_bound_set <= parent_bound_set:
        _deny("RESOURCE_BOUND_WIDENING", "child resource bounds exceed parent")
    if not _contained_cwd(parent_bounds["cwd"], child_bounds["cwd"]):
        _deny("RESOURCE_BOUND_WIDENING", "child cwd is outside parent cwd")
    _verify_argument_constraints(
        parent_extension["argumentConstraints"],
        child_extension["argumentConstraints"],
        {resource for _operation, resource in child_allowed},
    )
    _verify_budget(parent_extension["budget"], child_extension["budget"])
    if (
        child_extension["revocation"]["cascade"]
        != parent_extension["revocation"]["cascade"]
    ):
        _deny("REVOCATION_POLICY_MISMATCH", "child changes cascade semantics")
    if (
        parent_extension["revocation"]["required"]
        and not child_extension["revocation"]["required"]
    ):
        _deny("REVOCATION_POLICY_MISMATCH", "child weakens required revocation")


def _requested_action(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _deny("INVALID_ACTION", "action must be an object")
    allowed_fields = {"operation", "resource", "arguments", "sideEffectClass", "cwd"}
    if not set(value) <= allowed_fields:
        _deny("INVALID_ACTION", "action contains unknown fields")
    missing = {"operation", "resource", "sideEffectClass", "cwd"} - set(value)
    if missing:
        _deny("INVALID_ACTION", f"action is missing required fields: {sorted(missing)}")
    try:
        descriptor = tool_universe_document(
            [
                {
                    "operation": value.get("operation"),
                    "resource": value.get("resource"),
                }
            ]
        )["actions"][0]
    except DRPProfileError as exc:
        raise DRPVerificationError("INVALID_ACTION", str(exc)) from exc
    arguments = value.get("arguments", {})
    if not isinstance(arguments, Mapping) or any(
        not isinstance(name, str) or not name for name in arguments
    ):
        _deny("INVALID_ACTION", "action.arguments must be an object with named fields")
    side_effect_class = value.get("sideEffectClass")
    cwd = value.get("cwd")
    if not isinstance(side_effect_class, str) or not side_effect_class:
        _deny("INVALID_ACTION", "action.sideEffectClass must be a non-empty string")
    if not isinstance(cwd, str) or not _contained_cwd("/", cwd):
        _deny("INVALID_ACTION", "action.cwd must be an absolute normalized path")
    action = {
        **descriptor,
        "arguments": copy.deepcopy(dict(arguments)),
        "sideEffectClass": side_effect_class,
        "cwd": cwd,
    }
    try:
        _assert_nfc(action)
    except DRPVerificationError as exc:
        raise DRPVerificationError(
            "INVALID_ACTION", "action strings and object names must use Unicode NFC"
        ) from exc
    try:
        encoded = canonical_json_bytes(action)
    except (TypeError, ValueError) as exc:
        raise DRPVerificationError(
            "INVALID_ACTION", "action contains a non-canonical JSON value"
        ) from exc
    if len(encoded) > MAX_ACTION_BYTES:
        _deny("ACTION_TOO_LARGE", "action exceeds the 2 MiB input limit")
    return action


def _verify_action_bounds(
    leaf: Mapping[str, Any], trusted_resources: set[str], action: Mapping[str, Any]
) -> None:
    bounds = _x_ardur(leaf)["resourceBounds"]
    allowed_resources = _resource_pattern_set(bounds["resources"], trusted_resources)
    if action["resource"] not in allowed_resources:
        _deny(
            "RESOURCE_BOUND_VIOLATION",
            "requested resource is outside the leaf resource bounds",
        )
    if action["sideEffectClass"] not in bounds["sideEffectClasses"]:
        _deny(
            "RESOURCE_BOUND_VIOLATION",
            "requested side-effect class is outside the leaf resource bounds",
        )
    if not _contained_cwd(bounds["cwd"], action["cwd"]):
        _deny(
            "RESOURCE_BOUND_VIOLATION",
            "requested cwd is outside the leaf resource bounds",
        )


def verify_drp_chain(
    receipts: Sequence[str | bytes | Mapping[str, Any]],
    *,
    action: Mapping[str, Any],
    context: DRPVerificationContext,
    decision_time: datetime,
    offline: bool = False,
) -> DRPVerificationResult:
    """Verify a root-to-leaf chain and one concrete requested action."""

    if not receipts:
        _deny("MISSING_ANCESTOR", "DRP chain must contain a root receipt")
    if len(receipts) > MAX_CHAIN_LENGTH:
        _deny("CHAIN_TOO_LONG", f"DRP chain exceeds {MAX_CHAIN_LENGTH} receipts")
    action_doc = _requested_action(action)
    at = _as_utc(decision_time, "decision_time")
    parsed: list[dict[str, Any]] = []
    for value in receipts:
        try:
            parsed.append(validate_drp_receipt(load_drp_receipt(value)))
        except DRPVerificationError:
            raise
        except DRPProfileError as exc:
            raise DRPVerificationError("SCHEMA_INVALID", str(exc)) from exc
    receipt_ids = tuple(receipt["receiptId"] for receipt in parsed)
    if len(receipt_ids) != len(set(receipt_ids)):
        _deny("REPLAYED_RECEIPT", "DRP chain contains a duplicate receiptId")
    root = parsed[0]
    root_redelegation = _x_ardur(root)["redelegation"]
    if "parentReceiptId" in root or "orchestratorSignature" in root:
        _deny("PARENT_SCOPE_VIOLATION", "root receipt carries parent-only fields")
    if root_redelegation["depth"] != 0 or "parentTokenHash" in root_redelegation:
        _deny(
            "PARENT_SCOPE_VIOLATION", "root re-delegation metadata is not root-shaped"
        )
    scopes = [
        _verify_receipt(receipt, context, at, offline=offline) for receipt in parsed
    ]
    for index in range(1, len(parsed)):
        _verify_edge(
            parsed[index - 1],
            parsed[index],
            scopes[index - 1],
            scopes[index],
            context,
        )
    leaf_allowed = scopes[-1][0]
    action_tuple = (action_doc["operation"], action_doc["resource"])
    if action_tuple not in leaf_allowed:
        _deny(
            "ACTION_NOT_IN_SCOPE",
            f"leaf receipt does not permit {action_tuple[0]} on {action_tuple[1]}",
        )
    _verify_action_bounds(parsed[-1], scopes[-1][2], action_doc)
    _verify_action_arguments(parsed[-1], action_tuple[1], action_doc["arguments"])
    return DRPVerificationResult(
        decision="PERMIT",
        reason="verified",
        profile=ARDUR_DRP_PROFILE,
        receipt_ids=receipt_ids,
        leaf_receipt_id=receipt_ids[-1],
        chain_depth=len(parsed) - 1,
        action=action_doc,
        verified_at=at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        checks={
            "receipts": len(parsed),
            "signatures": len(parsed),
            "orchestrator_signatures": len(parsed) - 1,
            "attenuation_edges": len(parsed) - 1,
            "log_evidence": len(parsed),
            "revocation_evidence": len(parsed),
            "receipt_chain_evidence": sum(
                _x_ardur(receipt)["receiptChainAnchor"]["state"] == "present"
                for receipt in parsed
            ),
        },
    )

"""Receiver-side co-signatures for immutable Ardur Execution Receipts.

The action receipt remains the governor's signed statement. A receiver
attestation envelope adds a second, independently verifiable JWS over what the
called service observed. The envelope never rewrites the action receipt.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, ValidationError

from ._specs import receiver_attestation_v01_schema
from .canonical_json import RFC8785JSONEncoder, canonical_json_bytes
from .passport import ALGORITHM
from .receipt import RECEIPT_JWT_TYPE, verify_receipt
from .transparency import receipt_subject


ENVELOPE_SCHEMA_VERSION = "ardur.receiver_attestation.v0.1"
STATEMENT_SCHEMA_VERSION = "ardur.receiver_attestation_statement.v0.1"
ATTESTATION_JWT_TYPE = "application/ardur.receiver-attestation+jwt"
ASSURANCE_SELF_ATTESTED = "self-attested"
ASSURANCE_RECEIVER_ATTESTED = "receiver-attested"
MCP_TOOLS_CALL_METHOD = "tools/call"
MCP_RECEIPT_META_KEY = "ai.ardur/execution-receipt"
MCP_ATTESTATION_META_KEY = "ai.ardur/receiver-attestation"
DEFAULT_MAX_ATTESTATION_DELAY_S = 300
DEFAULT_RECEIVER_CLOCK_SKEW_S = 60
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_JSON_DOCUMENT_BYTES = 8 * 1024 * 1024

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ATTESTATION_ID_RE = re.compile(r"^receiver-attestation:[0-9a-f]{64}$")
_SHA256_B64URL_LENGTH = 43
_STATEMENT_FIELDS = {
    "schema_version",
    "canonicalization",
    "attestation_id",
    "receipt_subject",
    "receipt_id",
    "action_id",
    "step_id",
    "invocation_digest",
    "authority_summary",
    "request_digest",
    "response_digest",
    "result_status",
    "receiver_id",
    "observed_at",
    "iat",
    "jti",
}
_AUTHORITY_FIELDS = (
    "actor",
    "grant_id",
    "verifier_id",
    "action_class",
    "target",
    "resource_family",
    "side_effect_class",
    "verdict",
)


class ReceiverAttestationError(ValueError):
    """Base error for malformed receiver-attestation data."""


class ReceiverAttestationVerificationError(ReceiverAttestationError):
    """Raised when either signature or a cross-binding fails closed."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64url_sha256(value: Any) -> str:
    digest = hashlib.sha256(canonical_json_bytes(value)).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _digest_object(scope: str, value: Any) -> dict[str, str]:
    return {
        "alg": "sha-256",
        "canonicalization": "jcs-rfc8785",
        "scope": scope,
        "value": _b64url_sha256(value),
    }


def _observed_at(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _authority_summary(receipt_claims: Mapping[str, Any]) -> dict[str, str]:
    summary: dict[str, str] = {}
    for field in _AUTHORITY_FIELDS:
        value = receipt_claims.get(field)
        if not isinstance(value, str) or not value:
            raise ReceiverAttestationError(f"receipt {field} is required for receiver attestation")
        summary[field] = value
    return summary


def _require_es256_private_key(key: Any) -> ec.EllipticCurvePrivateKey:
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise TypeError("receiver private key must be an ES256 P-256 key")
    return key


def _require_es256_public_key(key: Any, label: str) -> ec.EllipticCurvePublicKey:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise TypeError(f"{label} must be an ES256 P-256 public key")
    return key


def _mcp_call_parts(request: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    if request.get("jsonrpc") != "2.0":
        raise ReceiverAttestationError("MCP request jsonrpc must be '2.0'")
    request_id = request.get("id")
    if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
        raise ReceiverAttestationError("MCP request id must be a string or integer")
    if request.get("method") != MCP_TOOLS_CALL_METHOD:
        raise ReceiverAttestationError("MCP request method must be 'tools/call'")
    params = request.get("params")
    if not isinstance(params, Mapping):
        raise ReceiverAttestationError("MCP tools/call params must be an object")
    tool_name = params.get("name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ReceiverAttestationError("MCP tools/call params.name must be non-empty")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, Mapping):
        raise ReceiverAttestationError("MCP tools/call params.arguments must be an object")
    return tool_name, dict(arguments)


def _receipt_from_mcp_metadata(request: Mapping[str, Any]) -> str | None:
    params = request.get("params")
    if not isinstance(params, Mapping):
        raise ReceiverAttestationError("MCP tools/call params must be an object")
    metadata = params.get("_meta")
    if metadata is None:
        return None
    if not isinstance(metadata, Mapping):
        raise ReceiverAttestationError("MCP tools/call params._meta must be an object")
    transported = metadata.get(MCP_RECEIPT_META_KEY)
    if transported is None:
        return None
    if not isinstance(transported, str) or not transported.strip():
        raise ReceiverAttestationError(
            f"MCP request metadata {MCP_RECEIPT_META_KEY!r} must be a non-empty JWT"
        )
    return transported.strip()


def _resolve_receipt_jwt(
    request: Mapping[str, Any], explicit_receipt_jwt: str | None
) -> str:
    transported = _receipt_from_mcp_metadata(request)
    explicit = explicit_receipt_jwt.strip() if isinstance(explicit_receipt_jwt, str) else None
    if explicit_receipt_jwt is not None and not explicit:
        raise ReceiverAttestationError("explicit receipt JWT must be non-empty")
    if explicit is not None and transported is not None and explicit != transported:
        raise ReceiverAttestationError(
            "explicit receipt JWT does not match MCP request metadata"
        )
    resolved = explicit or transported
    if resolved is None:
        raise ReceiverAttestationError(
            f"receipt JWT is required explicitly or in params._meta[{MCP_RECEIPT_META_KEY!r}]"
        )
    return resolved


def _mcp_result_status(
    request: Mapping[str, Any], response: Mapping[str, Any]
) -> str:
    if response.get("jsonrpc") != "2.0":
        raise ReceiverAttestationError("MCP response jsonrpc must be '2.0'")
    response_id = response.get("id")
    request_id = request.get("id")
    if type(response_id) is not type(request_id) or response_id != request_id:
        raise ReceiverAttestationError("MCP response id does not match the request")
    has_result = "result" in response
    has_error = "error" in response
    if has_result == has_error:
        raise ReceiverAttestationError(
            "MCP response must contain exactly one of result or error"
        )
    if has_error:
        if not isinstance(response.get("error"), Mapping):
            raise ReceiverAttestationError("MCP protocol error must be an object")
        return "error"
    result = response.get("result")
    if not isinstance(result, Mapping):
        raise ReceiverAttestationError("MCP tools/call result must be an object")
    is_error = result.get("isError")
    if is_error is True:
        return "error"
    if is_error is not None and is_error is not False:
        raise ReceiverAttestationError("MCP result isError must be boolean when present")
    return "success"


def _has_attestation_metadata(response: Mapping[str, Any]) -> bool:
    result = response.get("result")
    if not isinstance(result, Mapping):
        return False
    metadata = result.get("_meta")
    return isinstance(metadata, Mapping) and MCP_ATTESTATION_META_KEY in metadata


def _unsigned_mcp_response(response: Mapping[str, Any]) -> dict[str, Any]:
    """Remove only Ardur's metadata extension before response digesting.

    The envelope cannot sign a response that already contains the envelope.
    Existing, unrelated MCP metadata remains part of the signed digest.
    """

    unsigned = deepcopy(dict(response))
    result = unsigned.get("result")
    if not isinstance(result, dict):
        return unsigned
    metadata = result.get("_meta")
    if not isinstance(metadata, dict) or MCP_ATTESTATION_META_KEY not in metadata:
        return unsigned
    metadata.pop(MCP_ATTESTATION_META_KEY)
    if not metadata:
        result.pop("_meta")
    return unsigned


def _expected_arguments_hash(arguments: Mapping[str, Any]) -> str:
    return _sha256_hex(canonical_json_bytes(dict(arguments)))


def _statement_id(claims_without_id: Mapping[str, Any]) -> str:
    return f"receiver-attestation:{_sha256_hex(canonical_json_bytes(dict(claims_without_id)))}"


def _statement_jti() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(18)).decode("ascii").rstrip("=")


def validate_receiver_envelope(envelope: Mapping[str, Any]) -> None:
    """Validate the portable envelope before any cryptographic operation."""

    try:
        Draft202012Validator(receiver_attestation_v01_schema()).validate(dict(envelope))
    except ValidationError as exc:
        raise ReceiverAttestationError(
            f"receiver-attestation schema violation: {exc.message[:500]}"
        ) from exc


def self_attested_envelope(receipt_jwt: str) -> dict[str, Any]:
    """Represent the honest absence of receiver evidence."""

    envelope = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "assurance_tier": ASSURANCE_SELF_ATTESTED,
        "receipt_subject": receipt_subject(receipt_jwt),
        "receipt_jwt": receipt_jwt.strip(),
        "receiver_attestation": None,
    }
    validate_receiver_envelope(envelope)
    return envelope


class ReceiverAttestationShim:
    """Framework-light receiver SDK for MCP ``tools/call`` handlers.

    The receiver verifies the governor receipt, checks that the tool name and
    arguments match the observed MCP request, then signs a statement after the
    handler has produced its response.
    """

    def __init__(
        self,
        *,
        receiver_private_key: ec.EllipticCurvePrivateKey,
        receipt_public_key: ec.EllipticCurvePublicKey,
        receiver_id: str,
        key_id: str,
        trusted_receipt_issuer_bindings: (
            dict[str, set[str] | list[str] | tuple[str, ...]] | None
        ) = None,
    ) -> None:
        self._receiver_private_key = _require_es256_private_key(receiver_private_key)
        self._receipt_public_key = _require_es256_public_key(
            receipt_public_key, "receipt public key"
        )
        if (
            self._receiver_private_key.public_key().public_numbers()
            == self._receipt_public_key.public_numbers()
        ):
            raise ValueError(
                "receiver and receipt issuer must use distinct signing keys"
            )
        if not isinstance(receiver_id, str) or not receiver_id.strip():
            raise ValueError("receiver_id must be non-empty")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be non-empty")
        self.receiver_id = receiver_id.strip()
        self.key_id = key_id.strip()
        self._trusted_receipt_issuer_bindings = trusted_receipt_issuer_bindings

    def cosign_mcp_call(
        self,
        *,
        receipt_jwt: str | None = None,
        request: Mapping[str, Any],
        response: Mapping[str, Any],
        observed_at: int | None = None,
        jti: str | None = None,
    ) -> dict[str, Any]:
        """Return a receiver-attested envelope for one completed MCP call."""

        if observed_at is not None and (
            isinstance(observed_at, bool) or not isinstance(observed_at, int)
        ):
            raise ReceiverAttestationError(
                "receiver observed_at must be an integer epoch second"
            )
        timestamp = int(time.time()) if observed_at is None else observed_at
        if timestamp < 0:
            raise ReceiverAttestationError("receiver observed_at must be non-negative")
        request_dict = deepcopy(dict(request))
        tool_name, arguments = _mcp_call_parts(request_dict)
        resolved_receipt_jwt = _resolve_receipt_jwt(request_dict, receipt_jwt)
        receipt_claims = verify_receipt(
            resolved_receipt_jwt,
            self._receipt_public_key,
            trusted_issuer_bindings=self._trusted_receipt_issuer_bindings,
            now_fn=lambda: timestamp,
        )
        if receipt_claims.get("verdict") != "compliant":
            raise ReceiverAttestationError(
                "receiver refuses to co-sign a non-compliant action receipt"
            )

        if _has_attestation_metadata(response):
            raise ReceiverAttestationError(
                "MCP response already contains receiver-attestation metadata"
            )
        response_dict = deepcopy(dict(response))
        result_status = _mcp_result_status(request_dict, response_dict)
        if receipt_claims.get("tool") != tool_name:
            raise ReceiverAttestationError("receipt tool does not match the MCP request")
        if receipt_claims.get("arguments_hash") != _expected_arguments_hash(arguments):
            raise ReceiverAttestationError(
                "receipt arguments_hash does not match the MCP request"
            )

        nonce = _statement_jti() if jti is None else str(jti)
        if len(nonce) < 16 or not _BASE64URL_RE.fullmatch(nonce):
            raise ReceiverAttestationError(
                "receiver attestation jti must be at least 16 base64url characters"
            )
        subject = receipt_subject(resolved_receipt_jwt)
        statement_without_id = {
            "schema_version": STATEMENT_SCHEMA_VERSION,
            "canonicalization": "jcs-rfc8785",
            "receipt_subject": subject,
            "receipt_id": receipt_claims["receipt_id"],
            "action_id": receipt_claims["receipt_id"],
            "step_id": receipt_claims["step_id"],
            "invocation_digest": dict(receipt_claims["invocation_digest"]),
            "authority_summary": _authority_summary(receipt_claims),
            "request_digest": _digest_object("mcp_tools_call", request_dict),
            "response_digest": _digest_object("mcp_tools_call_result", response_dict),
            "result_status": result_status,
            "receiver_id": self.receiver_id,
            "observed_at": _observed_at(timestamp),
            "iat": timestamp,
            "jti": nonce,
        }
        statement = {
            **statement_without_id,
            "attestation_id": _statement_id(statement_without_id),
        }
        token = jwt.encode(
            statement,
            self._receiver_private_key,
            algorithm=ALGORITHM,
            headers={"typ": ATTESTATION_JWT_TYPE, "kid": self.key_id},
            json_encoder=RFC8785JSONEncoder,
        )
        envelope = {
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "assurance_tier": ASSURANCE_RECEIVER_ATTESTED,
            "receipt_subject": subject,
            "receipt_jwt": resolved_receipt_jwt,
            "receiver_attestation": {
                "format": ATTESTATION_JWT_TYPE,
                "receiver_id": self.receiver_id,
                "key_id": self.key_id,
                "statement_jws": token,
            },
        }
        validate_receiver_envelope(envelope)
        return envelope

    def attach_to_mcp_response(
        self,
        *,
        receipt_jwt: str | None = None,
        request: Mapping[str, Any],
        response: Mapping[str, Any],
        observed_at: int | None = None,
        jti: str | None = None,
    ) -> dict[str, Any]:
        """Attach the co-signature envelope under namespaced MCP result metadata."""

        if _has_attestation_metadata(response):
            raise ReceiverAttestationError(
                "MCP response already contains receiver-attestation metadata"
            )
        unsigned_response = deepcopy(dict(response))
        envelope = self.cosign_mcp_call(
            receipt_jwt=receipt_jwt,
            request=request,
            response=unsigned_response,
            observed_at=observed_at,
            jti=jti,
        )
        attested = deepcopy(unsigned_response)
        result = attested.get("result")
        if not isinstance(result, dict):
            raise ReceiverAttestationError(
                "MCP protocol errors cannot carry result receiver-attestation metadata"
            )
        metadata = result.setdefault("_meta", {})
        if not isinstance(metadata, dict):
            raise ReceiverAttestationError("MCP result _meta must be an object")
        if MCP_ATTESTATION_META_KEY in metadata:
            raise ReceiverAttestationError(
                "MCP response already contains receiver-attestation metadata"
            )
        metadata[MCP_ATTESTATION_META_KEY] = envelope
        return attested


def _validate_digest(value: Any, *, scope: str, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "alg",
        "canonicalization",
        "scope",
        "value",
    }:
        raise ReceiverAttestationVerificationError(f"{label} is malformed")
    if value.get("alg") != "sha-256":
        raise ReceiverAttestationVerificationError(f"{label} algorithm must be sha-256")
    if value.get("canonicalization") != "jcs-rfc8785":
        raise ReceiverAttestationVerificationError(
            f"{label} canonicalization must be jcs-rfc8785"
        )
    if value.get("scope") != scope:
        raise ReceiverAttestationVerificationError(f"{label} scope is invalid")
    digest = value.get("value")
    if (
        not isinstance(digest, str)
        or len(digest) != _SHA256_B64URL_LENGTH
        or not _BASE64URL_RE.fullmatch(digest)
    ):
        raise ReceiverAttestationVerificationError(f"{label} value is invalid")


def _validate_canonical_statement(token: str, claims: Mapping[str, Any]) -> None:
    try:
        encoded_payload = token.split(".")[1]
        padding = "=" * (-len(encoded_payload) % 4)
        payload = base64.urlsafe_b64decode(encoded_payload + padding)
        expected = canonical_json_bytes(dict(claims))
    except (IndexError, TypeError, ValueError) as exc:
        raise ReceiverAttestationVerificationError(
            f"receiver statement canonical payload could not be evaluated: {exc}"
        ) from exc
    if payload != expected:
        raise ReceiverAttestationVerificationError(
            "receiver statement JWS payload is not RFC 8785 canonical JSON"
        )


def _validate_statement_shape(claims: Mapping[str, Any]) -> None:
    if set(claims) != _STATEMENT_FIELDS:
        raise ReceiverAttestationVerificationError(
            "receiver statement has missing or unknown claims"
        )
    if claims.get("schema_version") != STATEMENT_SCHEMA_VERSION:
        raise ReceiverAttestationVerificationError(
            "receiver statement schema_version is unsupported"
        )
    if claims.get("canonicalization") != "jcs-rfc8785":
        raise ReceiverAttestationVerificationError(
            "receiver statement canonicalization is unsupported"
        )
    for field in (
        "attestation_id",
        "receipt_id",
        "action_id",
        "step_id",
        "receiver_id",
        "observed_at",
        "jti",
    ):
        if not isinstance(claims.get(field), str) or not claims[field]:
            raise ReceiverAttestationVerificationError(
                f"receiver statement {field} must be non-empty"
            )
    attestation_id = claims["attestation_id"]
    if not _ATTESTATION_ID_RE.fullmatch(attestation_id):
        raise ReceiverAttestationVerificationError(
            "receiver statement attestation_id is invalid"
        )
    jti = claims["jti"]
    if len(jti) < 16 or len(jti) > 256 or not _BASE64URL_RE.fullmatch(jti):
        raise ReceiverAttestationVerificationError(
            "receiver statement jti must be 16-256 base64url characters"
        )
    if not isinstance(claims.get("iat"), int) or isinstance(claims.get("iat"), bool):
        raise ReceiverAttestationVerificationError("receiver statement iat must be an integer")
    if claims.get("result_status") not in {"success", "error"}:
        raise ReceiverAttestationVerificationError(
            "receiver statement result_status is invalid"
        )
    _validate_digest(
        claims.get("request_digest"), scope="mcp_tools_call", label="request_digest"
    )
    _validate_digest(
        claims.get("response_digest"),
        scope="mcp_tools_call_result",
        label="response_digest",
    )
    subject = claims.get("receipt_subject")
    if not isinstance(subject, dict):
        raise ReceiverAttestationVerificationError("receipt_subject is malformed")
    digest = subject.get("digest")
    if (
        set(subject) != {"media_type", "digest"}
        or subject.get("media_type") != RECEIPT_JWT_TYPE
        or not isinstance(digest, dict)
        or set(digest) != {"algorithm", "value"}
        or digest.get("algorithm") != "sha256"
        or not isinstance(digest.get("value"), str)
        or not _SHA256_HEX_RE.fullmatch(digest["value"])
    ):
        raise ReceiverAttestationVerificationError("receipt_subject is malformed")


def _verify_statement_bindings(
    claims: Mapping[str, Any],
    *,
    envelope: Mapping[str, Any],
    receipt_claims: Mapping[str, Any],
    expected_request: Mapping[str, Any] | None,
    expected_response: Mapping[str, Any] | None,
    max_attestation_delay_s: int,
    receiver_clock_skew_s: int,
) -> tuple[bool, bool]:
    attestation = envelope["receiver_attestation"]
    if claims.get("receiver_id") != attestation.get("receiver_id"):
        raise ReceiverAttestationVerificationError(
            "receiver statement identity does not match the envelope"
        )
    expected_subject = envelope["receipt_subject"]
    if claims.get("receipt_subject") != expected_subject:
        raise ReceiverAttestationVerificationError(
            "receiver statement does not bind the exact receipt JWT"
        )
    for claim_field, receipt_field in (
        ("receipt_id", "receipt_id"),
        ("action_id", "receipt_id"),
        ("step_id", "step_id"),
        ("invocation_digest", "invocation_digest"),
    ):
        if claims.get(claim_field) != receipt_claims.get(receipt_field):
            raise ReceiverAttestationVerificationError(
                f"receiver statement {claim_field} does not match the receipt"
            )
    if claims.get("authority_summary") != _authority_summary(receipt_claims):
        raise ReceiverAttestationVerificationError(
            "receiver authority summary does not match the receipt"
        )

    statement_without_id = dict(claims)
    attestation_id = statement_without_id.pop("attestation_id")
    if attestation_id != _statement_id(statement_without_id):
        raise ReceiverAttestationVerificationError(
            "receiver attestation_id does not match the signed statement"
        )
    receiver_iat = int(claims["iat"])
    receipt_iat = receipt_claims.get("iat")
    receipt_exp = receipt_claims.get("exp")
    if not isinstance(receipt_iat, int) or not isinstance(receipt_exp, int):
        raise ReceiverAttestationVerificationError("receipt time claims are malformed")
    delay = receiver_iat - receipt_iat
    if delay < -receiver_clock_skew_s or delay > max_attestation_delay_s:
        raise ReceiverAttestationVerificationError(
            "receiver statement falls outside the receipt attestation window"
        )
    if receiver_iat > receipt_exp + receiver_clock_skew_s:
        raise ReceiverAttestationVerificationError(
            "receiver statement was issued after the receipt validity window"
        )
    if claims.get("observed_at") != _observed_at(receiver_iat):
        raise ReceiverAttestationVerificationError(
            "receiver observed_at does not match its numeric iat"
        )

    request_checked = expected_request is not None
    response_checked = expected_response is not None
    if expected_request is not None:
        request_dict = deepcopy(dict(expected_request))
        tool_name, arguments = _mcp_call_parts(request_dict)
        if receipt_claims.get("tool") != tool_name:
            raise ReceiverAttestationVerificationError(
                "expected MCP request tool does not match the receipt"
            )
        if receipt_claims.get("arguments_hash") != _expected_arguments_hash(arguments):
            raise ReceiverAttestationVerificationError(
                "expected MCP request arguments do not match the receipt"
            )
        if claims.get("request_digest") != _digest_object("mcp_tools_call", request_dict):
            raise ReceiverAttestationVerificationError(
                "expected MCP request does not match the receiver-signed digest"
            )
    if expected_response is not None:
        response_dict = _unsigned_mcp_response(expected_response)
        if expected_request is None:
            raise ReceiverAttestationVerificationError(
                "expected MCP response verification also requires the request"
            )
        expected_status = _mcp_result_status(dict(expected_request), response_dict)
        if claims.get("result_status") != expected_status:
            raise ReceiverAttestationVerificationError(
                "expected MCP response status does not match the receiver statement"
            )
        if claims.get("response_digest") != _digest_object(
            "mcp_tools_call_result", response_dict
        ):
            raise ReceiverAttestationVerificationError(
                "expected MCP response does not match the receiver-signed digest"
            )
    return request_checked, response_checked


def verify_receiver_envelope(
    envelope: Mapping[str, Any],
    *,
    receipt_public_key: ec.EllipticCurvePublicKey,
    receiver_public_key: ec.EllipticCurvePublicKey | None = None,
    expected_request: Mapping[str, Any] | None = None,
    expected_response: Mapping[str, Any] | None = None,
    max_attestation_delay_s: int = DEFAULT_MAX_ATTESTATION_DELAY_S,
    receiver_clock_skew_s: int = DEFAULT_RECEIVER_CLOCK_SKEW_S,
    trusted_receipt_issuer_bindings: (
        dict[str, set[str] | list[str] | tuple[str, ...]] | None
    ) = None,
) -> dict[str, Any]:
    """Verify the action and optional receiver signatures independently."""

    for label, value in (
        ("maximum attestation delay", max_attestation_delay_s),
        ("receiver clock skew", receiver_clock_skew_s),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ReceiverAttestationVerificationError(
                f"{label} must be a non-negative integer"
            )
    validate_receiver_envelope(envelope)
    receipt_key = _require_es256_public_key(receipt_public_key, "receipt public key")
    receipt_jwt = str(envelope["receipt_jwt"])
    expected_subject = receipt_subject(receipt_jwt)
    if envelope.get("receipt_subject") != expected_subject:
        raise ReceiverAttestationVerificationError(
            "envelope receipt_subject does not match the exact receipt JWT"
        )
    try:
        receipt_claims = verify_receipt(
            receipt_jwt,
            receipt_key,
            trusted_issuer_bindings=trusted_receipt_issuer_bindings,
            verify_expiry=False,
            iat_future_skew_s=None,
            iat_past_skew_s=None,
        )
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        raise ReceiverAttestationVerificationError(
            f"action receipt signature or schema verification failed: {exc}"
        ) from exc

    assurance = envelope["assurance_tier"]
    if assurance == ASSURANCE_SELF_ATTESTED:
        if expected_request is not None or expected_response is not None:
            raise ReceiverAttestationVerificationError(
                "self-attested envelopes have no receiver-signed request or response digest"
            )
        return {
            "valid": True,
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "assurance_tier": ASSURANCE_SELF_ATTESTED,
            "receipt": {
                "signature_valid": True,
                "receipt_id": receipt_claims["receipt_id"],
                "evidence_level": receipt_claims["evidence_level"],
            },
            "receiver_attestation": {
                "present": False,
                "signature_valid": False,
                "request_binding_checked": False,
                "response_binding_checked": False,
            },
        }

    attestation = envelope.get("receiver_attestation")
    if not isinstance(attestation, dict):
        raise ReceiverAttestationVerificationError(
            "receiver-attested envelope is missing its receiver signature"
        )
    if receiver_public_key is None:
        raise ReceiverAttestationVerificationError(
            "receiver public key is required for receiver-attested verification"
        )
    receiver_key = _require_es256_public_key(receiver_public_key, "receiver public key")
    if receiver_key.public_numbers() == receipt_key.public_numbers():
        raise ReceiverAttestationVerificationError(
            "receiver and receipt issuer must use distinct signing keys"
        )
    token = attestation["statement_jws"]
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise ReceiverAttestationVerificationError(
            f"receiver statement header is malformed: {exc}"
        ) from exc
    if set(header) != {"alg", "kid", "typ"}:
        raise ReceiverAttestationVerificationError(
            "receiver statement JWS header has missing or unknown fields"
        )
    if header.get("typ") != ATTESTATION_JWT_TYPE:
        raise ReceiverAttestationVerificationError(
            "receiver statement JWS typ is invalid"
        )
    if header.get("alg") != ALGORITHM:
        raise ReceiverAttestationVerificationError(
            "receiver statement JWS algorithm is invalid"
        )
    if header.get("kid") != attestation.get("key_id"):
        raise ReceiverAttestationVerificationError(
            "receiver statement key id does not match the envelope"
        )
    try:
        statement = jwt.decode(
            token,
            receiver_key,
            algorithms=[ALGORITHM],
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise ReceiverAttestationVerificationError(
            f"receiver statement signature verification failed: {exc}"
        ) from exc
    _validate_canonical_statement(token, statement)
    _validate_statement_shape(statement)
    request_checked, response_checked = _verify_statement_bindings(
        statement,
        envelope=envelope,
        receipt_claims=receipt_claims,
        expected_request=expected_request,
        expected_response=expected_response,
        max_attestation_delay_s=max_attestation_delay_s,
        receiver_clock_skew_s=receiver_clock_skew_s,
    )
    return {
        "valid": True,
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "assurance_tier": ASSURANCE_RECEIVER_ATTESTED,
        "receipt": {
            "signature_valid": True,
            "receipt_id": receipt_claims["receipt_id"],
            "evidence_level": receipt_claims["evidence_level"],
        },
        "receiver_attestation": {
            "present": True,
            "signature_valid": True,
            "attestation_id": statement["attestation_id"],
            "receiver_id": statement["receiver_id"],
            "key_id": attestation["key_id"],
            "observed_at": statement["observed_at"],
            "result_status": statement["result_status"],
            "request_binding_checked": request_checked,
            "response_binding_checked": response_checked,
        },
    }


def load_receiver_envelope(path: str | Path) -> dict[str, Any]:
    """Load a bounded, non-symlink receiver-attestation envelope."""

    envelope_path = Path(path).expanduser()
    if envelope_path.is_symlink():
        raise ReceiverAttestationError(
            "receiver-attestation envelope path must not be a symlink"
        )
    try:
        with envelope_path.open("rb") as handle:
            raw = handle.read(MAX_ENVELOPE_BYTES + 1)
        if not raw or len(raw) > MAX_ENVELOPE_BYTES:
            raise ReceiverAttestationError(
                "receiver-attestation envelope is empty or exceeds the size limit"
            )
        payload = json.loads(raw.decode("utf-8"))
    except ReceiverAttestationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiverAttestationError(
            f"receiver-attestation envelope could not be read ({type(exc).__name__})"
        ) from exc
    if not isinstance(payload, dict):
        raise ReceiverAttestationError(
            "receiver-attestation envelope must be a JSON object"
        )
    validate_receiver_envelope(payload)
    return payload


def load_json_document(path: str | Path, *, label: str) -> dict[str, Any]:
    """Load a bounded JSON object used for optional content-binding checks."""

    document_path = Path(path).expanduser()
    if document_path.is_symlink():
        raise ReceiverAttestationError(f"{label} path must not be a symlink")
    try:
        with document_path.open("rb") as handle:
            raw = handle.read(MAX_JSON_DOCUMENT_BYTES + 1)
        if not raw or len(raw) > MAX_JSON_DOCUMENT_BYTES:
            raise ReceiverAttestationError(f"{label} is empty or exceeds the size limit")
        payload = json.loads(raw.decode("utf-8"))
    except ReceiverAttestationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiverAttestationError(
            f"{label} could not be read ({type(exc).__name__})"
        ) from exc
    if not isinstance(payload, dict):
        raise ReceiverAttestationError(f"{label} must be a JSON object")
    return payload

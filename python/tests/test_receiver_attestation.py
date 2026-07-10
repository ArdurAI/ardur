from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from jsonschema import Draft202012Validator

from vibap.canonical_json import RFC8785JSONEncoder, canonical_json_bytes
from vibap.cli import main as cli_main
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import build_receipt, sign_receipt
from vibap.receiver_attestation import (
    ASSURANCE_RECEIVER_ATTESTED,
    ASSURANCE_SELF_ATTESTED,
    ATTESTATION_JWT_TYPE,
    MCP_ATTESTATION_META_KEY,
    MCP_RECEIPT_META_KEY,
    ReceiverAttestationError,
    ReceiverAttestationShim,
    ReceiverAttestationVerificationError,
    self_attested_envelope,
    verify_receiver_envelope,
)
from vibap.receiver_attestation_fixture import (
    ReceiverAttestationFixtureOutputError,
    run_receiver_attestation_fixture,
)


NOW = 1_800_000_000
FIXED_JTI = "receiverattestationfixture01"


def _fixture() -> dict[str, object]:
    receipt_private = ec.generate_private_key(ec.SECP256R1())
    receiver_private = ec.generate_private_key(ec.SECP256R1())
    arguments = {"path": "workspace/customer-notes.md", "limit": 3}
    timestamp = datetime.fromtimestamp(NOW, timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    event = PolicyEvent(
        timestamp=timestamp,
        step_id="step:receiver-fixture",
        actor="spiffe://example.test/agent/reviewer",
        verifier_id="spiffe://example.test/ardur/verifier",
        tool_name="read_file",
        arguments=arguments,
        action_class="read",
        target="workspace/customer-notes.md",
        resource_family="filesystem",
        side_effect_class="none",
        decision=Decision.PERMIT,
        reason="fixture permit",
        passport_jti="passport:receiver-fixture",
        trace_id="trace:receiver-fixture",
        run_nonce="receiver_fixture_nonce_0123456789",
    )
    receipt = build_receipt(Decision.PERMIT, event)
    receipt.iat = NOW
    receipt.exp = NOW + 300
    receipt_jwt = sign_receipt(receipt, receipt_private)
    request = {
        "jsonrpc": "2.0",
        "id": "call-17",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": arguments,
            "_meta": {MCP_RECEIPT_META_KEY: receipt_jwt},
        },
    }
    response = {
        "jsonrpc": "2.0",
        "id": "call-17",
        "result": {
            "content": [{"type": "text", "text": "fixture result"}],
            "structuredContent": {"count": 1},
            "isError": False,
            "_meta": {"example.test/source": "local-fixture"},
        },
    }
    shim = ReceiverAttestationShim(
        receiver_private_key=receiver_private,
        receipt_public_key=receipt_private.public_key(),
        receiver_id="spiffe://example.test/tool/read-file",
        key_id="read-file-receiver:v1",
    )
    envelope = shim.cosign_mcp_call(
        receipt_jwt=receipt_jwt,
        request=request,
        response=response,
        observed_at=NOW + 5,
        jti=FIXED_JTI,
    )
    return {
        "receipt_private": receipt_private,
        "receiver_private": receiver_private,
        "receipt_jwt": receipt_jwt,
        "request": request,
        "response": response,
        "shim": shim,
        "envelope": envelope,
    }


def _resign_statement(
    envelope: dict[str, object],
    receiver_private: ec.EllipticCurvePrivateKey,
    update: Callable[[dict[str, object]], object],
    *,
    refresh_attestation_id: bool = False,
) -> dict[str, object]:
    changed = copy.deepcopy(envelope)
    receiver = changed["receiver_attestation"]
    assert isinstance(receiver, dict)
    claims = jwt.decode(receiver["statement_jws"], options={"verify_signature": False})
    update(claims)
    if refresh_attestation_id:
        statement_without_id = dict(claims)
        statement_without_id.pop("attestation_id")
        digest = hashlib.sha256(canonical_json_bytes(statement_without_id)).hexdigest()
        claims["attestation_id"] = f"receiver-attestation:{digest}"
    receiver["statement_jws"] = jwt.encode(
        claims,
        receiver_private,
        algorithm="ES256",
        headers={"typ": ATTESTATION_JWT_TYPE, "kid": receiver["key_id"]},
        json_encoder=RFC8785JSONEncoder,
    )
    return changed


def test_receiver_attested_envelope_verifies_both_signatures_and_content_offline() -> None:
    fixture = _fixture()
    receipt_key = fixture["receipt_private"]
    receiver_key = fixture["receiver_private"]
    assert isinstance(receipt_key, ec.EllipticCurvePrivateKey)
    assert isinstance(receiver_key, ec.EllipticCurvePrivateKey)

    report = verify_receiver_envelope(
        fixture["envelope"],
        receipt_public_key=receipt_key.public_key(),
        receiver_public_key=receiver_key.public_key(),
        expected_request=fixture["request"],
        expected_response=fixture["response"],
    )

    assert report["valid"] is True
    assert report["assurance_tier"] == ASSURANCE_RECEIVER_ATTESTED
    assert report["receipt"]["signature_valid"] is True
    assert report["receipt"]["evidence_level"] == "self_signed"
    assert report["receiver_attestation"]["signature_valid"] is True
    assert report["receiver_attestation"]["request_binding_checked"] is True
    assert report["receiver_attestation"]["response_binding_checked"] is True


def test_self_attested_envelope_is_explicit_and_never_implies_receiver_evidence() -> None:
    fixture = _fixture()
    receipt_key = fixture["receipt_private"]
    assert isinstance(receipt_key, ec.EllipticCurvePrivateKey)
    envelope = self_attested_envelope(str(fixture["receipt_jwt"]))

    report = verify_receiver_envelope(
        envelope,
        receipt_public_key=receipt_key.public_key(),
    )

    assert report["assurance_tier"] == ASSURANCE_SELF_ATTESTED
    assert report["receipt"]["signature_valid"] is True
    assert report["receiver_attestation"] == {
        "present": False,
        "signature_valid": False,
        "request_binding_checked": False,
        "response_binding_checked": False,
    }


def test_claimed_receiver_tier_without_signature_fails_schema_validation() -> None:
    fixture = _fixture()
    dishonest = self_attested_envelope(str(fixture["receipt_jwt"]))
    dishonest["assurance_tier"] = ASSURANCE_RECEIVER_ATTESTED

    with pytest.raises(ReceiverAttestationError, match="schema violation"):
        verify_receiver_envelope(
            dishonest,
            receipt_public_key=fixture["receipt_private"].public_key(),
        )


def test_receiver_signature_is_independently_required() -> None:
    fixture = _fixture()
    unrelated_key = ec.generate_private_key(ec.SECP256R1()).public_key()

    with pytest.raises(
        ReceiverAttestationVerificationError, match="signature verification failed"
    ):
        verify_receiver_envelope(
            fixture["envelope"],
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=unrelated_key,
        )


def test_receiver_and_governor_keys_must_be_cryptographically_distinct() -> None:
    fixture = _fixture()
    receipt_private = fixture["receipt_private"]
    assert isinstance(receipt_private, ec.EllipticCurvePrivateKey)

    with pytest.raises(ValueError, match="distinct signing keys"):
        ReceiverAttestationShim(
            receiver_private_key=receipt_private,
            receipt_public_key=receipt_private.public_key(),
            receiver_id="spiffe://example.test/tool/read-file",
            key_id="reused-key:v1",
        )

    with pytest.raises(
        ReceiverAttestationVerificationError, match="distinct signing keys"
    ):
        verify_receiver_envelope(
            fixture["envelope"],
            receipt_public_key=receipt_private.public_key(),
            receiver_public_key=receipt_private.public_key(),
        )


def test_exact_receipt_subject_prevents_valid_signature_splicing() -> None:
    first = _fixture()
    second = _fixture()
    spliced = copy.deepcopy(first["envelope"])
    spliced["receipt_jwt"] = second["receipt_jwt"]

    with pytest.raises(
        ReceiverAttestationVerificationError, match="exact receipt JWT"
    ):
        verify_receiver_envelope(
            spliced,
            receipt_public_key=first["receipt_private"].public_key(),
            receiver_public_key=first["receiver_private"].public_key(),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("action_id", "receipt:other-action", "action_id does not match"),
        ("step_id", "step:other", "step_id does not match"),
        ("receiver_id", "spiffe://example.test/tool/other", "identity does not match"),
    ],
)
def test_signed_cross_bindings_cannot_be_substituted(
    field: str, value: str, message: str
) -> None:
    fixture = _fixture()
    tampered = _resign_statement(
        fixture["envelope"],
        fixture["receiver_private"],
        lambda claims: claims.__setitem__(field, value),
    )

    with pytest.raises(ReceiverAttestationVerificationError, match=message):
        verify_receiver_envelope(
            tampered,
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
        )


def test_request_and_response_digest_mismatches_fail_when_artifacts_are_supplied() -> None:
    fixture = _fixture()
    wrong_request = copy.deepcopy(fixture["request"])
    wrong_request["params"]["arguments"]["limit"] = 99
    with pytest.raises(
        ReceiverAttestationVerificationError, match="arguments do not match"
    ):
        verify_receiver_envelope(
            fixture["envelope"],
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
            expected_request=wrong_request,
        )

    wrong_response = copy.deepcopy(fixture["response"])
    wrong_response["result"]["structuredContent"]["count"] = 2
    with pytest.raises(
        ReceiverAttestationVerificationError, match="receiver-signed digest"
    ):
        verify_receiver_envelope(
            fixture["envelope"],
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
            expected_request=fixture["request"],
            expected_response=wrong_response,
        )


def test_receiver_refuses_to_notarize_a_mismatched_call() -> None:
    fixture = _fixture()
    wrong_request = copy.deepcopy(fixture["request"])
    wrong_request["params"]["name"] = "write_file"

    with pytest.raises(ReceiverAttestationError, match="receipt tool"):
        fixture["shim"].cosign_mcp_call(
            receipt_jwt=fixture["receipt_jwt"],
            request=wrong_request,
            response=fixture["response"],
            observed_at=NOW + 5,
            jti=FIXED_JTI,
        )


def test_receiver_rejects_existing_attestation_metadata_and_invalid_error_shape() -> None:
    fixture = _fixture()
    pre_attested = copy.deepcopy(fixture["response"])
    pre_attested["result"]["_meta"][MCP_ATTESTATION_META_KEY] = {"forged": True}
    with pytest.raises(ReceiverAttestationError, match="already contains"):
        fixture["shim"].attach_to_mcp_response(
            receipt_jwt=fixture["receipt_jwt"],
            request=fixture["request"],
            response=pre_attested,
            observed_at=NOW + 5,
            jti=FIXED_JTI,
        )

    invalid_error = copy.deepcopy(fixture["response"])
    invalid_error["result"]["isError"] = []
    with pytest.raises(ReceiverAttestationError, match="isError must be boolean"):
        fixture["shim"].cosign_mcp_call(
            receipt_jwt=fixture["receipt_jwt"],
            request=fixture["request"],
            response=invalid_error,
            observed_at=NOW + 5,
            jti=FIXED_JTI,
        )


def test_json_rpc_response_id_type_must_match_exactly() -> None:
    fixture = _fixture()
    numeric_request = copy.deepcopy(fixture["request"])
    numeric_request["id"] = 1
    float_response = copy.deepcopy(fixture["response"])
    float_response["id"] = 1.0

    with pytest.raises(ReceiverAttestationError, match="response id"):
        fixture["shim"].cosign_mcp_call(
            receipt_jwt=fixture["receipt_jwt"],
            request=numeric_request,
            response=float_response,
            observed_at=NOW + 5,
            jti=FIXED_JTI,
        )


def test_receiver_time_is_bounded_to_the_receipt_window() -> None:
    fixture = _fixture()
    changed = _resign_statement(
        fixture["envelope"],
        fixture["receiver_private"],
        lambda claims: (
            claims.__setitem__("iat", NOW + 301),
            claims.__setitem__(
                "observed_at",
                datetime.fromtimestamp(NOW + 301, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            ),
        ),
        refresh_attestation_id=True,
    )

    with pytest.raises(ReceiverAttestationVerificationError, match="attestation window"):
        verify_receiver_envelope(
            changed,
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
        )


@pytest.mark.parametrize("observed_at", [True, 1.5, "1800000000"])
def test_receiver_rejects_coerced_timestamp_inputs(observed_at: object) -> None:
    fixture = _fixture()

    with pytest.raises(ReceiverAttestationError, match="integer epoch second"):
        fixture["shim"].cosign_mcp_call(
            receipt_jwt=fixture["receipt_jwt"],
            request=fixture["request"],
            response=fixture["response"],
            observed_at=observed_at,
            jti=FIXED_JTI,
        )


def test_attestation_id_is_bound_to_the_complete_statement() -> None:
    fixture = _fixture()
    changed = _resign_statement(
        fixture["envelope"],
        fixture["receiver_private"],
        lambda claims: claims["authority_summary"].__setitem__(
            "target", "workspace/other.md"
        ),
    )

    with pytest.raises(ReceiverAttestationVerificationError, match="authority summary"):
        verify_receiver_envelope(
            changed,
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
        )


def test_signed_digest_and_jti_shapes_fail_even_without_raw_artifacts() -> None:
    fixture = _fixture()
    bad_digest = _resign_statement(
        fixture["envelope"],
        fixture["receiver_private"],
        lambda claims: claims["request_digest"].__setitem__("value", "short"),
        refresh_attestation_id=True,
    )
    with pytest.raises(ReceiverAttestationVerificationError, match="value is invalid"):
        verify_receiver_envelope(
            bad_digest,
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
        )

    bad_jti = _resign_statement(
        fixture["envelope"],
        fixture["receiver_private"],
        lambda claims: claims.__setitem__("jti", "short"),
        refresh_attestation_id=True,
    )
    with pytest.raises(ReceiverAttestationVerificationError, match="jti must"):
        verify_receiver_envelope(
            bad_jti,
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
        )


@pytest.mark.parametrize("value", [True, 1.5, -1])
def test_verifier_rejects_non_integer_attestation_policy(value: object) -> None:
    fixture = _fixture()

    with pytest.raises(ReceiverAttestationVerificationError, match="non-negative integer"):
        verify_receiver_envelope(
            fixture["envelope"],
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
            max_attestation_delay_s=value,
        )


def test_mcp_shim_attaches_namespaced_metadata_without_digest_recursion() -> None:
    fixture = _fixture()
    attached = fixture["shim"].attach_to_mcp_response(
        receipt_jwt=fixture["receipt_jwt"],
        request=fixture["request"],
        response=fixture["response"],
        observed_at=NOW + 5,
        jti=FIXED_JTI,
    )
    envelope = attached["result"]["_meta"][MCP_ATTESTATION_META_KEY]

    report = verify_receiver_envelope(
        envelope,
        receipt_public_key=fixture["receipt_private"].public_key(),
        receiver_public_key=fixture["receiver_private"].public_key(),
        expected_request=fixture["request"],
        expected_response=attached,
    )

    assert attached["result"]["_meta"]["example.test/source"] == "local-fixture"
    assert report["receiver_attestation"]["response_binding_checked"] is True


def test_mcp_shim_extracts_receipt_metadata_and_rejects_transport_substitution() -> None:
    fixture = _fixture()
    attached = fixture["shim"].attach_to_mcp_response(
        request=fixture["request"],
        response=fixture["response"],
        observed_at=NOW + 5,
        jti=FIXED_JTI,
    )
    envelope = attached["result"]["_meta"][MCP_ATTESTATION_META_KEY]
    assert envelope["receipt_jwt"] == fixture["receipt_jwt"]

    with pytest.raises(ReceiverAttestationError, match="does not match MCP request"):
        fixture["shim"].attach_to_mcp_response(
            receipt_jwt="header.payload.signature",
            request=fixture["request"],
            response=fixture["response"],
            observed_at=NOW + 5,
            jti=FIXED_JTI,
        )


def test_schema_is_strict_and_embedded_copy_matches() -> None:
    root = Path(__file__).resolve().parents[2]
    canonical_path = root / "docs/specs/receiver-attestation-v0.1.schema.json"
    embedded_path = root / "python/vibap/_specs/receiver_attestation_v01.schema.json"
    canonical = json.loads(canonical_path.read_text(encoding="utf-8"))
    embedded = json.loads(embedded_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(canonical)
    assert canonical == embedded


def test_public_golden_fixture_verifies_with_separate_committed_keys() -> None:
    root = Path(__file__).resolve().parents[2]
    fixture_dir = root / "docs/specs/fixtures"
    envelope = json.loads(
        (fixture_dir / "receiver-attestation-v0.1.json").read_text(
            encoding="utf-8"
        )
    )
    receipt_public_key = serialization.load_pem_public_key(
        (fixture_dir / "receiver-attestation-v0.1-receipt-public.pem").read_bytes()
    )
    receiver_public_key = serialization.load_pem_public_key(
        (fixture_dir / "receiver-attestation-v0.1-receiver-public.pem").read_bytes()
    )
    assert isinstance(receipt_public_key, ec.EllipticCurvePublicKey)
    assert isinstance(receiver_public_key, ec.EllipticCurvePublicKey)
    assert receipt_public_key.public_numbers() != receiver_public_key.public_numbers()

    report = verify_receiver_envelope(
        envelope,
        receipt_public_key=receipt_public_key,
        receiver_public_key=receiver_public_key,
    )

    assert report["valid"] is True
    assert report["assurance_tier"] == ASSURANCE_RECEIVER_ATTESTED
    assert report["receipt"]["signature_valid"] is True
    assert report["receiver_attestation"]["signature_valid"] is True
    assert report["receiver_attestation"]["request_binding_checked"] is False
    assert report["receiver_attestation"]["response_binding_checked"] is False


def test_noncanonical_but_validly_signed_statement_fails() -> None:
    fixture = _fixture()
    changed = copy.deepcopy(fixture["envelope"])
    attestation = changed["receiver_attestation"]
    claims = jwt.decode(attestation["statement_jws"], options={"verify_signature": False})
    header = {"alg": "ES256", "kid": attestation["key_id"], "typ": ATTESTATION_JWT_TYPE}
    header_segment = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii").rstrip("=")
    payload_segment = base64.urlsafe_b64encode(
        json.dumps(claims, indent=1, sort_keys=False).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = fixture["receiver_private"].sign(signing_input, ec.ECDSA(hashes.SHA256()))
    # JWS ES256 uses raw R||S, while cryptography returns ASN.1 DER.
    r, s = decode_dss_signature(signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    signature_segment = base64.urlsafe_b64encode(raw_signature).decode("ascii").rstrip("=")
    attestation["statement_jws"] = (
        f"{header_segment}.{payload_segment}.{signature_segment}"
    )

    with pytest.raises(ReceiverAttestationVerificationError, match="not RFC 8785 canonical"):
        verify_receiver_envelope(
            changed,
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
        )


def test_receiver_statement_rejects_unknown_protected_headers() -> None:
    fixture = _fixture()
    changed = copy.deepcopy(fixture["envelope"])
    attestation = changed["receiver_attestation"]
    claims = jwt.decode(attestation["statement_jws"], options={"verify_signature": False})
    attestation["statement_jws"] = jwt.encode(
        claims,
        fixture["receiver_private"],
        algorithm="ES256",
        headers={
            "typ": ATTESTATION_JWT_TYPE,
            "kid": attestation["key_id"],
            "x5u": "https://attacker.invalid/receiver.pem",
        },
        json_encoder=RFC8785JSONEncoder,
    )

    with pytest.raises(ReceiverAttestationVerificationError, match="unknown fields"):
        verify_receiver_envelope(
            changed,
            receipt_public_key=fixture["receipt_private"].public_key(),
            receiver_public_key=fixture["receiver_private"].public_key(),
        )


def _write_cli_fixture(tmp_path: Path, fixture: dict[str, object]) -> dict[str, Path]:
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    receipt_key = fixture["receipt_private"]
    receiver_key = fixture["receiver_private"]
    assert isinstance(receipt_key, ec.EllipticCurvePrivateKey)
    assert isinstance(receiver_key, ec.EllipticCurvePrivateKey)
    (keys_dir / "passport_public.pem").write_bytes(
        receipt_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    receiver_public = tmp_path / "receiver-public.pem"
    receiver_public.write_bytes(
        receiver_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    envelope = tmp_path / "receiver-attestation.json"
    envelope.write_text(
        json.dumps(fixture["envelope"], sort_keys=True), encoding="utf-8"
    )
    request = tmp_path / "mcp-request.json"
    request.write_text(json.dumps(fixture["request"], sort_keys=True), encoding="utf-8")
    response = tmp_path / "mcp-response.json"
    response.write_text(json.dumps(fixture["response"], sort_keys=True), encoding="utf-8")
    return {
        "keys_dir": keys_dir,
        "receiver_public": receiver_public,
        "envelope": envelope,
        "request": request,
        "response": response,
    }


def test_cli_verifies_receiver_attestation_and_exact_mcp_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture()
    paths = _write_cli_fixture(tmp_path, fixture)

    code = cli_main(
        [
            "verify",
            "--receiver-envelope",
            str(paths["envelope"]),
            "--keys-dir",
            str(paths["keys_dir"]),
            "--receiver-public-key",
            str(paths["receiver_public"]),
            "--mcp-request",
            str(paths["request"]),
            "--mcp-response",
            str(paths["response"]),
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["valid"] is True
    assert report["assurance_tier"] == ASSURANCE_RECEIVER_ATTESTED
    assert report["receipt"]["signature_valid"] is True
    assert report["receiver_attestation"]["signature_valid"] is True
    assert report["receiver_attestation"]["request_binding_checked"] is True
    assert report["receiver_attestation"]["response_binding_checked"] is True


def test_cli_fails_closed_when_receiver_key_is_omitted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture()
    paths = _write_cli_fixture(tmp_path, fixture)

    code = cli_main(
        [
            "verify",
            "--receiver-envelope",
            str(paths["envelope"]),
            "--keys-dir",
            str(paths["keys_dir"]),
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["valid"] is False
    assert report["error"] == "receiver_attestation_verification_failed"
    assert "receiver public key is required" in report["message"]


def test_cli_self_attested_mode_needs_no_receiver_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture()
    fixture["envelope"] = self_attested_envelope(str(fixture["receipt_jwt"]))
    paths = _write_cli_fixture(tmp_path, fixture)

    code = cli_main(
        [
            "verify",
            "--receiver-envelope",
            str(paths["envelope"]),
            "--keys-dir",
            str(paths["keys_dir"]),
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["assurance_tier"] == ASSURANCE_SELF_ATTESTED
    assert report["receiver_attestation"]["present"] is False


def test_cli_requires_request_when_response_binding_is_requested(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture()
    paths = _write_cli_fixture(tmp_path, fixture)

    code = cli_main(
        [
            "verify",
            "--receiver-envelope",
            str(paths["envelope"]),
            "--keys-dir",
            str(paths["keys_dir"]),
            "--receiver-public-key",
            str(paths["receiver_public"]),
            "--mcp-response",
            str(paths["response"]),
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["error"] == "receiver_attestation_request_required"


def test_reference_mcp_fixture_persists_public_evidence_only(tmp_path: Path) -> None:
    report = run_receiver_attestation_fixture(tmp_path, now=NOW)

    assert report["ok"] is True
    assert report["private_keys_persisted"] is False
    assert report["verification"]["receipt"]["signature_valid"] is True
    assert report["verification"]["receiver_attestation"]["signature_valid"] is True
    assert report["verification"]["receiver_attestation"]["request_binding_checked"] is True
    assert report["verification"]["receiver_attestation"]["response_binding_checked"] is True
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(report["artifacts"])
    assert not list(tmp_path.glob("*private*"))
    assert all(path.stat().st_mode & 0o077 == 0 for path in tmp_path.iterdir())


def test_reference_mcp_fixture_is_exposed_through_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "fixture"

    code = cli_main(["receiver-attestation-fixture", "--output", str(output)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["ok"] is True
    assert (output / "receiver-attestation.json").is_file()
    assert (output / "receipt-public.pem").is_file()
    assert (output / "receiver-public.pem").is_file()


# --- --output validation (existing-file / empty / whitespace) ---


def test_fixture_output_existing_regular_file_is_structured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    existing_file = tmp_path / "existing-file.txt"
    existing_file.write_text("not a directory", encoding="utf-8")

    code = cli_main(
        ["receiver-attestation-fixture", "--output", str(existing_file)]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "receiver_attestation_fixture_output_not_directory"
    assert report["condition"] == "receiver_attestation_fixture_output_not_directory"
    assert "[Errno" not in captured.out
    assert "[Errno" not in report.get("message", "")
    assert str(existing_file) not in captured.out
    assert str(existing_file) not in json.dumps(report)
    assert report["next_steps"]
    assert all("<" in step["command"] and ">" in step["command"] for step in report["next_steps"])


def test_fixture_output_empty_string_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    code = cli_main(["receiver-attestation-fixture", "--output", ""])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "receiver_attestation_fixture_output_empty"
    assert report["condition"] == "receiver_attestation_fixture_output_empty"
    assert report["next_steps"]
    assert not any(tmp_path.iterdir()), "no fixtures written to CWD on empty --output"


def test_fixture_output_whitespace_only_is_structured(
    tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    code = cli_main(["receiver-attestation-fixture", "--output", "   "])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 1
    assert captured.err == ""
    assert report["ok"] is False
    assert report["error"] == "receiver_attestation_fixture_output_empty"
    assert report["condition"] == "receiver_attestation_fixture_output_empty"
    assert report["next_steps"]
    assert not any(p.name.strip() == "" for p in tmp_path.iterdir()), (
        "no whitespace-named directory created on whitespace-only --output"
    )
    assert not any(tmp_path.iterdir()), "no fixtures written on whitespace-only --output"


def test_fixture_output_validation_raises_specialized_error(tmp_path: Path) -> None:
    existing_file = tmp_path / "blocking-file"
    existing_file.write_text("x", encoding="utf-8")

    with pytest.raises(ReceiverAttestationFixtureOutputError) as exc_info:
        run_receiver_attestation_fixture(existing_file)

    assert exc_info.value.condition == "receiver_attestation_fixture_output_not_directory"
    assert str(existing_file) not in exc_info.value.detail

    with pytest.raises(ReceiverAttestationFixtureOutputError) as empty_info:
        run_receiver_attestation_fixture("")
    assert empty_info.value.condition == "receiver_attestation_fixture_output_empty"


def test_fixture_output_valid_new_dir_behavior_preserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    new_dir = tmp_path / "fresh-output-dir"

    code = cli_main(["receiver-attestation-fixture", "--output", str(new_dir)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["ok"] is True
    assert (new_dir / "receiver-attestation.json").is_file()
    assert (new_dir / "receipt-public.pem").is_file()


def test_fixture_output_existing_empty_dir_behavior_preserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    existing_dir = tmp_path / "existing-dir"
    existing_dir.mkdir()

    code = cli_main(["receiver-attestation-fixture", "--output", str(existing_dir)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert report["ok"] is True
    assert (existing_dir / "receiver-attestation.json").is_file()

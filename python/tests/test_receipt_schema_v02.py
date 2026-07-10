"""Execution Receipt v0.2 versioning and canonicalization tests."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import jwt
import jsonschema
import pytest

from vibap.canonical_json import RFC8785JSONEncoder, canonical_json_bytes
from vibap._vendor import rfc8785 as vendored_rfc8785
from vibap.passport import ALGORITHM
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import (
    RECEIPT_CANONICALIZATION,
    RECEIPT_KIND_ACTION,
    RECEIPT_SCHEMA_VERSION,
    build_receipt,
    sign_receipt,
    verify_chain,
    verify_receipt,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def _event(step_id: str = "step-v02") -> PolicyEvent:
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return PolicyEvent(
        timestamp=timestamp,
        step_id=step_id,
        actor="spiffe://example.test/agent",
        verifier_id="vibap-governance-proxy",
        tool_name="read_file",
        arguments={"path": "README.md", "limit": 1.0},
        action_class="read",
        target="README.md",
        resource_family="file",
        side_effect_class="none",
        decision=Decision.PERMIT,
        reason="within scope",
        passport_jti="grant-v02",
        trace_id="trace-v02",
        run_nonce="fixture-run-nonce-0001",
    )


def _payload_bytes(token: str) -> bytes:
    encoded = token.split(".")[1]
    return base64.urlsafe_b64decode(encoded + ("=" * (-len(encoded) % 4)))


def test_v02_receipt_is_self_identifying_and_payload_is_jcs(private_key, public_key) -> None:
    receipt = build_receipt(Decision.PERMIT, _event())
    token = sign_receipt(receipt, private_key)
    claims = verify_receipt(token, public_key)

    assert claims["schema_version"] == RECEIPT_SCHEMA_VERSION
    assert claims["canonicalization"] == RECEIPT_CANONICALIZATION
    assert claims["receipt_kind"] == RECEIPT_KIND_ACTION
    assert _payload_bytes(token) == canonical_json_bytes(claims)


def test_v02_verifier_rejects_valid_signature_over_noncanonical_payload(
    private_key, public_key
) -> None:
    claims = build_receipt(Decision.PERMIT, _event()).to_dict()
    token = jwt.encode(
        claims,
        private_key,
        algorithm=ALGORITHM,
        headers={"typ": "application/ardur.er+jwt"},
    )

    assert _payload_bytes(token) != canonical_json_bytes(claims)
    with pytest.raises(jwt.InvalidTokenError, match="not RFC 8785 canonical"):
        verify_receipt(token, public_key)


def test_unknown_receipt_schema_version_fails_closed(private_key, public_key) -> None:
    claims = build_receipt(Decision.PERMIT, _event()).to_dict()
    claims["schema_version"] = "ardur.execution_receipt.v99"
    token = jwt.encode(
        claims,
        private_key,
        algorithm=ALGORITHM,
        json_encoder=RFC8785JSONEncoder,
    )

    with pytest.raises(jwt.InvalidTokenError, match="unsupported schema_version"):
        verify_receipt(token, public_key)


def test_unversioned_legacy_receipt_chain_still_verifies(private_key, public_key) -> None:
    def sign_legacy(receipt) -> str:
        claims = receipt.to_dict()
        for field in ("schema_version", "canonicalization", "receipt_kind"):
            claims.pop(field)
        return jwt.encode(
            claims,
            private_key,
            algorithm=ALGORITHM,
            headers={"typ": "application/ardur.er+jwt"},
        )

    first_token = sign_legacy(build_receipt(Decision.PERMIT, _event("legacy-1")))
    parent_hash = hashlib.sha256(first_token.encode("ascii")).hexdigest()
    second_token = sign_legacy(
        build_receipt(
            Decision.PERMIT,
            _event("legacy-2"),
            parent_receipt_hash=parent_hash,
        )
    )

    verified = verify_chain([first_token, second_token], public_key)

    assert [claims["step_id"] for claims in verified] == ["legacy-1", "legacy-2"]
    assert all("schema_version" not in claims for claims in verified)


def test_rfc8785_number_serialization_differs_from_sorted_stdlib_json() -> None:
    assert canonical_json_bytes({"minus_zero": -0.0, "small": 1e-7}) == (
        b'{"minus_zero":0,"small":1e-7}'
    )


def test_vendored_rfc8785_fallback_matches_installed_implementation() -> None:
    value = {"astral": "\U0001f600", "minus_zero": -0.0, "small": 1e-7}

    assert vendored_rfc8785.dumps(value) == canonical_json_bytes(value)


def test_canonical_json_selects_vendor_when_distribution_is_unavailable() -> None:
    script = """
import builtins

original_import = builtins.__import__

def import_without_rfc8785(name, *args, **kwargs):
    if name == "rfc8785":
        raise ModuleNotFoundError("blocked for fallback test", name=name)
    return original_import(name, *args, **kwargs)

builtins.__import__ = import_without_rfc8785
from vibap.canonical_json import canonical_json_bytes
print(canonical_json_bytes({"minus_zero": -0.0, "small": 1e-7}).decode("utf-8"))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT / "python",
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == '{"minus_zero":0,"small":1e-7}'


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_rfc8785_rejects_non_json_numbers(value: float) -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": value})


def test_v02_golden_fixture_schema_digest_and_embedded_copy_are_in_sync() -> None:
    canonical_schema_path = REPO_ROOT / "docs/specs/execution-receipt-v0.2.schema.json"
    embedded_schema_path = (
        REPO_ROOT / "python/vibap/_specs/execution_receipt_v02.schema.json"
    )
    fixture_path = (
        REPO_ROOT / "docs/specs/fixtures/execution-receipt-v0.2-action.json"
    )
    digest_path = fixture_path.with_suffix(".jcs.sha256")

    canonical_schema = json.loads(canonical_schema_path.read_text(encoding="utf-8"))
    embedded_schema = json.loads(embedded_schema_path.read_text(encoding="utf-8"))
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected_digest = digest_path.read_text(encoding="ascii").strip()

    assert embedded_schema == canonical_schema
    jsonschema.Draft202012Validator(
        canonical_schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(fixture)
    assert hashlib.sha256(canonical_json_bytes(fixture)).hexdigest() == expected_digest

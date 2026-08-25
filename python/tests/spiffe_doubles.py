"""Deterministic SPIFFE test doubles. Test-only — never shipped.

These helpers used to live in ``vibap/spiffe_identity.py``, which *is* part
of the distributed package (``pyproject.toml`` ships ``vibap*`` and nothing
else). That made them importable by anyone who ran ``pip install ardur``.

They must not be. Every key they produce is derived from a SHA-256 over a
constant label and the caller's SPIFFE ID, so the private half of the mock
trust anchor is computable by anyone holding this source. Anything that
wires ``make_mock_trust_bundle`` into a real configuration installs a trust
root whose signing key is public knowledge, and the SVIDs it validates
would then be forgeable by anyone. Nothing in ``vibap/`` ever called them,
so this was a latent hazard rather than an exploited one — moving them out
of the shipped package is what keeps it that way.

``python/tests/`` is not packaged, so this module is reachable from the test
suite and from nowhere else. ``python/tests/test_no_test_doubles_shipped.py``
enforces the boundary structurally.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any

import jwt
import spiffe
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from vibap.spiffe_identity import SvidBundle, TrustBundle

_MOCK_JWT_AUDIENCE = "vibap://spiffe-mock"
_MOCK_IAT = 1_700_000_000
_MOCK_EXP = 2_524_608_000
_MOCK_CERT_NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
_MOCK_CERT_NOT_AFTER = datetime(2034, 1, 1, tzinfo=timezone.utc)
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


def make_mock_svid_bundle(
    spiffe_id: str = "spiffe://example.org/workload-test",
    *,
    iat: int | None = None,
    exp: int | None = None,
) -> SvidBundle:
    """Build a deterministic mock X.509-SVID/JWT-SVID bundle for tests.

    Round-5 (FIX-R5-H7, 2026-04-28): the original ``_MOCK_IAT`` constant
    sat at 2023-11 — fine for tests that never call
    :func:`verify_jwt_svid` against the bundle, but unusable once the
    bounded-iat-skew gate (FIX-R4-4) defaults to ±30 days past. New
    callers can pass ``iat=int(time.time())`` to mint a fresh token
    that survives the gate; the legacy ``_MOCK_IAT`` default is kept
    for back-compat with tests that don't exercise the verifier path.
    """

    effective_iat = _MOCK_IAT if iat is None else iat
    effective_exp = _MOCK_EXP if exp is None else exp
    materials = _mock_materials(spiffe_id)
    jwt_svid_token = jwt.encode(
        {
            "sub": spiffe_id,
            "aud": [_MOCK_JWT_AUDIENCE],
            "iat": effective_iat,
            "exp": effective_exp,
        },
        materials["jwt_private_key"],
        algorithm="ES256",
        headers={
            "kid": materials["jwt_jwk"]["kid"],
            "typ": "JWT",
        },
    )

    return SvidBundle(
        spiffe_id=spiffe_id,
        x509_svid_pem=materials["leaf_cert"].public_bytes(serialization.Encoding.PEM),
        private_key_pem=materials["leaf_private_key"].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        trust_chain_pem=materials["ca_cert"].public_bytes(serialization.Encoding.PEM),
        jwt_svid_token=jwt_svid_token,
    )


def make_mock_trust_bundle(
    spiffe_id: str = "spiffe://example.org/workload-test",
) -> TrustBundle:
    """Build a deterministic trust bundle that matches `make_mock_svid_bundle`."""

    parsed_spiffe_id = spiffe.SpiffeId(spiffe_id)
    materials = _mock_materials(spiffe_id)
    return TrustBundle(
        trust_domain=parsed_spiffe_id.trust_domain.name,
        jwks={"keys": [materials["jwt_jwk"], materials["biscuit_jwk"]]},
        federated_bundles={},
    )


def _mock_materials(spiffe_id: str) -> dict[str, Any]:
    parsed_spiffe_id = spiffe.SpiffeId(spiffe_id)
    trust_domain = parsed_spiffe_id.trust_domain.name
    # spiffe-python 3.x removed SpiffeId.path; derive the path segment
    # from the raw URI. The SPIFFE URI shape is
    # ``spiffe://<trust-domain>/<path>`` — strip the ``spiffe://<td>``
    # prefix to recover the trailing path. Gracefully falls back to the
    # full SPIFFE ID string when there's no path segment, matching the
    # original ``parsed.path or spiffe_id`` semantic.
    _td_prefix = f"spiffe://{trust_domain}"
    _spiffe_path_segment = (
        spiffe_id[len(_td_prefix):] if spiffe_id.startswith(_td_prefix) else ""
    )

    leaf_private_key = _deterministic_private_key("mock-leaf", spiffe_id)
    ca_private_key = _deterministic_private_key("mock-ca", trust_domain)
    jwt_private_key = _deterministic_p256_private_key("mock-jwt", trust_domain)

    ca_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"{trust_domain} mock trust anchor")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_private_key.public_key())
        .serial_number(_deterministic_serial("mock-ca-cert", trust_domain))
        .not_valid_before(_MOCK_CERT_NOT_BEFORE)
        .not_valid_after(_MOCK_CERT_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_private_key, algorithm=None)
    )

    leaf_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, _spiffe_path_segment or spiffe_id)]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(ca_subject)
        .public_key(leaf_private_key.public_key())
        .serial_number(_deterministic_serial("mock-leaf-cert", spiffe_id))
        .not_valid_before(_MOCK_CERT_NOT_BEFORE)
        .not_valid_after(_MOCK_CERT_NOT_AFTER)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_private_key, algorithm=None)
    )

    biscuit_jwk = _public_key_to_jwk(
        leaf_private_key.public_key(),
        spiffe_id,
        purpose="biscuit-root",
    )
    jwt_jwk = _public_key_to_jwk(
        jwt_private_key.public_key(),
        spiffe_id,
        purpose="jwt-authority",
    )
    return {
        "leaf_private_key": leaf_private_key,
        "leaf_cert": leaf_cert,
        "ca_cert": ca_cert,
        "jwt_private_key": jwt_private_key,
        "biscuit_jwk": biscuit_jwk,
        "jwt_jwk": jwt_jwk,
    }


def _deterministic_private_key(label: str, material: str) -> ed25519.Ed25519PrivateKey:
    seed = hashlib.sha256(f"{label}\0{material}".encode("utf-8")).digest()
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _deterministic_p256_private_key(
    label: str,
    material: str,
) -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(
        hashlib.sha256(f"{label}\0{material}".encode("utf-8")).digest(),
        "big",
    )
    scalar = (scalar % (_P256_ORDER - 1)) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def _deterministic_serial(label: str, material: str) -> int:
    digest = hashlib.sha256(f"{label}\0{material}".encode("utf-8")).digest()
    serial = int.from_bytes(digest[:20], "big") >> 1
    return max(serial, 1)


def _public_key_to_jwk(
    public_key: ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey,
    spiffe_id: str,
    purpose: str,
) -> dict[str, str]:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        raw_public_key = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        key_id = _b64url(hashlib.sha256(raw_public_key).digest()[:12])
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(raw_public_key),
            "kid": key_id,
            "alg": "EdDSA",
            "use": "sig",
            "spiffe_id": spiffe_id,
            "purpose": purpose,
        }

    numbers = public_key.public_numbers()
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")
    key_material = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    key_id = _b64url(hashlib.sha256(key_material).digest()[:12])
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(x_bytes),
        "y": _b64url(y_bytes),
        "kid": key_id,
        "alg": "ES256",
        "use": "jwt-svid" if purpose == "jwt-authority" else "sig",
        "spiffe_id": spiffe_id,
        "purpose": purpose,
    }


def _b64url(data: bytes) -> str:
    return jwt.utils.base64url_encode(data).decode("ascii")

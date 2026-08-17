"""SPIFFE workload-identity integration — Layer 1 of ADR-014."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Optional

import jwt
import spiffe
from biscuit_auth import PrivateKey, PublicKey
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

_MOCK_JWT_AUDIENCE = "vibap://spiffe-mock"
_MOCK_IAT = 1_700_000_000
_MOCK_EXP = 2_524_608_000
_MOCK_CERT_NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
_MOCK_CERT_NOT_AFTER = datetime(2034, 1, 1, tzinfo=timezone.utc)
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


@dataclass(slots=True)
class SvidBundle:
    """Holds both X.509-SVID and JWT-SVID for a workload."""

    spiffe_id: str
    x509_svid_pem: bytes
    private_key_pem: bytes
    trust_chain_pem: bytes
    jwt_svid_token: Optional[str] = None


@dataclass(slots=True)
class SvidClaims:
    """Verified claims from a JWT-SVID."""

    spiffe_id: str
    audience: list[str]
    iat: int
    exp: int


@dataclass(slots=True)
class TrustBundle:
    """SPIFFE trust bundle — maps trust domain to JWKS keys."""

    trust_domain: str
    jwks: dict
    federated_bundles: dict[str, dict]


def fetch_svid(
    socket_path: str = "unix:///tmp/spire-agent/public/api.sock",
) -> SvidBundle:
    """Fetch workload identity material from a real SPIFFE Workload API socket.

    This path is only smoke-tested when a live SPIRE agent socket is present.
    The installed `spiffe==0.2.6` Workload API requires an audience when it
    mints a JWT-SVID, but this contract does not accept one, so the function
    requests a self-audience JWT-SVID (`aud == <spiffe_id>`) on a best-effort
    basis and leaves `jwt_svid_token` unset if that fetch fails.
    """

    # Verified against `vibap-prototype/.venv` before calling the real API:
    #   dir(spiffe) == ['JwtBundle', 'JwtBundleSet', 'JwtSource', 'JwtSvid', 'SpiffeId', 'TrustDomain', 'WorkloadApiClient', 'X509Bundle', 'X509BundleSet', 'X509Source', 'X509Svid', 'bundle', 'config', 'errors', 'spiffe_id', 'svid', 'utils', 'workloadapi']
    #   inspect.signature(spiffe.WorkloadApiClient) == (socket_path: Optional[str] = None) -> None
    #   inspect.signature(spiffe.WorkloadApiClient.fetch_x509_svid) == (self) -> 'X509Svid'
    #   inspect.signature(spiffe.WorkloadApiClient.fetch_x509_bundles) == (self) -> 'X509BundleSet'
    #   inspect.signature(spiffe.WorkloadApiClient.fetch_jwt_svid) == (self, audience: 'Set[str]', subject: 'Optional[SpiffeId]' = None) -> 'JwtSvid'
    with spiffe.WorkloadApiClient(socket_path=socket_path) as client:
        x509_svid = client.fetch_x509_svid()
        x509_bundles = client.fetch_x509_bundles()

        jwt_svid_token: str | None = None
        try:
            jwt_svid = client.fetch_jwt_svid({str(x509_svid.spiffe_id)})
            jwt_svid_token = jwt_svid.token
        except (spiffe.utils.errors.PySpiffeError, OSError, ValueError):
            # Best-effort JWT-SVID fetch. The caller who needs a JWT-SVID
            # should request it explicitly via fetch_jwt_svid(audience=...).
            # Tightened from bare Exception per Phase 2 auggie review
            # finding #1; catches the PySpiffeError hierarchy, socket/
            # network errors, and library validation errors.
            jwt_svid_token = None

    trust_bundle = x509_bundles.get_bundle_for_trust_domain(
        x509_svid.spiffe_id.trust_domain
    )
    trust_chain_pem = _x509_bundle_to_pem(trust_bundle)
    if not trust_chain_pem:
        trust_chain_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM)
            for cert in x509_svid.cert_chain[1:]
        )

    return SvidBundle(
        spiffe_id=str(x509_svid.spiffe_id),
        x509_svid_pem=x509_svid.leaf.public_bytes(serialization.Encoding.PEM),
        private_key_pem=x509_svid.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        trust_chain_pem=trust_chain_pem,
        jwt_svid_token=jwt_svid_token,
    )


def verify_jwt_svid(
    token: str,
    trust_bundle: TrustBundle,
    audience: str,
) -> SvidClaims:
    """Verify a JWT-SVID against a local or federated trust bundle."""

    if not token:
        raise ValueError("JWT-SVID token cannot be empty")
    if not audience:
        raise ValueError("JWT-SVID audience cannot be empty")

    # Verified against `vibap-prototype/.venv` before calling validation APIs:
    #   dir(spiffe) == ['JwtBundle', 'JwtBundleSet', 'JwtSource', 'JwtSvid', 'SpiffeId', 'TrustDomain', 'WorkloadApiClient', 'X509Bundle', 'X509BundleSet', 'X509Source', 'X509Svid', 'bundle', 'config', 'errors', 'spiffe_id', 'svid', 'utils', 'workloadapi']
    #   inspect.signature(spiffe.JwtSvid.parse_insecure) == (token: str, audience: Set[str]) -> 'JwtSvid'
    #   inspect.signature(spiffe.JwtSvid.parse_and_validate) == (token: str, jwt_bundle: spiffe.bundle.jwt_bundle.jwt_bundle.JwtBundle, audience: Set[str]) -> 'JwtSvid'
    #   inspect.signature(spiffe.JwtBundle.parse) == (trust_domain: spiffe.spiffe_id.spiffe_id.TrustDomain, bundle_bytes: bytes) -> 'JwtBundle'
    try:
        insecure_svid = spiffe.JwtSvid.parse_insecure(token, {audience})
    except Exception as exc:
        raise ValueError(f"JWT-SVID audience/shape validation failed: {exc}") from exc

    spiffe_id = str(insecure_svid.spiffe_id)
    jwks = _jwt_svid_jwks(_jwks_for_spiffe_id(trust_bundle, spiffe_id))

    try:
        bundle_bytes = json.dumps(jwks, sort_keys=True).encode("utf-8")
        jwt_bundle = spiffe.JwtBundle.parse(spiffe.TrustDomain(spiffe_id), bundle_bytes)
        validated_svid = spiffe.JwtSvid.parse_and_validate(
            token, jwt_bundle, {audience}
        )
    except Exception as exc:
        raise ValueError(f"JWT-SVID validation failed: {exc}") from exc

    claims = getattr(validated_svid, "_claims", None)
    if not isinstance(claims, dict):
        raise ValueError("JWT-SVID validation did not expose verified claims")
    raw_audience = claims.get("aud", list(validated_svid.audience))
    audience_list = (
        [raw_audience] if isinstance(raw_audience, str) else list(raw_audience)
    )
    iat = claims.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise ValueError("JWT-SVID iat claim must be an integer")
    exp = validated_svid.expiry
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise ValueError("JWT-SVID exp claim must be an integer")
    # Round-4 hardening (FIX-R4-4, 2026-04-28): the JWT-SVID spec is
    # silent on iat-future bounds, and the underlying SPIFFE library
    # cannot be relied on to enforce them. Apply the same bounded-iat
    # gate every other JWT verifier in this codebase uses, so a
    # briefly-compromised SPIFFE signer cannot mint long-lived
    # future-dated SVIDs that bind to Biscuit holder identities forever.
    # Local import avoids a circular dep at module load time.
    from .passport import assert_iat_in_window
    try:
        assert_iat_in_window(iat, field_name="JWT-SVID iat")
    except Exception as exc:  # noqa: BLE001 - re-raise as ValueError for caller contract
        raise ValueError(str(exc)) from exc

    return SvidClaims(
        spiffe_id=str(validated_svid.spiffe_id),
        audience=audience_list,
        iat=iat,
        exp=exp,
    )


def load_trust_bundle(path: str) -> TrustBundle:
    """Load a JSON-serialized trust bundle from disk."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return TrustBundle(
        trust_domain=str(payload["trust_domain"]),
        jwks=dict(payload["jwks"]),
        federated_bundles={
            str(domain): dict(jwks)
            for domain, jwks in dict(payload.get("federated_bundles", {})).items()
        },
    )


def save_trust_bundle(bundle: TrustBundle, path: str) -> None:
    """Persist a trust bundle as stable JSON."""

    payload = {
        "trust_domain": bundle.trust_domain,
        "jwks": bundle.jwks,
        "federated_bundles": bundle.federated_bundles,
    }
    Path(path).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def derive_biscuit_root_key_from_svid_pem(private_key_pem: bytes) -> PrivateKey:
    """Convert an Ed25519 PKCS#8 PEM key into the Biscuit root-key type."""

    loaded_private_key = serialization.load_pem_private_key(
        private_key_pem, password=None
    )
    if not isinstance(loaded_private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("SPIFFE SVID private key must be Ed25519")
    return PrivateKey.from_pem(private_key_pem.decode("ascii"))


def get_public_key_from_trust_bundle(
    trust_bundle: TrustBundle,
    spiffe_id: str,
) -> PublicKey:
    """Resolve the Biscuit-compatible public key for a SPIFFE ID."""

    jwks = _jwks_for_spiffe_id(trust_bundle, spiffe_id)
    jwk = _select_jwk(jwks, spiffe_id)
    public_key = jwt.PyJWK.from_dict(jwk).key
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return PublicKey.from_pem(pem.decode("ascii"))


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


def _jwks_for_spiffe_id(trust_bundle: TrustBundle, spiffe_id: str) -> dict:
    parsed_spiffe_id = spiffe.SpiffeId(spiffe_id)
    trust_domain = parsed_spiffe_id.trust_domain.name
    if trust_domain == trust_bundle.trust_domain:
        return trust_bundle.jwks
    if trust_domain in trust_bundle.federated_bundles:
        return trust_bundle.federated_bundles[trust_domain]
    raise ValueError(f"No trust bundle available for trust domain '{trust_domain}'")


def _jwt_svid_jwks(jwks: dict) -> dict:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise ValueError("Trust bundle JWKS does not contain a key list")
    jwt_svid_keys = [
        dict(key)
        for key in keys
        if isinstance(key, dict) and ("use" not in key or key["use"] == "jwt-svid")
    ]
    if not jwt_svid_keys:
        raise ValueError("Trust bundle JWKS does not contain JWT-SVID signing keys")
    return {"keys": jwt_svid_keys}


def _select_jwk(jwks: dict, spiffe_id: str) -> dict:
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("Trust bundle JWKS does not contain any keys")

    exact_matches = [
        key
        for key in keys
        if isinstance(key, dict) and key.get("spiffe_id") == spiffe_id
    ]
    purpose_matches = [
        key for key in exact_matches if key.get("purpose") == "biscuit-root"
    ]
    if len(purpose_matches) == 1:
        return purpose_matches[0]
    if len(exact_matches) == 1:
        return exact_matches[0]
    if len(exact_matches) > 1:
        raise ValueError(
            f"Trust bundle contains multiple keys for SPIFFE ID '{spiffe_id}'"
        )
    if len(keys) == 1 and isinstance(keys[0], dict):
        return keys[0]
    raise ValueError(
        "Trust bundle contains multiple keys without SPIFFE-ID metadata; "
        "cannot choose a workload key safely"
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


def _x509_bundle_to_pem(bundle: Any) -> bytes:
    if bundle is None:
        return b""
    authorities = sorted(
        bundle.x509_authorities,
        key=lambda cert: cert.subject.rfc4514_string(),
    )
    return b"".join(
        cert.public_bytes(serialization.Encoding.PEM) for cert in authorities
    )

"""SPIFFE workload-identity integration — Layer 1 of ADR-014."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Optional

import jwt
import spiffe
from biscuit_auth import PrivateKey, PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

DEFAULT_SPIFFE_ENDPOINT_SOCKET = "unix:///run/spire/sockets/agent.sock"


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
    socket_path: str = DEFAULT_SPIFFE_ENDPOINT_SOCKET,
) -> SvidBundle:
    """Fetch workload identity material from a real SPIFFE Workload API socket.

    This path is only smoke-tested when a live SPIRE agent socket is present.
    The supported `spiffe>=0.2,<0.4` Workload API requires an audience when it
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


def load_trust_bundle(
    path: str,
    *,
    trust_domain: str | None = None,
) -> TrustBundle:
    """Load an Ardur-wrapped or native SPIRE JSON trust bundle from disk.

    Native Workload API and federation bundles are raw JWKS documents and do
    not carry their trust-domain name, so those inputs require the explicit
    ``trust_domain`` argument. The legacy Ardur wrapper remains supported and
    rejects a conflicting explicit trust domain.
    """

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("SPIFFE trust bundle must be a JSON object")

    wrapped = "trust_domain" in payload or "jwks" in payload
    if wrapped:
        if "trust_domain" not in payload or "jwks" not in payload:
            raise ValueError(
                "Wrapped SPIFFE trust bundle requires trust_domain and jwks"
            )
        embedded_domain = str(payload["trust_domain"]).strip()
        if trust_domain is not None and trust_domain.strip() != embedded_domain:
            raise ValueError("Configured trust domain conflicts with trust bundle")
        selected_domain = embedded_domain
        jwks = payload["jwks"]
        federated = payload.get("federated_bundles", {})
    else:
        if trust_domain is None or not trust_domain.strip():
            raise ValueError("Raw SPIRE trust bundle requires a trust domain")
        selected_domain = trust_domain.strip()
        jwks = payload
        federated = {}

    if not selected_domain:
        raise ValueError("SPIFFE trust domain cannot be empty")
    if not isinstance(jwks, dict):
        raise ValueError("SPIFFE trust bundle JWKS must be an object")
    if not isinstance(federated, dict):
        raise ValueError("SPIFFE federated bundles must be an object")
    return TrustBundle(
        trust_domain=selected_domain,
        jwks=dict(jwks),
        federated_bundles={
            str(domain): dict(domain_jwks)
            for domain, domain_jwks in federated.items()
        },
    )


def load_biscuit_public_key(path: str) -> PublicKey:
    """Load a PEM-encoded Biscuit issuer public key from disk."""

    return PublicKey.from_pem(Path(path).read_text(encoding="ascii"))


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

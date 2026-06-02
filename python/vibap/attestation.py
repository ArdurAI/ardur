"""Behavioral attestation helpers for governed VIBAP sessions."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from .passport import ALGORITHM


def compute_log_digest(events: list[dict[str, Any]]) -> str:
    canonical = json.dumps(events, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


ATTESTATION_TTL_S = 90 * 24 * 3600  # 90 days; archive separately for long-term retention


def issue_attestation(
    passport_jti: str,
    agent_id: str,
    mission: str,
    events: list[dict[str, Any]],
    permits: int,
    denials: int,
    elapsed_s: float,
    private_key: ec.EllipticCurvePrivateKey,
    issuer: str = "vibap-governance-proxy",
    ttl_s: int = ATTESTATION_TTL_S,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": agent_id,
        "aud": "vibap-attestation-verifier",
        "iat": now,
        "exp": now + ttl_s,
        "jti": str(uuid.uuid4()),
        "type": "behavioral_attestation",
        "passport_jti": passport_jti,
        "mission": mission,
        "total_events": len(events),
        "permits": permits,
        "denials": denials,
        "elapsed_s": round(elapsed_s, 3),
        "scope_compliance": "full" if denials == 0 else "violated",
        "log_digest_sha256": compute_log_digest(events),
    }
    if extra_claims:
        collisions = sorted(set(claims) & set(extra_claims))
        if collisions:
            raise ValueError(
                f"extra attestation claims cannot override reserved claims: {collisions}"
            )
        claims.update(extra_claims)
    return jwt.encode(claims, private_key, algorithm=ALGORITHM)


def verify_attestation(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
) -> dict[str, Any]:
    """Verify a Phase-3.3 attestation JWT and return its claims.

    Round-4 hardening (FIX-R4-3, 2026-04-28): the attestation verifier
    now applies the same bounded-iat-skew gate every other JWT loader
    runs, defending against a briefly-compromised attestation issuer
    minting tokens with iat far in the future. Defaults to ±300s future
    / 30 days past — same envelope as the rest of the JWT surface.
    """
    # Local import keeps attestation.py free of a cyclic dep on passport
    # at module load time.
    from .passport import assert_iat_in_window

    claims = jwt.decode(
        token,
        public_key,
        algorithms=[ALGORITHM],
        audience="vibap-attestation-verifier",
        options={
            "require": ["iss", "sub", "aud", "iat", "exp", "jti", "passport_jti"],
            # Use the explicit window helper below; PyJWT's default check
            # uses zero leeway and clashes with cross-node clock drift.
            "verify_iat": False,
        },
    )
    assert_iat_in_window(claims.get("iat"), field_name="attestation iat")
    return claims

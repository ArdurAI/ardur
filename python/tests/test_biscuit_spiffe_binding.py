"""Adversarial tests for server-owned Biscuit JWT-SVID binding."""

from __future__ import annotations

import time
from pathlib import Path

import jwt
import pytest
from biscuit_auth import Algorithm, KeyPair, PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.biscuit_passport import BiscuitVerifyError, issue_biscuit_passport
from vibap.passport import MissionPassport
from vibap.proxy import GovernanceProxy
from vibap.spiffe_identity import make_mock_svid_bundle, make_mock_trust_bundle


_HOLDER_SPIFFE_ID = "spiffe://ardur.dev/agent/pinned-holder"
_SVID_AUDIENCE = "vibap://spiffe-mock"


def _rogue_jwt_svid(spiffe_id: str) -> str:
    private_key = ec.generate_private_key(ec.SECP256R1())
    now = int(time.time())
    return jwt.encode(
        {
            "sub": spiffe_id,
            "aud": [_SVID_AUDIENCE],
            "iat": now,
            "exp": now + 600,
        },
        private_key,
        algorithm="ES256",
        headers={
            "kid": "attacker-controlled-key",
            "typ": "JWT",
        },
    )


def _biscuit_material(
    holder_spiffe_id: str = _HOLDER_SPIFFE_ID,
) -> tuple[bytes, object]:
    keypair = KeyPair()
    private_bytes = bytes(keypair.private_key.to_bytes())
    mission = MissionPassport(
        agent_id="pinned-holder-agent",
        mission="verify server-owned SPIFFE trust",
        allowed_tools=["read_file"],
        forbidden_tools=[],
        resource_scope=["/data/*"],
        max_tool_calls=2,
        max_duration_s=600,
        holder_spiffe_id=holder_spiffe_id,
    )
    token = issue_biscuit_passport(
        mission,
        PrivateKey.from_bytes(private_bytes, Algorithm.Ed25519),
        "spiffe://ardur.dev/issuer",
        ttl_s=600,
    )
    return token, keypair.public_key


def _proxy(
    tmp_path: Path,
    public_key,
    session_keys_dir: Path,
    biscuit_issuer_public_key,
    trust_bundle=None,
) -> GovernanceProxy:
    return GovernanceProxy(
        log_path=tmp_path / "governance_log.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
        biscuit_issuer_public_key=biscuit_issuer_public_key,
        biscuit_peer_trust_bundle=trust_bundle
        or make_mock_trust_bundle(_HOLDER_SPIFFE_ID),
        biscuit_svid_audience=_SVID_AUDIENCE,
    )


def test_matching_spiffe_id_signed_by_untrusted_key_is_rejected(
    tmp_path: Path,
    public_key,
    session_keys_dir: Path,
) -> None:
    biscuit_token, issuer_public_key = _biscuit_material()
    proxy = _proxy(tmp_path, public_key, session_keys_dir, issuer_public_key)

    with pytest.raises(
        PermissionError, match="JWT-SVID verification failed"
    ) as raised:
        proxy.start_session_from_biscuit(
            biscuit_token,
            issuer_public_key,
            peer_jwt_svid=_rogue_jwt_svid(_HOLDER_SPIFFE_ID),
        )

    assert "JWT-SVID validation failed" in str(raised.value)
    assert "audience/shape" not in str(raised.value)

    assert proxy.sessions == {}


def test_server_pinned_bundle_accepts_matching_jwt_svid(
    tmp_path: Path,
    public_key,
    session_keys_dir: Path,
) -> None:
    biscuit_token, issuer_public_key = _biscuit_material()
    proxy = _proxy(tmp_path, public_key, session_keys_dir, issuer_public_key)
    peer_svid = make_mock_svid_bundle(_HOLDER_SPIFFE_ID, iat=int(time.time()))

    session = proxy.start_session_from_biscuit(
        biscuit_token,
        issuer_public_key,
        peer_jwt_svid=peer_svid.jwt_svid_token,
    )

    assert session.passport_claims["holder_spiffe_id"] == _HOLDER_SPIFFE_ID
    assert session.passport_claims["svid_bound"] is True


def test_server_pinned_biscuit_issuer_rejects_presenter_key(
    tmp_path: Path,
    public_key,
    session_keys_dir: Path,
) -> None:
    _trusted_token, trusted_issuer_public_key = _biscuit_material()
    attacker_token, attacker_public_key = _biscuit_material()
    proxy = _proxy(
        tmp_path,
        public_key,
        session_keys_dir,
        trusted_issuer_public_key,
    )
    peer_svid = make_mock_svid_bundle(_HOLDER_SPIFFE_ID, iat=int(time.time()))

    with pytest.raises(BiscuitVerifyError, match="invalid signature/format"):
        proxy.start_session_from_biscuit(
            attacker_token,
            attacker_public_key,
            peer_jwt_svid=peer_svid.jwt_svid_token,
        )

    assert proxy.sessions == {}


def test_proxy_snapshots_server_owned_trust_bundle(
    tmp_path: Path,
    public_key,
    session_keys_dir: Path,
) -> None:
    biscuit_token, issuer_public_key = _biscuit_material()
    configured_trust = make_mock_trust_bundle(_HOLDER_SPIFFE_ID)
    proxy = _proxy(
        tmp_path,
        public_key,
        session_keys_dir,
        issuer_public_key,
        trust_bundle=configured_trust,
    )
    configured_trust.jwks["keys"].clear()
    peer_svid = make_mock_svid_bundle(_HOLDER_SPIFFE_ID, iat=int(time.time()))

    session = proxy.start_session_from_biscuit(
        biscuit_token,
        issuer_public_key,
        peer_jwt_svid=peer_svid.jwt_svid_token,
    )

    assert session.passport_claims["svid_bound"] is True


def test_server_configured_binding_rejects_omitted_jwt_svid(
    tmp_path: Path,
    public_key,
    session_keys_dir: Path,
) -> None:
    biscuit_token, issuer_public_key = _biscuit_material()
    proxy = _proxy(tmp_path, public_key, session_keys_dir, issuer_public_key)

    with pytest.raises(PermissionError, match="peer JWT-SVID is required"):
        proxy.start_session_from_biscuit(biscuit_token, issuer_public_key)

    assert proxy.sessions == {}


def test_federated_svid_cannot_cross_server_configured_trust_domain(
    tmp_path: Path,
    public_key,
    session_keys_dir: Path,
) -> None:
    foreign_spiffe_id = "spiffe://foreign.example/agent/holder"
    biscuit_token, issuer_public_key = _biscuit_material(foreign_spiffe_id)
    server_trust = make_mock_trust_bundle(_HOLDER_SPIFFE_ID)
    server_trust.federated_bundles["foreign.example"] = make_mock_trust_bundle(
        foreign_spiffe_id
    ).jwks
    proxy = _proxy(
        tmp_path,
        public_key,
        session_keys_dir,
        issuer_public_key,
        trust_bundle=server_trust,
    )
    foreign_svid = make_mock_svid_bundle(foreign_spiffe_id, iat=int(time.time()))

    with pytest.raises(PermissionError, match="trust domain"):
        proxy.start_session_from_biscuit(
            biscuit_token,
            issuer_public_key,
            peer_jwt_svid=foreign_svid.jwt_svid_token,
        )

    assert proxy.sessions == {}


def test_unconfigured_server_records_biscuit_as_unbound(
    tmp_path: Path,
    public_key,
    session_keys_dir: Path,
) -> None:
    biscuit_token, issuer_public_key = _biscuit_material()
    proxy = GovernanceProxy(
        log_path=tmp_path / "governance_log.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
        biscuit_issuer_public_key=issuer_public_key,
    )

    session = proxy.start_session_from_biscuit(
        biscuit_token,
        issuer_public_key,
    )

    assert session.passport_claims["svid_bound"] is False

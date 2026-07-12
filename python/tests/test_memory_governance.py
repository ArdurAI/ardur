"""Tests for governed memory stores (B.9)."""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.memory import (
    MEMORY_READ_TOOL,
    MEMORY_WRITE_TOOL,
    GovernedMemoryStore,
    MemoryIntegrityError,
)
from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.proxy import Decision, GovernanceProxy


@pytest.fixture
def actor_keys(tmp_path):
    priv, pub = generate_keypair(keys_dir=tmp_path / "mem-keys", force=True)
    return priv, pub


def _pem_priv(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def _pem_pub(key: ec.EllipticCurvePublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def test_write_read_round_trip(actor_keys):
    priv, pub = actor_keys
    store = GovernedMemoryStore("s1", "vibap.test", 60, "default")
    rid = store.write("hello", priv)
    content, prov = store.read(rid, pub)
    assert content == "hello"
    assert prov["jti"] == rid
    assert prov["sub"] == "s1"


def test_ttl_expiry_raises(actor_keys):
    priv, pub = actor_keys
    store = GovernedMemoryStore("s1", "vibap.test", 1, "default")
    rid = store.write("x", priv)
    time.sleep(1.2)
    with pytest.raises(MemoryIntegrityError, match="expired|invalid"):
        store.read(rid, pub)


def test_signature_tampering_raises(actor_keys):
    priv, pub = actor_keys
    store = GovernedMemoryStore("s1", "vibap.test", 600, "default")
    rid = store.write("secret", priv)
    tag = store._records[rid]["tag"]
    store._records[rid]["tag"] = tag[:-4] + "XXXX"
    with pytest.raises(MemoryIntegrityError):
        store.read(rid, pub)


def test_foreign_signer_raises(actor_keys, tmp_path):
    priv_a, pub_a = actor_keys
    _priv_b, pub_b = generate_keypair(keys_dir=tmp_path / "other", force=True)
    store = GovernedMemoryStore("s1", "vibap.test", 600, "default")
    rid = store.write("data", priv_a)
    with pytest.raises(MemoryIntegrityError):
        store.read(rid, pub_b)


def test_minja_forged_record_injection_fails(tmp_path):
    priv_victim, pub_victim = generate_keypair(keys_dir=tmp_path / "victim", force=True)
    priv_attacker, _pub_attacker = generate_keypair(keys_dir=tmp_path / "attacker", force=True)
    store = GovernedMemoryStore("s1", "vibap.test", 600, "default")
    store.write("legit", priv_victim)
    other = GovernedMemoryStore("s1", "vibap.test", 600, "default")
    forged_id = other.write("evil", priv_attacker)
    store._records[forged_id] = dict(other._records[forged_id])
    with pytest.raises(MemoryIntegrityError):
        store.read(forged_id, pub_victim)


def test_proxy_violation_then_insufficient_evidence(
    tmp_path, public_key, private_key, session_keys_dir
):
    mission = MissionPassport(
        agent_id="a1",
        mission="m",
        allowed_tools=[MEMORY_WRITE_TOOL, MEMORY_READ_TOOL],
        forbidden_tools=[],
        resource_scope=["**"],
        max_tool_calls=20,
        max_duration_s=300,
    )
    token = issue_passport(mission, private_key, ttl_s=300)
    proxy = GovernanceProxy(
        log_path=tmp_path / "log.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )
    session = proxy.start_session(token)

    wargs = {
        "store_id": "mem-1",
        "content": "payload",
    }
    d1, _r1 = proxy.evaluate_tool_call(session, MEMORY_WRITE_TOOL, wargs)
    assert d1 == Decision.PERMIT
    rid = session.last_memory_record_id
    assert rid

    # Tamper stored tag to force integrity failure on read
    store = session.memory_stores["mem-1"]
    tag = store._records[rid]["tag"]
    store._records[rid]["tag"] = tag[:-5] + "ABCDE"

    rargs = {
        "store_id": "mem-1",
        "record_id": rid,
    }
    d2, r2 = proxy.evaluate_tool_call(session, MEMORY_READ_TOOL, rargs)
    assert d2 == Decision.VIOLATION
    assert r2 == "memory_integrity_failure"

    d3, r3 = proxy.evaluate_tool_call(session, MEMORY_READ_TOOL, rargs)
    assert d3 == Decision.INSUFFICIENT_EVIDENCE
    assert r3 == "memory_compromise_boundary"


def test_proxy_write_read_success(tmp_path, public_key, private_key, session_keys_dir):
    mission = MissionPassport(
        agent_id="a1",
        mission="m",
        allowed_tools=[MEMORY_WRITE_TOOL, MEMORY_READ_TOOL],
        forbidden_tools=[],
        resource_scope=["**"],
        max_tool_calls=20,
        max_duration_s=300,
    )
    token = issue_passport(mission, private_key, ttl_s=300)
    proxy = GovernanceProxy(
        log_path=tmp_path / "log.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )
    session = proxy.start_session(token)

    d1, _ = proxy.evaluate_tool_call(
        session,
        MEMORY_WRITE_TOOL,
        {
            "store_id": "s-ok",
            "content": "ok",
        },
    )
    assert d1 == Decision.PERMIT
    rid = session.last_memory_record_id
    d2, _ = proxy.evaluate_tool_call(
        session,
        MEMORY_READ_TOOL,
        {
            "store_id": "s-ok",
            "record_id": rid,
        },
    )
    assert d2 == Decision.PERMIT


# --- FIX-8 from S2 hostile audit (2026-04-28): memory-store signing
# ------------------------------------------------------------------
# Before this change, callers could supply ``actor_private_key_pem`` /
# ``verifier_public_key_pem`` to memory-store tool calls — letting an
# attacker substitute their own signing key for either side of the
# memory-record integrity chain. The fix binds both signer and verifier
# to the proxy's session-anchored key.

class TestMemoryStoreSignerBinding:
    @pytest.fixture
    def _memory_proxy(self, tmp_path, public_key, private_key, session_keys_dir):
        mission = MissionPassport(
            agent_id="a-sign-bind",
            mission="m",
            allowed_tools=[MEMORY_WRITE_TOOL, MEMORY_READ_TOOL],
            forbidden_tools=[],
            resource_scope=["**"],
            max_tool_calls=20,
            max_duration_s=300,
        )
        token = issue_passport(mission, private_key, ttl_s=300)
        proxy = GovernanceProxy(
            log_path=tmp_path / "log.jsonl",
            state_dir=tmp_path / "state",
            public_key=public_key,
            keys_dir=session_keys_dir,
        )
        session = proxy.start_session(token)
        return proxy, session

    def test_caller_supplied_actor_private_key_pem_is_rejected(
        self, _memory_proxy
    ):
        """A tool-call payload that includes actor_private_key_pem is
        rejected at the memory-write boundary. The proxy turns the
        ValueError into a DENY decision with the rejection reason in
        the receipt, ensuring auditors see exactly what failed."""
        proxy, session = _memory_proxy
        attacker_key = ec.generate_private_key(ec.SECP256R1())
        attacker_pem = attacker_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        decision, reason = proxy.evaluate_tool_call(
            session,
            MEMORY_WRITE_TOOL,
            {
                "store_id": "mem-attacker",
                "content": "forged",
                "actor_private_key_pem": attacker_pem,
            },
        )
        assert decision == Decision.DENY
        assert "actor_private_key_pem" in reason

    def test_caller_supplied_verifier_public_key_pem_is_rejected(
        self, _memory_proxy
    ):
        """A read payload that includes verifier_public_key_pem is
        rejected at the memory-read boundary, same DENY semantics."""
        proxy, session = _memory_proxy
        proxy.evaluate_tool_call(
            session,
            MEMORY_WRITE_TOOL,
            {"store_id": "mem-rb", "content": "ok"},
        )
        rid = session.last_memory_record_id

        attacker_key = ec.generate_private_key(ec.SECP256R1())
        attacker_pub = attacker_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        decision, reason = proxy.evaluate_tool_call(
            session,
            MEMORY_READ_TOOL,
            {
                "store_id": "mem-rb",
                "record_id": rid,
                "verifier_public_key_pem": attacker_pub,
            },
        )
        assert decision == Decision.DENY
        assert "verifier_public_key_pem" in reason


# --- Round-3 audit (2026-04-28): approval_policy presence/absence
# end-to-end coverage. Round-2 flagged that the omission of
# approval_policy from _REQUIRED_V01_MEMBERS was rationalized but not
# tested — a future change could silently re-add it (forcing every tool
# call to carry operator_id) or accidentally treat absence as
# "approval required" without anything noticing. These tests pin both
# directions of the absence-vs-presence contract.

class TestApprovalPolicyAbsenceContract:
    def test_md_without_approval_policy_permits_tool_calls_without_operator_id(
        self, tmp_path, public_key, private_key, session_keys_dir
    ):
        """Absence-as-no-gate: a passport that does NOT declare
        approval_policy must let tool calls through without operator_id.
        This is the documented v0.1 semantic and the reason
        approval_policy is omitted from _REQUIRED_V01_MEMBERS."""
        mission = MissionPassport(
            agent_id="a-no-approval",
            mission="m",
            allowed_tools=["read_file"],
            forbidden_tools=[],
            resource_scope=["**"],
            max_tool_calls=5,
            max_duration_s=60,
        )
        # No approval_policy in extra_claims.
        token = issue_passport(mission, private_key, ttl_s=60)
        proxy = GovernanceProxy(
            log_path=tmp_path / "g.jsonl",
            state_dir=tmp_path / "state",
            public_key=public_key,
            keys_dir=session_keys_dir,
        )
        session = proxy.start_session(token)
        decision, reason = proxy.evaluate_tool_call(
            session,
            "read_file",
            {"path": "/x"},  # no operator_id
        )
        assert decision == Decision.PERMIT, (decision, reason)
        # Importantly, the reason is NOT "approval_operator_unavailable".
        assert "approval" not in reason.lower()

    def test_md_with_approval_policy_blocks_without_operator_id(
        self, tmp_path, public_key, private_key, session_keys_dir
    ):
        """Presence-as-gate: a passport that DOES declare approval_policy
        must reject tool calls that omit operator_id, with the
        approval_operator_unavailable reason. This is the inverse of the
        absence-as-no-gate test above; together they pin the contract."""
        mission = MissionPassport(
            agent_id="a-with-approval",
            mission="m",
            allowed_tools=["read_file"],
            forbidden_tools=[],
            resource_scope=["**"],
            max_tool_calls=5,
            max_duration_s=60,
        )
        token = issue_passport(
            mission,
            private_key,
            ttl_s=60,
            extra_claims={
                "approval_policy": {"max_approvals_per_hour_per_operator": 30},
            },
        )
        proxy = GovernanceProxy(
            log_path=tmp_path / "g.jsonl",
            state_dir=tmp_path / "state",
            public_key=public_key,
            keys_dir=session_keys_dir,
        )
        session = proxy.start_session(token)
        decision, reason = proxy.evaluate_tool_call(
            session,
            "read_file",
            {"path": "/x"},  # no operator_id
        )
        assert decision == Decision.INSUFFICIENT_EVIDENCE
        assert reason == "approval_operator_unavailable"


# --- FIX-R6-4 (round-6, 2026-04-29): regression tests for the
# bounded-iat skew gate added in round-5 to ``GovernedMemoryStore.read``.
# Round-5 audit flagged that the M3 fix (route memory.py through
# canonical assert_iat_in_window) shipped without tests — a refactor
# that re-relied on PyJWT's default verify_iat would silently regress.
# These tests pin the new gate.

class TestMemoryStoreIatSkewGuard:
    def _build_store_with_record(
        self,
        private_key,
        public_key,
        *,
        signed_at: int,
    ):
        """Mint a memory-store record whose JWT iat is at ``signed_at``,
        bypassing the regular ``write`` path so we can inject arbitrary
        iat values for the test. Returns (store, record_id)."""
        from vibap.memory import (
            ALGORITHM as MEM_ALG,
            GovernedMemoryStore,
            MEMORY_AUDIENCE,
            MEMORY_ISSUER,
        )
        import hashlib
        import jwt as _jwt
        import uuid as _uuid

        store = GovernedMemoryStore(
            store_id="mem-iat",
            resource_family="test",
            ttl_s=3600,
            integrity_policy="entry_signed",
        )
        content = "payload"
        record_id = str(_uuid.uuid4())
        ch = hashlib.sha256(content.encode("utf-8")).hexdigest()
        claims = {
            "iss": MEMORY_ISSUER,
            "aud": MEMORY_AUDIENCE,
            "sub": store.store_id,
            "iat": signed_at,
            "exp": signed_at + 3600,
            "jti": record_id,
            "rf": store.resource_family,
            "ipol": store._policy_wire(),
            "ch": ch,
        }
        tag = _jwt.encode(claims, private_key, algorithm=MEM_ALG)
        store._records[record_id] = {"content": content, "tag": tag}
        return store, record_id

    def test_far_future_iat_rejected_with_memory_integrity_error(
        self, private_key, public_key
    ):
        from vibap.memory import MemoryIntegrityError
        far_future = int(time.time()) + 365 * 86400
        store, record_id = self._build_store_with_record(
            private_key, public_key, signed_at=far_future,
        )
        with pytest.raises(MemoryIntegrityError, match="memory tag iat"):
            store.read(record_id, public_key)

    def test_iat_within_clock_drift_window_accepted(
        self, private_key, public_key
    ):
        slight_future = int(time.time()) + 60
        store, record_id = self._build_store_with_record(
            private_key, public_key, signed_at=slight_future,
        )
        # Should not raise — within ±300s default future window.
        content, _ = store.read(record_id, public_key)
        assert content == "payload"

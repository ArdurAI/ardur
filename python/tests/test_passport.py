"""Tests for passport issuance, verification, and tamper detection."""

from __future__ import annotations

import base64
import hashlib
import json
import stat
import time

import jwt
import pytest

from vibap.passport import (
    MissionPassport,
    derive_child_passport,
    generate_keypair,
    issue_passport,
    verify_passport,
)
from vibap.proxy import GovernanceProxy


def _tamper_payload(token: str, mutator) -> str:
    """Flip a bit in the payload segment of a JWT without re-signing.

    Returns a token whose payload differs from the signed payload, which any
    honest verifier must reject.
    """
    header_b64, payload_b64, sig_b64 = token.split(".")
    # Decode with URL-safe base64, padding as needed.
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    payload = json.loads(raw)
    mutator(payload)
    new_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    new_b64 = base64.urlsafe_b64encode(new_raw).rstrip(b"=").decode("ascii")
    return ".".join([header_b64, new_b64, sig_b64])


class TestPassportRoundtrip:
    def test_generate_keypair_writes_private_key_restrictively(self, tmp_path):
        generate_keypair(keys_dir=tmp_path)

        private_mode = stat.S_IMODE((tmp_path / "passport_private.pem").stat().st_mode)
        public_mode = stat.S_IMODE((tmp_path / "passport_public.pem").stat().st_mode)
        assert private_mode == 0o600
        assert public_mode == 0o644

    def test_issue_and_verify_roundtrip(self, example_mission, private_key, public_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        claims = verify_passport(token, public_key)

        assert claims["sub"] == "agent-test"
        assert claims["mission"] == "run Q1 sales analysis"
        assert claims["allowed_tools"] == ["read_file", "write_file", "analyze"]
        assert claims["forbidden_tools"] == ["delete_file", "execute_shell"]
        assert claims["max_tool_calls"] == 5
        assert claims["iss"] == "vibap-governance-proxy"
        assert claims["aud"] == "vibap-proxy"
        assert "jti" in claims and "exp" in claims and "iat" in claims

    def test_rejects_invalid_ttl(self, example_mission, private_key):
        with pytest.raises(ValueError):
            issue_passport(example_mission, private_key, ttl_s=0)


class TestPassportExpiry:
    def test_expired_passport_is_rejected(self, example_mission, private_key, public_key):
        # Issue with TTL=1s and wait past expiry.
        token = issue_passport(example_mission, private_key, ttl_s=1)
        time.sleep(1.2)
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_passport(token, public_key)


class TestPassportTamper:
    def test_tampered_payload_is_rejected(self, issued_passport, public_key):
        tampered = _tamper_payload(
            issued_passport,
            lambda payload: payload.update({"allowed_tools": ["delete_file", "execute_shell"]}),
        )
        with pytest.raises(jwt.InvalidSignatureError):
            verify_passport(tampered, public_key)

    def test_tampered_agent_id_is_rejected(self, issued_passport, public_key):
        tampered = _tamper_payload(
            issued_passport,
            lambda payload: payload.update({"sub": "attacker"}),
        )
        with pytest.raises(jwt.InvalidSignatureError):
            verify_passport(tampered, public_key)

    def test_delegated_passport_rejects_parent_token_hash_mismatch(
        self, private_key, public_key
    ):
        parent_a = issue_passport(
            MissionPassport(
                agent_id="parent-a",
                mission="coordinate",
                allowed_tools=["read_file"],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=60,
        )
        parent_b = issue_passport(
            MissionPassport(
                agent_id="parent-b",
                mission="coordinate",
                allowed_tools=["read_file"],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=60,
        )
        child_token = derive_child_passport(
            parent_token=parent_a,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read_file"],
            child_mission="subtask",
            child_ttl_s=30,
        )

        forged_child = jwt.encode(
            {
                **verify_passport(child_token, public_key, parent_token=parent_a),
                "parent_token_hash": hashlib.sha256(parent_b.encode("utf-8")).hexdigest(),
            },
            private_key,
            algorithm="ES256",
        )

        with pytest.raises(PermissionError, match="parent token hash mismatch"):
            verify_passport(forged_child, public_key, parent_token=parent_a)


class TestDelegation:
    def test_delegation_scope_narrowing(self, issued_delegating_passport, private_key, public_key):
        child_token = derive_child_passport(
            parent_token=issued_delegating_passport,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child-agent-1",
            child_allowed_tools=["read_file", "analyze"],
            child_mission="gather data only",
            child_ttl_s=60,
        )
        child_claims = verify_passport(
            child_token, public_key, parent_token=issued_delegating_passport
        )
        assert set(child_claims["allowed_tools"]) == {"read_file", "analyze"}
        parent_claims = verify_passport(issued_delegating_passport, public_key)
        # Child scope MUST be a subset of parent scope
        assert set(child_claims["allowed_tools"]).issubset(set(parent_claims["allowed_tools"]))
        # parent_jti correctly set
        assert child_claims["parent_jti"] == parent_claims["jti"]
        assert child_claims["delegation_chain"][0]["jti"] == parent_claims["jti"]

    def test_scope_escalation_blocked(self, issued_delegating_passport, private_key, public_key):
        with pytest.raises(PermissionError, match="scope escalation"):
            derive_child_passport(
                parent_token=issued_delegating_passport,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="evil-child",
                child_allowed_tools=["read_file", "rm_rf_root"],
                child_mission="malicious",
                child_ttl_s=60,
            )

    def test_delegation_depth_exhaustion(self, example_mission, private_key, public_key):
        """A passport with max_delegation_depth=0 cannot delegate at all."""
        mission = MissionPassport(
            agent_id="no-delegate",
            mission="solo task",
            allowed_tools=["read_file"],
            delegation_allowed=True,       # allowed flag set, but depth = 0
            max_delegation_depth=0,
        )
        parent_token = issue_passport(mission, private_key, ttl_s=60)
        with pytest.raises(PermissionError, match="depth exhausted"):
            derive_child_passport(
                parent_token=parent_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="child",
                child_allowed_tools=["read_file"],
                child_mission="sub",
            )

    def test_signed_lineage_cap_blocks_additional_child_minting(
        self, private_key, public_key
    ):
        root_token = issue_passport(
            MissionPassport(
                agent_id="root",
                mission="root task",
                allowed_tools=["read_file"],
                delegation_allowed=True,
                max_delegation_depth=32,
            ),
            private_key,
            ttl_s=60,
        )

        current_token = root_token
        for depth in range(16):
            current_token = derive_child_passport(
                parent_token=current_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id=f"child-{depth}",
                child_allowed_tools=["read_file"],
                child_mission=f"subtask-{depth}",
                child_ttl_s=30,
            )

        with pytest.raises(PermissionError, match="delegation depth exceeded"):
            derive_child_passport(
                parent_token=current_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="too-deep",
                child_allowed_tools=["read_file"],
                child_mission="overflow",
                child_ttl_s=30,
            )

    def test_delegation_without_allowed_flag_blocked(
        self, example_mission, private_key, public_key
    ):
        """example_mission has delegation_allowed=False — must refuse."""
        parent_token = issue_passport(example_mission, private_key, ttl_s=60)
        with pytest.raises(PermissionError, match="does not allow delegation"):
            derive_child_passport(
                parent_token=parent_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="child",
                child_allowed_tools=["read_file"],
                child_mission="sub",
            )

    def test_child_ttl_clamped_to_parent_exp(self, private_key, public_key):
        """Regression: child TTL must never exceed parent's remaining lifetime."""
        mission = MissionPassport(
            agent_id="parent",
            mission="short-lived",
            allowed_tools=["read_file"],
            max_tool_calls=10,
            max_duration_s=30,           # parent only lives 30s
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(mission, private_key, ttl_s=30)
        parent_claims = verify_passport(parent_token, public_key)

        # Request a 1-hour child TTL — must get clamped.
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read_file"],
            child_mission="sub",
            child_ttl_s=3600,
        )
        child_claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert child_claims["exp"] <= parent_claims["exp"], (
            "child exp must not exceed parent exp"
        )

    def test_multi_level_delegation(self, private_key, public_key):
        """parent -> child -> grandchild -> great-grandchild, each narrowing scope."""
        mission = MissionPassport(
            agent_id="gen0",
            mission="root",
            allowed_tools=["read", "write", "analyze", "search"],
            max_tool_calls=100,
            max_duration_s=600,
            delegation_allowed=True,
            max_delegation_depth=3,
        )
        gen0_token = issue_passport(mission, private_key, ttl_s=600)

        gen1_token = derive_child_passport(
            parent_token=gen0_token, public_key=public_key, private_key=private_key,
            child_agent_id="gen1", child_allowed_tools=["read", "write", "analyze"],
            child_mission="gen1", child_ttl_s=300,
        )
        gen1_claims = verify_passport(gen1_token, public_key, parent_token=gen0_token)
        assert gen1_claims["max_delegation_depth"] == 2
        assert gen1_claims["delegation_allowed"] is True

        gen2_token = derive_child_passport(
            parent_token=gen1_token, public_key=public_key, private_key=private_key,
            child_agent_id="gen2", child_allowed_tools=["read", "write"],
            child_mission="gen2", child_ttl_s=200,
        )
        gen2_claims = verify_passport(gen2_token, public_key, parent_token=gen1_token)
        assert gen2_claims["max_delegation_depth"] == 1

        gen3_token = derive_child_passport(
            parent_token=gen2_token, public_key=public_key, private_key=private_key,
            child_agent_id="gen3", child_allowed_tools=["read"],
            child_mission="gen3", child_ttl_s=100,
        )
        gen3_claims = verify_passport(gen3_token, public_key, parent_token=gen2_token)
        assert gen3_claims["max_delegation_depth"] == 0
        assert gen3_claims["delegation_allowed"] is False
        assert gen3_claims["allowed_tools"] == ["read"]

        # gen3 cannot further delegate.
        with pytest.raises(PermissionError):
            derive_child_passport(
                parent_token=gen3_token, public_key=public_key, private_key=private_key,
                child_agent_id="gen4", child_allowed_tools=["read"],
                child_mission="gen4", child_ttl_s=50,
            )


class TestCwdClaim:
    """C8: optional `cwd` passport claim for relative-path resolution.

    The `cwd` claim is an opt-in anchor. When declared, the scope checker
    resolves relative candidate values against it before the fallback
    coercions. When absent, behavior is identical to pre-C8 (JWT bytes
    unchanged, scope check unchanged).
    """

    # -- happy path & back-compat --------------------------------------------

    def test_cwd_included_in_claims_when_set(self, private_key, public_key):
        mission = MissionPassport(
            agent_id="agent-cwd",
            mission="scoped to /workspace",
            allowed_tools=["read_file"],
            resource_scope=["/workspace/*"],
            max_tool_calls=5,
            max_duration_s=60,
            cwd="/workspace",
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        claims = verify_passport(token, public_key)
        assert claims.get("cwd") == "/workspace"

    def test_cwd_absent_from_claims_when_not_set(self, example_mission, private_key, public_key):
        """Back-compat: passports without cwd must not have the claim in the JWT."""
        assert example_mission.cwd is None
        token = issue_passport(example_mission, private_key, ttl_s=60)
        claims = verify_passport(token, public_key)
        assert "cwd" not in claims

    # -- validation at construction ------------------------------------------

    def test_empty_cwd_coerced_to_none(self):
        """Empty / whitespace cwd is a common mission-file slip — coerce to None."""
        mission = MissionPassport(
            agent_id="a", mission="m", allowed_tools=["read_file"], cwd="",
        )
        assert mission.cwd is None
        mission2 = MissionPassport(
            agent_id="a", mission="m", allowed_tools=["read_file"], cwd="   ",
        )
        assert mission2.cwd is None

    def test_relative_cwd_rejected(self):
        """`cwd` must be absolute — relative paths are semantically undefined."""
        with pytest.raises(ValueError, match="absolute"):
            MissionPassport(
                agent_id="a", mission="m", allowed_tools=["read_file"], cwd="workspace",
            )
        with pytest.raises(ValueError, match="absolute"):
            MissionPassport(
                agent_id="a", mission="m", allowed_tools=["read_file"], cwd="./rel",
            )

    def test_cwd_normalized_at_construction(self):
        """Trailing slashes and './' noise are canonicalized so narrowing comparisons are consistent."""
        mission = MissionPassport(
            agent_id="a", mission="m", allowed_tools=["read_file"],
            cwd="/workspace/./sub/",
        )
        assert mission.cwd == "/workspace/sub"

    def test_cwd_omitted_from_to_dict_when_none(self, example_mission):
        """to_dict() omits cwd when None so wire format stays bit-identical to pre-C8."""
        assert "cwd" not in example_mission.to_dict()
        # Positive case: when set, it IS present
        m = MissionPassport(
            agent_id="a", mission="m", allowed_tools=["read_file"], cwd="/w",
        )
        assert m.to_dict().get("cwd") == "/w"

    # -- delegation ----------------------------------------------------------

    def test_cwd_inherited_by_child_delegation(self, private_key, public_key):
        parent_mission = MissionPassport(
            agent_id="parent", mission="root",
            allowed_tools=["read_file", "write_file"],
            resource_scope=["/workspace/*"],
            max_tool_calls=10, max_duration_s=60,
            delegation_allowed=True, max_delegation_depth=2,
            cwd="/workspace",
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=60)
        child_token = derive_child_passport(
            parent_token=parent_token, public_key=public_key, private_key=private_key,
            child_agent_id="child", child_allowed_tools=["read_file"],
            child_mission="sub", child_ttl_s=30,
        )
        child_claims = verify_passport(child_token, public_key, parent_token=parent_token)
        # Child inherits parent's cwd verbatim when child_cwd is None.
        assert child_claims.get("cwd") == "/workspace"

    def test_cwd_narrowing_allowed(self, private_key, public_key):
        """Child may narrow cwd to a subpath (boundary on '/')."""
        parent_mission = MissionPassport(
            agent_id="parent", mission="root",
            allowed_tools=["read_file"],
            resource_scope=["/workspace/*"],
            delegation_allowed=True, max_delegation_depth=2,
            cwd="/workspace",
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=60)
        child_token = derive_child_passport(
            parent_token=parent_token, public_key=public_key, private_key=private_key,
            child_agent_id="child", child_allowed_tools=["read_file"],
            child_mission="sub", child_ttl_s=30,
            child_cwd="/workspace/a",
        )
        child_claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert child_claims.get("cwd") == "/workspace/a"

    def test_cwd_widening_blocked(self, private_key, public_key):
        """Child requesting a cwd outside parent's must be rejected."""
        parent_mission = MissionPassport(
            agent_id="parent", mission="root",
            allowed_tools=["read_file"],
            delegation_allowed=True, max_delegation_depth=2,
            cwd="/workspace",
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=60)
        with pytest.raises(PermissionError, match="cwd escalation"):
            derive_child_passport(
                parent_token=parent_token, public_key=public_key, private_key=private_key,
                child_agent_id="child", child_allowed_tools=["read_file"],
                child_mission="sub", child_ttl_s=30,
                child_cwd="/other",
            )

    def test_cwd_boundary_blocks_prefix_collision(self, private_key, public_key):
        """'/workspaceabc' is NOT a narrowing of '/workspace' — boundary must be '/'."""
        parent_mission = MissionPassport(
            agent_id="parent", mission="root",
            allowed_tools=["read_file"],
            delegation_allowed=True, max_delegation_depth=2,
            cwd="/workspace",
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=60)
        with pytest.raises(PermissionError, match="cwd escalation"):
            derive_child_passport(
                parent_token=parent_token, public_key=public_key, private_key=private_key,
                child_agent_id="child", child_allowed_tools=["read_file"],
                child_mission="sub", child_ttl_s=30,
                child_cwd="/workspaceabc",
            )

    def test_cwd_introduction_when_parent_none_blocked(self, private_key, public_key):
        """Parent with no cwd → child cannot unilaterally introduce one."""
        parent_mission = MissionPassport(
            agent_id="parent", mission="root",
            allowed_tools=["read_file"],
            delegation_allowed=True, max_delegation_depth=2,
            # cwd intentionally omitted
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=60)
        with pytest.raises(PermissionError, match="cannot introduce cwd"):
            derive_child_passport(
                parent_token=parent_token, public_key=public_key, private_key=private_key,
                child_agent_id="child", child_allowed_tools=["read_file"],
                child_mission="sub", child_ttl_s=30,
                child_cwd="/workspace",
            )

    def test_cwd_none_parent_none_child_inherits_none(self, private_key, public_key):
        """Back-compat: no cwd anywhere in the chain keeps None."""
        parent_mission = MissionPassport(
            agent_id="parent", mission="root",
            allowed_tools=["read_file"],
            delegation_allowed=True, max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=60)
        child_token = derive_child_passport(
            parent_token=parent_token, public_key=public_key, private_key=private_key,
            child_agent_id="child", child_allowed_tools=["read_file"],
            child_mission="sub", child_ttl_s=30,
        )
        child_claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert "cwd" not in child_claims

    # -- end-to-end via proxy ------------------------------------------------

    def test_relative_candidate_resolved_against_cwd_in_scope_check(
        self, private_key, public_key, proxy: GovernanceProxy
    ):
        """End-to-end: a passport with cwd=/workspace + scope=/workspace/* must
        PERMIT a tool call that passes './file.txt' as an argument."""
        mission = MissionPassport(
            agent_id="agent-cwd",
            mission="edit files in workspace",
            allowed_tools=["read_file"],
            resource_scope=["/workspace/*"],
            max_tool_calls=5, max_duration_s=60,
            cwd="/workspace",
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        # Candidate './file.txt' is relative. Without cwd, the fallback
        # absolute-coercion ('/' + './file.txt' = '/file.txt') would NOT
        # match '/workspace/*'. With cwd resolution, it becomes
        # '/workspace/file.txt' and matches.
        decision, reason, _ = session.check_and_record(
            "read_file", {"path": "./file.txt"}
        )
        assert decision.value == "PERMIT", reason

    def test_relative_candidate_with_traversal_still_denied(
        self, private_key, public_key, proxy: GovernanceProxy
    ):
        """Defense in depth: cwd resolution must not mask '..' traversal.
        './.../../etc/passwd' from cwd=/workspace must still be denied."""
        mission = MissionPassport(
            agent_id="agent-cwd",
            mission="edit files in workspace",
            allowed_tools=["read_file"],
            resource_scope=["/workspace/*"],
            max_tool_calls=5, max_duration_s=60,
            cwd="/workspace",
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, reason, _ = session.check_and_record(
            "read_file", {"path": "../etc/passwd"}
        )
        assert decision.value == "DENY", reason

    def test_cwd_absent_scope_check_unchanged(
        self, issued_passport, proxy: GovernanceProxy
    ):
        """Back-compat: passport without cwd → scope check behaves exactly as pre-C8
        (empty scope = all permitted)."""
        session = proxy.start_session(issued_passport)
        decision, _, _ = session.check_and_record(
            "read_file", {"path": "./anything.txt"}
        )
        assert decision.value == "PERMIT"


# --- Round-4 audit (2026-04-28): the round-3 prompt advertised passport
# iat-skew tests in the test class header but never wrote them. This
# closes the regression-test gap (FIX-R4-7).

class TestPassportIatSkewGuard:
    """Pin that ``verify_passport`` rejects far-future / far-past iat
    values via the shared ``assert_iat_in_window`` helper."""

    def test_passport_with_iat_in_far_future_fails_closed(
        self, private_key, public_key
    ):
        far_future = int(time.time()) + 365 * 86400
        claims = {
            "iss": "vibap-governance-proxy",
            "sub": "agent-test",
            "aud": "vibap-proxy",
            "iat": far_future,
            "exp": far_future + 60,
            "jti": "passport-far-future",
            "mission": "test",
            "allowed_tools": ["read_file"],
            "forbidden_tools": [],
            "resource_scope": [],
            "max_tool_calls": 5,
            "max_duration_s": 60,
            "delegation_allowed": False,
            "max_delegation_depth": 0,
        }
        token = jwt.encode(claims, private_key, algorithm="ES256")
        with pytest.raises(jwt.InvalidTokenError, match="passport iat"):
            verify_passport(token, public_key)

    def test_passport_with_iat_in_far_past_fails_closed(
        self, private_key, public_key
    ):
        far_past = int(time.time()) - 365 * 86400
        claims = {
            "iss": "vibap-governance-proxy",
            "sub": "agent-test",
            "aud": "vibap-proxy",
            "iat": far_past,
            # exp also far in the past; PyJWT will catch ExpiredSignature
            # before our gate runs, so we must also push exp into the
            # future to exercise the past-skew check distinctly.
            "exp": int(time.time()) + 60,
            "jti": "passport-far-past",
            "mission": "test",
            "allowed_tools": ["read_file"],
            "forbidden_tools": [],
            "resource_scope": [],
            "max_tool_calls": 5,
            "max_duration_s": 60,
            "delegation_allowed": False,
            "max_delegation_depth": 0,
        }
        token = jwt.encode(claims, private_key, algorithm="ES256")
        with pytest.raises(jwt.InvalidTokenError, match="passport iat"):
            verify_passport(token, public_key)


# --- FIX-R7-3 (round-7, 2026-04-29): defense-in-depth regression for
# the KB-JWT second-decode bounded-iat. Round-6 added the
# ``assert_iat_in_window`` call at proxy.py:2339-2347 specifically to
# defend against a future refactor that removes ``verify_pop`` while
# keeping the nonce-extraction path. Round-6 audit (LOW-2) flagged
# that no test catches a revert of just that block, because verify_pop
# above it already covers the same shape. This test monkeypatches
# verify_pop to a no-op and confirms the second-decode gate fires.

class TestKbJwtSecondDecodeIatBound:
    def test_far_future_kb_jwt_iat_rejected_when_verify_pop_mocked(
        self, tmp_path, public_key, private_key, session_keys_dir, monkeypatch
    ):
        """If verify_pop is silently bypassed (refactor risk), the
        defense-in-depth iat gate at proxy.py:2339-2347 must still
        reject a KB-JWT with iat far in the future. Mock verify_pop
        to a no-op to isolate the new gate."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from vibap.passport import (
            MissionPassport,
            compute_jwk_thumbprint,
            issue_passport,
        )
        from vibap.proxy import GovernanceProxy

        # Generate a holder keypair.
        holder_priv = ec.generate_private_key(ec.SECP256R1())
        holder_pub = holder_priv.public_key()
        thumbprint = compute_jwk_thumbprint(holder_pub)

        # Mint a passport bound to that key (cnf claim).
        mission = MissionPassport(
            agent_id="agent-kb-jwt-iat",
            mission="m",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=5,
            max_duration_s=60,
            holder_key_thumbprint=thumbprint,
        )
        passport_token = issue_passport(mission, private_key, ttl_s=60)

        # Build a KB-JWT with iat far in the future.
        far_future = int(time.time()) + 365 * 86400
        sd_hash_raw = hashlib.sha256(passport_token.encode("ascii")).digest()
        sd_hash = base64.urlsafe_b64encode(sd_hash_raw).rstrip(b"=").decode()
        kb_claims = {
            "iat": far_future,
            "nonce": "fresh-nonce-x" * 4,
            "sd_hash": sd_hash,
        }
        kb_jwt_str = jwt.encode(kb_claims, holder_priv, algorithm="ES256")

        # Mock verify_pop to a no-op so we can isolate the second-decode
        # gate. In real production, verify_pop runs first and catches
        # this case — the round-6 fix is defense-in-depth for the case
        # where a future refactor splits or removes verify_pop. The
        # function is locally imported inside start_session via
        # ``from .passport import verify_pop``, so we patch the source
        # module attribute (proxy_mod resolves the name at call time).
        def _noop_verify_pop(*args, **kwargs):
            return True
        monkeypatch.setattr("vibap.passport.verify_pop", _noop_verify_pop)

        proxy = GovernanceProxy(
            log_path=tmp_path / "log.jsonl",
            state_dir=tmp_path / "state",
            public_key=public_key,
            keys_dir=session_keys_dir,
        )
        with pytest.raises(PermissionError, match="KB-JWT iat"):
            proxy.start_session(
                passport_token,
                holder_public_key=holder_pub,
                kb_jwt=kb_jwt_str,
            )

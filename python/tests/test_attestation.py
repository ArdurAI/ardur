"""Tests for behavioral attestation issuance and verification."""

from __future__ import annotations

import time

import jwt
import pytest

from vibap.attestation import (
    ATTESTATION_SCHEMA_VERSION,
    compute_log_digest,
    issue_attestation,
    verify_attestation,
)


def _sample_events() -> list[dict]:
    return [
        {"tool": "read_file", "decision": "PERMIT", "reason": "within scope"},
        {"tool": "delete_file", "decision": "DENY", "reason": "forbidden"},
    ]


class TestAttestationRoundtrip:
    def test_issue_and_verify_roundtrip(self, private_key, public_key):
        events = _sample_events()
        token = issue_attestation(
            passport_jti="parent-jti-123",
            agent_id="agent-test",
            mission="sales analysis",
            events=events,
            permits=1,
            denials=1,
            elapsed_s=12.345,
            private_key=private_key,
        )
        claims = verify_attestation(token, public_key)

        assert claims["schema_version"] == ATTESTATION_SCHEMA_VERSION
        assert claims["sub"] == "agent-test"
        assert claims["passport_jti"] == "parent-jti-123"
        assert claims["type"] == "behavioral_attestation"
        assert claims["permits"] == 1
        assert claims["denials"] == 1
        assert claims["total_events"] == 2
        assert claims["scope_compliance"] == "violated"
        assert claims["log_digest_sha256"] == compute_log_digest(events)

    def test_exp_claim_present(self, private_key, public_key):
        """Regression: attestation must include an exp claim (earlier versions
        omitted it, making tokens valid forever)."""
        token = issue_attestation(
            passport_jti="j", agent_id="a", mission="m",
            events=[], permits=0, denials=0, elapsed_s=0.0,
            private_key=private_key,
        )
        claims = verify_attestation(token, public_key)
        assert "exp" in claims, "attestation token must carry an exp claim"
        # Sanity: exp is in the future relative to iat.
        assert claims["exp"] > claims["iat"]

    def test_scope_compliance_full_when_no_denials(self, private_key, public_key):
        token = issue_attestation(
            passport_jti="j", agent_id="a", mission="m",
            events=[{"tool": "read", "decision": "PERMIT"}],
            permits=1, denials=0, elapsed_s=1.0,
            private_key=private_key,
        )
        claims = verify_attestation(token, public_key)
        assert claims["scope_compliance"] == "full"

    def test_extra_claims_are_included_without_overriding_reserved_claims(
        self,
        private_key,
        public_key,
    ):
        token = issue_attestation(
            passport_jti="j",
            agent_id="a",
            mission="m",
            events=[],
            permits=0,
            denials=0,
            elapsed_s=0.0,
            private_key=private_key,
            extra_claims={"children_spawned": 6, "child_jtis": ["c1", "c2"]},
        )
        claims = verify_attestation(token, public_key)
        assert claims["children_spawned"] == 6
        assert claims["child_jtis"] == ["c1", "c2"]

        with pytest.raises(ValueError, match="reserved claims"):
            issue_attestation(
                passport_jti="j",
                agent_id="a",
                mission="m",
                events=[],
                permits=0,
                denials=0,
                elapsed_s=0.0,
                private_key=private_key,
                extra_claims={"passport_jti": "override"},
            )


class TestAttestationDigest:
    def test_digest_is_deterministic(self):
        events = _sample_events()
        d1 = compute_log_digest(events)
        d2 = compute_log_digest(events)
        assert d1 == d2
        assert len(d1) == 64  # sha256 hex length

    def test_digest_changes_when_events_change(self):
        d1 = compute_log_digest(_sample_events())
        d2 = compute_log_digest(
            _sample_events() + [{"tool": "write", "decision": "PERMIT", "reason": "ok"}]
        )
        assert d1 != d2

    def test_digest_stable_across_key_order(self):
        """RFC 8785 object ordering must not affect the digest."""
        a = [{"tool": "read", "decision": "PERMIT"}]
        b = [{"decision": "PERMIT", "tool": "read"}]
        assert compute_log_digest(a) == compute_log_digest(b)


class TestAttestationMissingClaims:
    def test_missing_required_claim_rejected(self, private_key, public_key):
        """A hand-rolled token missing required claims (e.g. passport_jti)
        must fail verification."""
        from vibap.passport import ALGORITHM

        now = int(time.time())
        bad_claims = {
            "iss": "vibap-governance-proxy",
            "sub": "agent",
            "aud": "vibap-attestation-verifier",
            "iat": now,
            "exp": now + 3600,
            "jti": "some-jti",
            # passport_jti intentionally omitted
        }
        bad_token = jwt.encode(bad_claims, private_key, algorithm=ALGORITHM)
        with pytest.raises(jwt.MissingRequiredClaimError):
            verify_attestation(bad_token, public_key)


# --- Round-4 audit (FIX-R4-3, 2026-04-28): the round-3 hostile audit
# flagged that ``verify_attestation`` had no bounded iat check. As a
# public API exported in vibap/__init__.py, callers in cross-trust
# scenarios got no protection from far-future-iat attestation forgeries.
# The round-4 fix wires ``assert_iat_in_window`` into the verifier;
# this test pins the new gate.

class TestVerifyAttestationIatSkew:
    def test_far_future_iat_fails_closed(self, private_key, public_key):
        from vibap.passport import ALGORITHM as _ALG
        far_future = int(time.time()) + 365 * 86400
        claims = {
            "iss": "att-issuer",
            "sub": "agent",
            "aud": "vibap-attestation-verifier",
            "iat": far_future,
            "exp": far_future + 3600,
            "jti": "att-far-future",
            "passport_jti": "p-1",
            "log_digest": "abc",
            "events_count": 1,
        }
        token = jwt.encode(claims, private_key, algorithm=_ALG)
        with pytest.raises(jwt.InvalidTokenError, match="attestation iat"):
            verify_attestation(token, public_key)

    def test_in_window_iat_accepted(self, private_key, public_key):
        # Exercise the happy path so the new gate doesn't false-positive.
        events = _sample_events()
        token = issue_attestation(
            passport_jti="parent-jti-456",
            agent_id="agent-happy-path",
            mission="iat-window check",
            events=events,
            permits=1,
            denials=1,
            elapsed_s=0.5,
            private_key=private_key,
        )
        claims = verify_attestation(token, public_key)
        assert claims["passport_jti"] == "parent-jti-456"

"""Tests for vibap.spiffe_identity.verify_jwt_svid.

The round-4 hostile audit (FIX-R5-H7, 2026-04-28) flagged that
``verify_jwt_svid`` — the SPIFFE peer-identity binding entrypoint
consumed by ``proxy.start_session_from_biscuit`` — had **zero** test
coverage. A regression that removed the bounded-iat-skew gate (or the
entire function call) would not be caught by any existing test.

These tests close that gap by exercising:
- the happy path (well-formed SVID, valid audience, in-window iat),
- audience mismatch (wrong audience → ValueError),
- bounded-iat-skew gate on far-future iat,
- bounded-iat-skew gate on far-past iat,
- empty token / empty audience input validation.

The tests use the ``make_mock_svid_bundle`` / ``make_mock_trust_bundle``
helpers; the iat-override parameter added in round-5 lets us mint tokens
at fresh / future / past timestamps. Those helpers used to live in
``vibap.spiffe_identity`` itself and now live in ``tests/spiffe_doubles.py``
— they mint deterministic, attacker-derivable key material, so they must
not sit in the shipped package (see ``test_no_test_doubles_shipped.py``).
"""

from __future__ import annotations

import time

import pytest

from spiffe_doubles import make_mock_svid_bundle, make_mock_trust_bundle
from vibap.spiffe_identity import SvidClaims, verify_jwt_svid


_AUDIENCE = "vibap://spiffe-mock"
_SPIFFE_ID = "spiffe://example.org/workload-test"


class TestVerifyJwtSvidHappyPath:
    def test_federation_bundle_with_labelled_keys_verifies(self):
        """Round-5 happy path: a freshly-minted SVID with valid audience
        flows through ``verify_jwt_svid`` cleanly. Without this test, a
        regression that breaks the entire verifier (e.g. accidentally
        commenting out ``parse_and_validate``) would not be detected."""
        now = int(time.time())
        bundle = make_mock_svid_bundle(_SPIFFE_ID, iat=now, exp=now + 600)
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        for key in trust.jwks["keys"]:
            if key.get("use") != "jwt-svid":
                key["use"] = "x509-svid"
        assert {key["use"] for key in trust.jwks["keys"]} == {
            "jwt-svid",
            "x509-svid",
        }
        claims = verify_jwt_svid(bundle.jwt_svid_token, trust, _AUDIENCE)
        assert isinstance(claims, SvidClaims)
        assert claims.spiffe_id == _SPIFFE_ID
        assert _AUDIENCE in claims.audience
        assert claims.iat == now

    def test_workload_api_bundle_without_use_verifies(self):
        now = int(time.time())
        bundle = make_mock_svid_bundle(_SPIFFE_ID, iat=now, exp=now + 600)
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        labelled_key = next(
            key for key in trust.jwks["keys"] if key.get("use") == "jwt-svid"
        )
        workload_api_key = {
            field: labelled_key[field] for field in ("kty", "kid", "crv", "x", "y")
        }
        assert "use" not in workload_api_key
        trust.jwks = {"keys": [workload_api_key]}
        assert bundle.jwt_svid_token is not None

        claims = verify_jwt_svid(bundle.jwt_svid_token, trust, _AUDIENCE)

        assert claims.spiffe_id == _SPIFFE_ID


class TestVerifyJwtSvidIatGate:
    def test_far_future_iat_fails_closed(self):
        """FIX-R4-4 regression test: a token with iat far in the future
        must be rejected. Two layers can catch this: the underlying
        SPIFFE library (PyJWT under the hood may raise "not yet valid")
        AND our explicit ``assert_iat_in_window`` gate. The round-5
        rationale for the explicit gate is that the SPIFFE library's
        behavior is not contractually guaranteed across versions —
        match either rejection text so the test pins the
        defense-in-depth outcome regardless of which layer fires."""
        far_future = int(time.time()) + 365 * 86400
        bundle = make_mock_svid_bundle(
            _SPIFFE_ID, iat=far_future, exp=far_future + 3600
        )
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        with pytest.raises(
            ValueError,
            match=r"(JWT-SVID iat lies more than|not yet valid|future)",
        ):
            verify_jwt_svid(bundle.jwt_svid_token, trust, _AUDIENCE)

    def test_far_past_iat_fails_closed(self):
        """The default ±30-day past-skew bound also rejects archival
        tokens — caller must opt in by passing a different bound (the
        function signature doesn't currently expose that, which is itself
        a known limitation; this test pins the conservative default)."""
        far_past = int(time.time()) - 365 * 86400
        # exp is also in the past with the default _MOCK_EXP, so the
        # SPIFFE library may reject on exp first. We push exp into the
        # future to isolate the iat past-skew check.
        bundle = make_mock_svid_bundle(
            _SPIFFE_ID, iat=far_past, exp=int(time.time()) + 3600
        )
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        with pytest.raises(
            ValueError,
            match=r"(JWT-SVID iat lies more than|expired|invalid)",
        ):
            verify_jwt_svid(bundle.jwt_svid_token, trust, _AUDIENCE)


class TestVerifyJwtSvidInputValidation:
    def test_empty_token_raises(self):
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        with pytest.raises(ValueError, match="cannot be empty"):
            verify_jwt_svid("", trust, _AUDIENCE)

    def test_empty_audience_raises(self):
        bundle = make_mock_svid_bundle(_SPIFFE_ID, iat=int(time.time()))
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        with pytest.raises(ValueError, match="audience cannot be empty"):
            verify_jwt_svid(bundle.jwt_svid_token, trust, "")

    def test_wrong_audience_rejected(self):
        """Audience binding is the SPIFFE library's job — but a
        regression that bypasses it would silently let any audience
        through. Pin the contract."""
        now = int(time.time())
        bundle = make_mock_svid_bundle(_SPIFFE_ID, iat=now, exp=now + 600)
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        with pytest.raises(ValueError):
            verify_jwt_svid(bundle.jwt_svid_token, trust, "wrong-audience")

    def test_tampered_signature_rejected(self):
        now = int(time.time())
        bundle = make_mock_svid_bundle(_SPIFFE_ID, iat=now, exp=now + 600)
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        assert bundle.jwt_svid_token is not None
        header, payload, signature = bundle.jwt_svid_token.split(".")
        replacement = "A" if signature[0] != "A" else "B"
        tampered_token = f"{header}.{payload}.{replacement}{signature[1:]}"

        with pytest.raises(ValueError, match="JWT-SVID validation failed"):
            verify_jwt_svid(tampered_token, trust, _AUDIENCE)

    def test_unknown_trust_domain_rejected(self):
        unknown_spiffe_id = "spiffe://unknown.example/workload-test"
        now = int(time.time())
        bundle = make_mock_svid_bundle(
            unknown_spiffe_id,
            iat=now,
            exp=now + 600,
        )
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        assert bundle.jwt_svid_token is not None

        with pytest.raises(
            ValueError,
            match="No trust bundle available for trust domain 'unknown.example'",
        ):
            verify_jwt_svid(bundle.jwt_svid_token, trust, _AUDIENCE)

    def test_non_jwt_svid_bundle_keys_are_rejected(self):
        now = int(time.time())
        bundle = make_mock_svid_bundle(_SPIFFE_ID, iat=now, exp=now + 600)
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        for key in trust.jwks["keys"]:
            key["use"] = "sig"

        with pytest.raises(ValueError, match="does not contain JWT-SVID"):
            verify_jwt_svid(bundle.jwt_svid_token, trust, _AUDIENCE)

    def test_x509_svid_only_bundle_keys_are_rejected(self):
        now = int(time.time())
        bundle = make_mock_svid_bundle(_SPIFFE_ID, iat=now, exp=now + 600)
        trust = make_mock_trust_bundle(_SPIFFE_ID)
        jwt_key = next(
            dict(key) for key in trust.jwks["keys"] if key.get("use") == "jwt-svid"
        )
        jwt_key["use"] = "x509-svid"
        trust.jwks = {"keys": [jwt_key]}
        assert bundle.jwt_svid_token is not None

        with pytest.raises(ValueError, match="does not contain JWT-SVID"):
            verify_jwt_svid(bundle.jwt_svid_token, trust, _AUDIENCE)

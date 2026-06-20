"""Regression tests for vibap.training_attestation.verify_bundle.

Round-5 audit (FIX-R6-3, 2026-04-29) flagged that ``verify_bundle`` had
NO test file at all. The round-5 fix made the future-iat check
unconditional (was gated on ``max_age_s is not None``), but a refactor
that re-gates it would not be caught by any existing test. These tests
close that gap.

Coverage:
- happy path: well-formed bundle verifies cleanly
- future-iat regression: a link with signed_at far in the future is
  rejected even when max_age_s is not set (the round-5 default-fix)
- chain-linkage regression: tampered predecessor_hash → INVALID
- empty bundle: zero links → INVALID
"""

from __future__ import annotations

import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from vibap.training_attestation import (
    AttestationBundle,
    InMemorySignerRegistry,
    sign_link,
    verify_bundle,
)


def _gen_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def _make_link(
    *,
    role: str,
    signer_spiffe_id: str,
    materials_root: str,
    predecessor_hash: str,
    private_key,
    key_id: str,
    signed_at: int | None = None,
    extra: dict[str, Any] | None = None,
):
    return sign_link(
        role=role,
        signer_spiffe_id=signer_spiffe_id,
        materials_root=materials_root,
        predecessor_hash=predecessor_hash,
        private_key=private_key,
        key_id=key_id,
        extra=extra,
        signed_at=signed_at,
    )


class TestVerifyBundleHappyPath:
    def test_well_formed_single_link_bundle_verifies(self):
        priv, pub = _gen_keypair()
        registry = InMemorySignerRegistry()
        registry.register("kid-1", pub)

        link = _make_link(
            role="dataset-curator",
            signer_spiffe_id="spiffe://example.org/curator",
            materials_root="abc123",
            predecessor_hash="",
            private_key=priv,
            key_id="kid-1",
        )
        bundle = AttestationBundle(links=(link,))
        verdict = verify_bundle(bundle, resolver=registry)
        assert verdict.verdict == "VALID", verdict.reason


class TestVerifyBundleFutureIatGuard:
    """FIX-R5-H6 + FIX-R6-3 (round-5 + round-6, 2026-04-28/29).

    Before round-5, the future-iat check inside ``verify_bundle`` only
    fired when the caller passed ``max_age_s``. Default ``max_age_s=None``
    accepted ``signed_at=year_3000`` indefinitely. Round-5 made the
    check unconditional. This test pins that contract.
    """

    def test_far_future_signed_at_rejected_with_default_max_age(self):
        priv, pub = _gen_keypair()
        registry = InMemorySignerRegistry()
        registry.register("kid-future", pub)
        far_future = int(time.time()) + 365 * 86400
        link = _make_link(
            role="dataset-curator",
            signer_spiffe_id="spiffe://example.org/curator",
            materials_root="abc123",
            predecessor_hash="",
            private_key=priv,
            key_id="kid-future",
            signed_at=far_future,
        )
        bundle = AttestationBundle(links=(link,))
        # No max_age_s passed → default None. Round-5's contract:
        # future-iat check still fires.
        verdict = verify_bundle(bundle, resolver=registry)
        assert verdict.verdict == "INVALID"
        assert "future" in verdict.reason

    def test_slight_future_within_60s_tolerance_accepted(self):
        """The future-skew bound is 60s; clock drift within that
        envelope must not false-positive."""
        priv, pub = _gen_keypair()
        registry = InMemorySignerRegistry()
        registry.register("kid-slight", pub)
        slight_future = int(time.time()) + 30  # within 60s
        link = _make_link(
            role="dataset-curator",
            signer_spiffe_id="spiffe://example.org/curator",
            materials_root="abc123",
            predecessor_hash="",
            private_key=priv,
            key_id="kid-slight",
            signed_at=slight_future,
        )
        bundle = AttestationBundle(links=(link,))
        verdict = verify_bundle(bundle, resolver=registry)
        assert verdict.verdict == "VALID", verdict.reason


class TestVerifyBundleChainLinkage:
    def test_tampered_predecessor_hash_rejected(self):
        priv, pub = _gen_keypair()
        registry = InMemorySignerRegistry()
        registry.register("kid-chain", pub)

        link0 = _make_link(
            role="curator",
            signer_spiffe_id="spiffe://example.org/curator",
            materials_root="root-0",
            predecessor_hash="",
            private_key=priv,
            key_id="kid-chain",
        )
        link1 = _make_link(
            role="trainer",
            signer_spiffe_id="spiffe://example.org/trainer",
            materials_root="root-1",
            # WRONG predecessor — should be link0.canonical_hash()
            predecessor_hash="0" * 64,
            private_key=priv,
            key_id="kid-chain",
        )
        bundle = AttestationBundle(links=(link0, link1))
        verdict = verify_bundle(bundle, resolver=registry)
        assert verdict.verdict == "INVALID"
        # Either "predecessor" or "linkage" or "chain" is acceptable —
        # the test pins the rejection, not the exact message.
        assert any(
            term in verdict.reason.lower()
            for term in ("predecessor", "chain", "link", "hash")
        ), f"unexpected rejection reason: {verdict.reason}"


class TestVerifyBundleEmpty:
    def test_empty_bundle_rejected(self):
        registry = InMemorySignerRegistry()
        bundle = AttestationBundle(links=())
        verdict = verify_bundle(bundle, resolver=registry)
        assert verdict.verdict == "INVALID"

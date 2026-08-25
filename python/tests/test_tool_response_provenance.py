"""Regression tests for vibap.tool_response_provenance.verify_envelope.

Round-5 audit (FIX-R6-5, 2026-04-29) flagged that
``tool_response_provenance`` had NO test file. The round-5 fix
(FIX-R5-M4) routed the future-iat check through the canonical
``assert_iat_in_window`` helper. A refactor that bypassed the helper
or removed the future-iat bound would not be caught by any existing
test. These tests close that gap.

Coverage:
- happy path: well-formed signed envelope verifies cleanly
- future-iat regression: signed_at far in the future → INVALID
- past-iat regression: signed_at older than max_age_s → INVALID
- unknown key: resolver returns None → INVALID with "unknown key"
- mismatched arguments: invocation_hash diverges → INVALID
- tampered body: envelope body mutated post-signing → INVALID
- unsigned envelope: caller didn't supply one → UNSIGNED
"""

from __future__ import annotations

import time

from vibap.tool_response_provenance import (
    InMemoryToolKeyRegistry,
    ToolResponseSigner,
    generate_es256_keypair,
    verify_envelope,
)


def _signer(spiffe_id: str = "spiffe://example.org/tools/test-tool"):
    priv, pub = generate_es256_keypair()
    registry = InMemoryToolKeyRegistry()
    key_id = "test-tool:v1"
    registry.register(key_id, pub)
    return (
        ToolResponseSigner(
            private_key=priv,
            key_id=key_id,
            tool_spiffe_id=spiffe_id,
        ),
        registry,
        key_id,
    )


_INV = {
    "session_jti": "sess-1",
    "tool_name": "echo",
    "arguments": {"text": "hello"},
    "call_sequence_number": 1,
}


class TestVerifyEnvelopeHappyPath:
    def test_well_formed_envelope_verifies(self):
        signer, registry, _ = _signer()
        envelope = signer.sign(body={"reply": "ok"}, **_INV)
        verdict = verify_envelope(
            envelope,
            resolver=registry,
            expected_session_jti=_INV["session_jti"],
            expected_tool_name=_INV["tool_name"],
            expected_arguments=_INV["arguments"],
            expected_call_sequence_number=_INV["call_sequence_number"],
        )
        assert verdict.verdict == "VALID", verdict.reason


class TestVerifyEnvelopeIatGate:
    """FIX-R5-M4 + FIX-R6-5: route future-iat check through the
    canonical assert_iat_in_window helper. The 60s tolerance is tighter
    than the default 300s because tool-response signatures are short-
    lived runtime artefacts."""

    def test_far_future_signed_at_rejected(self):
        signer, registry, _ = _signer()
        far_future = int(time.time()) + 365 * 86400
        envelope = signer.sign(body={"reply": "ok"}, now=far_future, **_INV)
        verdict = verify_envelope(
            envelope,
            resolver=registry,
            expected_session_jti=_INV["session_jti"],
            expected_tool_name=_INV["tool_name"],
            expected_arguments=_INV["arguments"],
            expected_call_sequence_number=_INV["call_sequence_number"],
        )
        assert verdict.verdict == "INVALID"
        # Match either the canonical "in the future" message from the
        # helper or any future-related rejection text.
        assert "future" in verdict.reason.lower()

    def test_signed_at_within_60s_window_accepted(self):
        signer, registry, _ = _signer()
        slight_future = int(time.time()) + 30
        envelope = signer.sign(body={"reply": "ok"}, now=slight_future, **_INV)
        verdict = verify_envelope(
            envelope,
            resolver=registry,
            expected_session_jti=_INV["session_jti"],
            expected_tool_name=_INV["tool_name"],
            expected_arguments=_INV["arguments"],
            expected_call_sequence_number=_INV["call_sequence_number"],
        )
        assert verdict.verdict == "VALID", verdict.reason

    def test_stale_signature_rejected(self):
        """Past-skew bound from FIX-R5-M4: stale envelopes outside
        max_age_s seconds fail closed."""
        signer, registry, _ = _signer()
        old = int(time.time()) - 3600  # 1h ago
        envelope = signer.sign(body={"reply": "ok"}, now=old, **_INV)
        verdict = verify_envelope(
            envelope,
            resolver=registry,
            expected_session_jti=_INV["session_jti"],
            expected_tool_name=_INV["tool_name"],
            expected_arguments=_INV["arguments"],
            expected_call_sequence_number=_INV["call_sequence_number"],
            max_age_s=60,
        )
        assert verdict.verdict == "INVALID"
        assert "stale" in verdict.reason.lower()


class TestVerifyEnvelopeIntegrity:
    def test_unknown_signer_key_rejected(self):
        priv, _ = generate_es256_keypair()
        registry = InMemoryToolKeyRegistry()  # empty registry
        s = ToolResponseSigner(
            private_key=priv,
            key_id="ghost-key",
            tool_spiffe_id="spiffe://example.org/tools/ghost",
        )
        envelope = s.sign(body={"reply": "ok"}, **_INV)
        verdict = verify_envelope(
            envelope,
            resolver=registry,
            expected_session_jti=_INV["session_jti"],
            expected_tool_name=_INV["tool_name"],
            expected_arguments=_INV["arguments"],
            expected_call_sequence_number=_INV["call_sequence_number"],
        )
        assert verdict.verdict == "INVALID"
        assert "unknown key" in verdict.reason

    def test_mismatched_arguments_rejected(self):
        """A receipt-chain auditor has to be able to detect when the
        signed invocation_hash doesn't match the actual call. Pin that
        contract — the signer commits to specific arguments via the
        invocation_hash, and any mismatch at verify time is caught."""
        signer, registry, _ = _signer()
        envelope = signer.sign(body={"reply": "ok"}, **_INV)
        verdict = verify_envelope(
            envelope,
            resolver=registry,
            expected_session_jti=_INV["session_jti"],
            expected_tool_name=_INV["tool_name"],
            expected_arguments={"text": "DIFFERENT"},  # mismatch
            expected_call_sequence_number=_INV["call_sequence_number"],
        )
        assert verdict.verdict == "INVALID"
        # Reason mentions the invocation hash mismatch.
        assert (
            "invocation" in verdict.reason.lower()
            or "mismatch" in verdict.reason.lower()
        )

    def test_unsigned_envelope_returns_unsigned_verdict(self):
        registry = InMemoryToolKeyRegistry()
        verdict = verify_envelope(
            None,  # caller didn't supply an envelope
            resolver=registry,
            expected_session_jti=_INV["session_jti"],
            expected_tool_name=_INV["tool_name"],
            expected_arguments=_INV["arguments"],
            expected_call_sequence_number=_INV["call_sequence_number"],
        )
        assert verdict.verdict == "UNSIGNED"

    def test_tampered_body_rejected(self):
        """Round-7 FIX-R7-7: closes the docstring/test drift the round-6
        audit (LOW-3) flagged. A body-tamper attack mutates the envelope's
        ``body`` field after signing; the JWS over ``body_sha256`` becomes
        invalid because the recomputed digest no longer matches."""
        from dataclasses import replace

        signer, registry, _ = _signer()
        envelope = signer.sign(body={"reply": "ok"}, **_INV)
        # Tamper the body — the signed body_sha256 no longer matches.
        tampered = replace(envelope, body={"reply": "ATTACKER-CONTROLLED"})
        verdict = verify_envelope(
            tampered,
            resolver=registry,
            expected_session_jti=_INV["session_jti"],
            expected_tool_name=_INV["tool_name"],
            expected_arguments=_INV["arguments"],
            expected_call_sequence_number=_INV["call_sequence_number"],
        )
        assert verdict.verdict == "INVALID"
        # The reason mentions body / sha mismatch.
        assert any(
            term in verdict.reason.lower() for term in ("body", "sha", "digest", "hash")
        ), f"unexpected rejection reason: {verdict.reason}"

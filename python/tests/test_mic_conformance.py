"""Verifier contract conformance tests — MIC-State and MIC-Evidence checks.

Closes the 4 design-only gaps identified by the deep review:
- Manifest digest comparison (§9.6)
- Envelope signature verification (§9.5)
- Visibility check (§6.4)
- last_seen_receipts tracking (§5.7)
- Hidden-hop detection (§9.1)
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from vibap.denial import DenialReason
from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import Decision, GovernanceProxy

from tests.conftest import v01_required_md_extras

DIGEST = "sha-256:" + hashlib.sha256(b"test-manifest").hexdigest()
WRONG_DIGEST = "sha-256:" + hashlib.sha256(b"wrong-manifest").hexdigest()
FAKE_PARENT_JTI = "fake-parent-" + uuid.uuid4().hex[:12]
FAKE_MISSION_ID = "urn:ardur:mission:mic-test:" + uuid.uuid4().hex[:8]

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _issue_passport(
    private_key,
    *,
    conformance_profile: str = "Delegation-Core",
    tool_manifest_digest: str | None = None,
    parent_jti: str | None = None,
    mission_id: str | None = None,
    allowed_tools: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Issue a passport. ``tool_manifest_digest=None`` means use the
    v01_required_md_extras default; pass an explicit string to override;
    pass ``""`` to remove it from claims entirely."""
    mission = MissionPassport(
        agent_id="mic-test-agent",
        mission="MIC conformance test",
        allowed_tools=allowed_tools or ["read_file", "write_file"],
        forbidden_tools=["delete_file"],
        resource_scope=[],
        max_tool_calls=10,
        max_duration_s=60,
    )
    extras = v01_required_md_extras(
        mission_id=mission_id or FAKE_MISSION_ID,
        conformance_profile=conformance_profile,
    )
    if tool_manifest_digest is not None:
        if tool_manifest_digest:
            extras["tool_manifest_digest"] = tool_manifest_digest
        else:
            extras.pop("tool_manifest_digest", None)
    if extra:
        extras.update(extra)
    return issue_passport(mission, private_key, ttl_s=60, extra_claims=extras)


def _base_telemetry() -> dict[str, Any]:
    return {
        "action_class": "read",
        "tool_name": "read_file",
        "target": "/tmp/test.txt",
        "resource_family": "filesystem",
        "content_class": "text",
        "content_provenance": {"source": "local"},
        "side_effect_class": "none",
        "visibility": "full",
        "sensitivity": "low",
        "instruction_bearing": False,
        "budget_delta": {"delta": 1, "effect_class": "read"},
        "envelope_signature_valid": True,
        "observed_manifest_digest": DIGEST,
    }


def _call(proxy, session, **overrides) -> tuple[Decision, str]:
    args = _base_telemetry()
    args.update(overrides)
    return proxy.evaluate_tool_call(session, "read_file", args)


def _inject_parent(session, proxy, parent_jti: str) -> None:
    """Add parent_jti and a minimal delegation_chain to a session's claims,
    then persist so evaluate_tool_call's disk reload picks it up."""
    session.passport_claims["parent_jti"] = parent_jti
    session.passport_claims["delegation_chain"] = [{"jti": parent_jti}]
    proxy._persist_session(session)


# ---------------------------------------------------------------------------
# Manifest Digest (§9.6)
# ---------------------------------------------------------------------------


class TestManifestDigestCheck:
    def test_match_permitted(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest=DIGEST,
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session)
        assert decision == Decision.PERMIT

    def test_mismatch_denied(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest=DIGEST,
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, observed_manifest_digest=WRONG_DIGEST)
        assert decision == Decision.VIOLATION
        assert "manifest_drift" in reason

    def test_missing_denied(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest=DIGEST,
        )
        session = proxy.start_session(token)
        args = _base_telemetry()
        del args["observed_manifest_digest"]
        decision, reason = proxy.evaluate_tool_call(session, "read_file", args)
        assert decision == Decision.VIOLATION
        assert "manifest_drift" in reason

    def test_absent_from_md_skipped(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session)
        assert decision == Decision.PERMIT

    def test_delegation_core_skips(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="Delegation-Core",
            tool_manifest_digest=DIGEST,
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, observed_manifest_digest=WRONG_DIGEST)
        assert decision == Decision.PERMIT


# ---------------------------------------------------------------------------
# Envelope Signature (§9.5)
# ---------------------------------------------------------------------------


class TestEnvelopeSignatureCheck:
    def test_true_permitted(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, envelope_signature_valid=True)
        assert decision == Decision.PERMIT

    def test_false_denied(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, envelope_signature_valid=False)
        assert decision == Decision.VIOLATION
        assert "envelope_tampered" in reason

    def test_missing_denied(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        args = _base_telemetry()
        del args["envelope_signature_valid"]
        decision, reason = proxy.evaluate_tool_call(session, "read_file", args)
        assert decision == Decision.VIOLATION
        assert "envelope_tampered" in reason

    def test_truthy_string_rejected(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, envelope_signature_valid="true")
        assert decision == Decision.VIOLATION

    def test_delegation_core_skips(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="Delegation-Core",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, envelope_signature_valid=False)
        assert decision == Decision.PERMIT


# ---------------------------------------------------------------------------
# Visibility Check (§6.4)
# ---------------------------------------------------------------------------


class TestVisibilityCheck:
    def test_full_permitted(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, visibility="full")
        assert decision == Decision.PERMIT

    def test_partial_denied(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, visibility="partial")
        assert decision == Decision.INSUFFICIENT_EVIDENCE

    def test_hidden_denied(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, visibility="hidden")
        assert decision == Decision.INSUFFICIENT_EVIDENCE

    def test_missing_denied(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        args = _base_telemetry()
        del args["visibility"]
        decision, reason = proxy.evaluate_tool_call(session, "read_file", args)
        assert decision == Decision.INSUFFICIENT_EVIDENCE

    def test_delegation_core_skips(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="Delegation-Core",
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, visibility="hidden")
        assert decision == Decision.PERMIT


# ---------------------------------------------------------------------------
# last_seen_receipts Tracking (§5.7)
# ---------------------------------------------------------------------------


class TestLastSeenReceiptsTracking:
    def test_receipt_updates_last_seen(self, proxy, private_key):
        token = _issue_passport(private_key)
        session = proxy.start_session(token)
        _call(proxy, session)

        grant_id = session.jti
        with proxy._last_seen_receipts_lock:
            assert grant_id in proxy._last_seen_receipts
            assert proxy._last_seen_receipts[grant_id]

    def test_tracks_correct_grant_id(self, proxy, private_key):
        token = _issue_passport(private_key)
        session = proxy.start_session(token)
        _call(proxy, session)

        grant_id = session.jti
        receipts = _read_receipts(proxy.receipts_log_path)
        assert len(receipts) == 1
        assert receipts[0]["grant_id"] == grant_id
        with proxy._last_seen_receipts_lock:
            assert proxy._last_seen_receipts[grant_id] == receipts[0]["receipt_id"]

    def test_independent_sessions_tracked(self, proxy, private_key):
        t1 = _issue_passport(private_key, mission_id="urn:ardur:mission:mic:a")
        t2 = _issue_passport(private_key, mission_id="urn:ardur:mission:mic:b")
        s1 = proxy.start_session(t1)
        s2 = proxy.start_session(t2)
        _call(proxy, s1)
        _call(proxy, s2)

        with proxy._last_seen_receipts_lock:
            assert s1.jti in proxy._last_seen_receipts
            assert s2.jti in proxy._last_seen_receipts
            assert proxy._last_seen_receipts[s1.jti] != proxy._last_seen_receipts[s2.jti]

    def test_parent_receipt_required_for_child(self, proxy, private_key):
        # Inject parent_jti + delegation_chain into claims after session
        # start to avoid triggering delegation_chain validation in
        # verify_passport. Must persist because evaluate_tool_call reloads
        # from disk.
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-Evidence",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        _inject_parent(session, proxy, FAKE_PARENT_JTI)
        decision, reason = _call(proxy, session)
        assert decision == Decision.INSUFFICIENT_EVIDENCE
        assert "missing_parent_receipt" in reason


# ---------------------------------------------------------------------------
# Hidden-Hop Detection (§9.1)
# ---------------------------------------------------------------------------


class TestHiddenHopDetection:
    def test_root_no_hidden_hop(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-Evidence",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        proxy._seed_lineage_parent_cache(session.passport_claims)
        decision, reason = _call(proxy, session)
        assert decision == Decision.PERMIT

    def test_child_with_known_parent_no_hidden_hop(self, proxy, private_key):
        parent_token = _issue_passport(
            private_key,
            conformance_profile="MIC-Evidence",
            tool_manifest_digest="",
            mission_id="urn:ardur:mission:mic:parent-hop",
        )
        parent_session = proxy.start_session(parent_token)
        parent_jti = parent_session.jti

        child_token = _issue_passport(
            private_key,
            conformance_profile="MIC-Evidence",
            tool_manifest_digest="",
            mission_id="urn:ardur:mission:mic:child-hop",
        )
        child_session = proxy.start_session(child_token)
        _inject_parent(child_session, proxy, parent_jti)

        # Seed lineage cache so parent is known
        proxy._remember_lineage_parent(parent_jti, None)
        proxy._remember_lineage_parent(child_session.jti, parent_jti)

        # Produce parent receipt so missing_parent_receipt check also passes
        _call(proxy, parent_session)

        decision, reason = _call(proxy, child_session)
        assert decision == Decision.PERMIT

    def test_child_with_unknown_parent_hidden_hop(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-Evidence",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        _inject_parent(session, proxy, FAKE_PARENT_JTI)
        decision, reason = _call(proxy, session)
        assert decision == Decision.INSUFFICIENT_EVIDENCE
        assert "missing_parent_receipt" in reason

    def test_mic_state_skips_hidden_hop(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        _inject_parent(session, proxy, FAKE_PARENT_JTI)
        decision, reason = _call(proxy, session)
        assert decision == Decision.PERMIT


# ---------------------------------------------------------------------------
# Conformance Profile Gating
# ---------------------------------------------------------------------------


class TestConformanceProfileGating:
    def test_delegation_core_skips_all_new_checks(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="Delegation-Core",
        )
        session = proxy.start_session(token)
        _inject_parent(session, proxy, FAKE_PARENT_JTI)
        decision, reason = _call(
            proxy,
            session,
            envelope_signature_valid=False,
            observed_manifest_digest=WRONG_DIGEST,
            visibility="hidden",
        )
        assert decision == Decision.PERMIT

    def test_mic_state_applies_envelope_and_manifest(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest=DIGEST,
        )
        session = proxy.start_session(token)
        decision, reason = _call(proxy, session, envelope_signature_valid=False)
        assert decision == Decision.VIOLATION
        assert "envelope_tampered" in reason

    def test_mic_evidence_applies_all_checks(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-Evidence",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        _inject_parent(session, proxy, FAKE_PARENT_JTI)
        decision, reason = _call(proxy, session)
        assert decision == Decision.INSUFFICIENT_EVIDENCE
        assert "missing_parent_receipt" in reason

    def test_missing_profile_defaults_to_delegation_core(self, proxy, private_key):
        mission = MissionPassport(
            agent_id="no-profile-agent",
            mission="No conformance profile set",
            allowed_tools=["read_file"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=5,
            max_duration_s=60,
        )
        extras = v01_required_md_extras(mission_id="urn:ardur:mission:mic:no-profile")
        del extras["conformance_profile"]
        token = issue_passport(mission, private_key, ttl_s=60, extra_claims=extras)
        session = proxy.start_session(token)
        decision, reason = _call(
            proxy,
            session,
            envelope_signature_valid=False,
            visibility="hidden",
        )
        assert decision == Decision.PERMIT


# ---------------------------------------------------------------------------
# End-to-end: receipt contains correct denial reasons
# ---------------------------------------------------------------------------


class TestReceiptDenialReasons:
    def test_receipt_records_manifest_drift(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest=DIGEST,
        )
        session = proxy.start_session(token)
        _call(proxy, session, observed_manifest_digest=WRONG_DIGEST)

        receipts = _read_receipts(proxy.receipts_log_path)
        assert len(receipts) >= 1
        assert receipts[0]["verdict"] == "violation"
        assert receipts[0].get("internal_denial_code") == DenialReason.MANIFEST_DRIFT.value

    def test_receipt_records_envelope_tampered(self, proxy, private_key):
        token = _issue_passport(
            private_key,
            conformance_profile="MIC-State",
            tool_manifest_digest="",
        )
        session = proxy.start_session(token)
        _call(proxy, session, envelope_signature_valid=False)

        receipts = _read_receipts(proxy.receipts_log_path)
        assert len(receipts) >= 1
        assert receipts[0].get("internal_denial_code") == DenialReason.ENVELOPE_TAMPERED.value


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _read_receipts(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

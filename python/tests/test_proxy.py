"""Unit tests for GovernanceProxy core methods.

Tests session lifecycle, kill-switch, and receipt chain integrity.
Uses the same fixtures + token pattern as test_http.py.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from vibap.passport import issue_passport
from vibap.proxy import Decision, _check_resource_scope, _sanitize_value


class TestResourceScopeSecurity:
    def test_existing_symlink_escape_is_rejected_after_lexical_match(self, tmp_path):
        workspace = tmp_path / "workspace"
        outside = tmp_path / "outside"
        workspace.mkdir()
        outside.mkdir()
        (workspace / "escape").symlink_to(outside, target_is_directory=True)

        ok, reason = _check_resource_scope(
            {"file_path": str(workspace / "escape" / "stolen.txt")},
            resource_scope=[str(workspace), f"{workspace}/*"],
            cwd=str(workspace),
        )

        assert not ok
        assert "resolves outside resource_scope" in reason

    def test_relative_symlink_escape_is_rejected_against_declared_cwd(self, tmp_path):
        workspace = tmp_path / "workspace"
        outside = tmp_path / "outside"
        workspace.mkdir()
        outside.mkdir()
        (workspace / "escape").symlink_to(outside, target_is_directory=True)

        ok, reason = _check_resource_scope(
            {"file_path": "escape/stolen.txt"},
            resource_scope=[str(workspace), f"{workspace}/*"],
            cwd=str(workspace),
        )

        assert not ok
        assert "resolves outside resource_scope" in reason

    def test_dangling_symlink_escape_is_rejected_for_future_output(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "escape").symlink_to(
            tmp_path / "outside" / "missing", target_is_directory=True
        )

        ok, reason = _check_resource_scope(
            {"file_path": str(workspace / "escape" / "future.txt")},
            resource_scope=[str(workspace), f"{workspace}/*"],
            cwd=str(workspace),
        )

        assert not ok
        assert "resolves outside resource_scope" in reason

    def test_symlink_loop_fails_closed_after_lexical_match(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "loop").symlink_to(
            workspace / "loop", target_is_directory=True
        )

        ok, reason = _check_resource_scope(
            {"file_path": str(workspace / "loop" / "future.txt")},
            resource_scope=[str(workspace), f"{workspace}/*"],
            cwd=str(workspace),
        )

        assert not ok
        assert "canonical path resolution failed" in reason

    def test_symlink_that_resolves_within_scope_remains_permitted(self, tmp_path):
        workspace = tmp_path / "workspace"
        target = workspace / "target"
        target.mkdir(parents=True)
        (workspace / "alias").symlink_to(target, target_is_directory=True)

        ok, reason = _check_resource_scope(
            {"file_path": str(workspace / "alias" / "future.txt")},
            resource_scope=[str(workspace), f"{workspace}/*"],
            cwd=str(workspace),
        )

        assert ok
        assert reason == ""

    def test_path_hint_list_wrapped_bare_value_is_scope_checked(self):
        ok, reason = _check_resource_scope(
            {"directory": ["hr"]},
            resource_scope=["sales/*"],
        )

        assert not ok
        assert "hr" in reason
        assert "outside resource_scope" in reason

    def test_deep_percent_encoded_traversal_is_rejected(self):
        normalized, error = _sanitize_value(
            "%2525252E%2525252E%2525252Fetc%2525252Fpasswd"
        )

        assert error is not None
        assert ".." in error
        assert normalized == "../etc/passwd"

    def test_excessive_percent_encoding_fails_closed(self):
        import urllib.parse

        value = "../etc/passwd"
        for _ in range(12):
            value = urllib.parse.quote(value, safe="")

        normalized, error = _sanitize_value(value)

        assert error == "percent-encoding nesting exceeds maximum"
        assert normalized == value


class TestSessionLifecycle:
    def test_start_session_returns_valid_session(self, proxy, example_mission, private_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        assert session is not None
        assert hasattr(session, "jti")

    def test_start_session_sets_claims(self, proxy, example_mission, private_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        claims = session.passport_claims
        assert "allowed_tools" in claims

    def test_get_session_returns_started_session(self, proxy, example_mission, private_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        retrieved = proxy.get_session(session.jti)
        assert retrieved.jti == session.jti

    def test_get_session_invalid_id_raises(self, proxy):
        with pytest.raises(ValueError):
            proxy.get_session("not-a-uuid")

    def test_start_session_rejects_invalid_token(self, proxy):
        with pytest.raises(Exception):
            proxy.start_session("not.a.valid.token")

    def test_end_session_persists_summary(self, proxy, example_mission, private_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        result = proxy.end_session(session)
        assert isinstance(result, dict)


class TestIssueAttestationForSessionKernelEnforcement:
    """Epic A #63 / plan E3 phase b: the finalized attestation must be able to
    see kernel-level enforcement denials, not just proxy-evaluated decisions.
    """

    def test_folds_kernel_enforcement_block_into_attestation_claims(
        self, proxy, example_mission, private_key
    ):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, _reason = proxy.evaluate_tool_call(
            session,
            "read_file",
            {"path": "README.md"},
        )
        assert decision == Decision.PERMIT
        enforcement = {
            "total_events": 3,
            "verdict_counts": {"denied": 2, "compliant": 1},
            "tier_coverage": {"bpf_lsm:enforce": 3},
            "chain_digest": "deadbeef",
            "tamper_chain_start_seq": 4,
            "tamper_chain_last_seq": 6,
            "tamper_chain_digest": "feedface",
            "kill_switch_change_count": 2,
            "kill_switch_engaged_during_session": True,
            "kill_switch_evidence_gap": False,
            "lost_samples": 7,
            "lifecycle_capture": {
                "coverage_status": "degraded",
                "ringbuf_dropped": 7,
                "producer_ringbuf_dropped": 5,
                "malformed_records": 2,
                "producer_counter_evidence_gap": False,
                "daemon_queue_dropped": 0,
            },
        }

        _jwt_token, claims = proxy.issue_attestation_for_session(
            session.jti, proxy.receipt_private_key, kernel_enforcement=enforcement
        )

        assert claims["kernel_enforcement"] == enforcement
        receipts = [
            json.loads(line)
            for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(receipts) == 1
        token = receipts[0]["jwt"]
        assert claims["receipt_chain_head"] == {
            "hash_algorithm": "sha-256",
            "receipt_id": receipts[0]["receipt_id"],
            "receipt_jwt_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        }

    def test_omits_kernel_enforcement_when_none_provided(
        self, proxy, example_mission, private_key
    ):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)

        _jwt_token, claims = proxy.issue_attestation_for_session(
            session.jti, proxy.receipt_private_key
        )

        assert "kernel_enforcement" not in claims


class TestPassportVerification:
    def test_verify_valid_passport(self, proxy, example_mission, private_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        proxy.verify_passport_token(token)


class TestKillSwitch:
    def test_kill_switch_active_after_activate(self, proxy):
        assert proxy.kill_switch_active is False
        proxy.activate_kill_switch()
        assert proxy.kill_switch_active is True

    def test_deactivate_kill_switch_restores(self, proxy):
        proxy.activate_kill_switch()
        proxy.deactivate_kill_switch()
        assert proxy.kill_switch_active is False


class TestSessionCheckAndRecord:
    def test_check_and_record_basic(self, proxy, example_mission, private_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, reason, event = session.check_and_record(
            tool_name="read_file",
            arguments={"path": "/tmp/test.txt"},
        )
        assert decision == Decision.PERMIT
        assert event is not None

    def test_check_and_record_increments_counter(self, proxy, example_mission, private_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        assert session.tool_call_count == 0
        session.check_and_record(
            tool_name="read_file",
            arguments={"path": "/tmp/test.txt"},
        )
        assert session.tool_call_count == 1

    def test_tool_limit_exhausted_denies(self, proxy, example_mission, private_key):
        token = issue_passport(example_mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        max_calls = session.passport_claims.get("max_tool_calls", 5)
        for _ in range(max_calls):
            decision, _reason, _event = session.check_and_record(
                tool_name="read_file",
                arguments={"path": "/tmp/test.txt"},
            )
            assert decision == Decision.PERMIT
        # Next should be denied
        decision, _reason, _event = session.check_and_record(
            tool_name="read_file",
            arguments={"path": "/tmp/test.txt"},
        )
        assert decision != Decision.PERMIT


class TestSanitizeValueDotConfusables:
    """_sanitize_value step-2b: dot-confusable codepoints fold to ASCII '.'."""

    @pytest.mark.parametrize("dot_char", [
        "․",  # ONE DOT LEADER
        "﹒",  # SMALL FULL STOP
        "．",  # FULLWIDTH FULL STOP
    ])
    def test_single_dot_confusable_does_not_traverse(self, dot_char):
        # A single dot-confusable followed by a path: no traversal possible.
        value, reason = _sanitize_value(f"{dot_char}etc/passwd")
        # Should NOT raise; single '.' segment is harmless.
        assert reason is None

    @pytest.mark.parametrize("dot_char", [
        "․",  # ONE DOT LEADER
        "﹒",  # SMALL FULL STOP
        "．",  # FULLWIDTH FULL STOP
    ])
    def test_double_dot_confusable_is_denied(self, dot_char):
        # Two consecutive dot-confusables form a '..' traversal after fold.
        value, reason = _sanitize_value(f"{dot_char}{dot_char}/etc/passwd")
        assert reason is not None, (
            f"Expected DENY for double {repr(dot_char)}, got PERMIT"
        )
        assert ".." in reason

    def test_mixed_dot_confusables_traversal_denied(self):
        # Mixed: U+2024 + U+FF0E → ".." after fold.
        value, reason = _sanitize_value("․．/etc/passwd")
        assert reason is not None
        assert ".." in reason

    def test_absolute_scope_escape_denied(self):
        # /tmp/safe/[U+2024][U+2024]/etc/passwd — the exact threat scenario.
        value, reason = _sanitize_value("/tmp/safe/․․/etc/passwd")
        assert reason is not None, (
            "Scope-escape via dot-confusable must be caught before PERMIT"
        )


class TestSanitizeValueSingleCodepointDotDot:
    """_sanitize_value step-2c: single codepoints that NFKC-expand to '..'.

    U+2025 TWO DOT LEADER and U+FE30 PRESENTATION FORM FOR VERTICAL TWO DOT
    LEADER each decompose to a full ``..`` under NFKC in a SINGLE codepoint,
    so the step-2b per-character '.' fold cannot express them. A tool that
    NFKC-normalises before ``open()`` would turn a PERMIT'd ``‥/etc/passwd``
    into a real ``../etc/passwd``. The NFKC-form backstop must DENY these.
    """

    @pytest.mark.parametrize("dd_char", [
        "‥",   # U+2025 TWO DOT LEADER
        "︰",   # U+FE30 PRESENTATION FORM FOR VERTICAL TWO DOT LEADER
    ])
    def test_single_codepoint_dotdot_is_denied(self, dd_char):
        # A single two-dot-leader IS a '..' segment after NFKC.
        _value, reason = _sanitize_value(f"{dd_char}/etc/passwd")
        assert reason is not None, (
            f"Expected DENY for single {repr(dd_char)} (NFKC → '..'), got PERMIT"
        )

    @pytest.mark.parametrize("dd_char", [
        "‥",   # U+2025 TWO DOT LEADER
        "︰",   # U+FE30 PRESENTATION FORM FOR VERTICAL TWO DOT LEADER
    ])
    def test_single_codepoint_dotdot_scope_escape_denied(self, dd_char):
        # /tmp/safe/‥/etc/passwd — one codepoint escapes the scope root.
        _value, reason = _sanitize_value(f"/tmp/safe/{dd_char}/etc/passwd")
        assert reason is not None, (
            "Single-codepoint '..' scope-escape must be caught before PERMIT"
        )

    def test_legitimate_fullwidth_path_still_permitted(self):
        # Fullwidth letters are valid filenames; the NFKC backstop must not
        # false-DENY them (it only fires on a literal '..' segment).
        _value, reason = _sanitize_value("/tmp/safe/ｒｅｐｏｒｔ.txt")
        assert reason is None, (
            f"Legit fullwidth path wrongly denied: {reason!r}"
        )

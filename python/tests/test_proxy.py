"""Unit tests for GovernanceProxy core methods.

Tests session lifecycle, kill-switch, and receipt chain integrity.
Uses the same fixtures + token pattern as test_http.py.
"""

from __future__ import annotations

import pytest

from vibap.passport import issue_passport
from vibap.proxy import Decision, _sanitize_value


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

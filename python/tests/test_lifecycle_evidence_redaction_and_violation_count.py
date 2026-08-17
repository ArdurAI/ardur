"""Regression tests for lifecycle evidence redaction and violation count.

Three security issues are covered:

1. **Path leak in signed attestation** — ``_build_process_lifecycle_evidence``
   previously returned unredacted local paths (``command``, ``run_command``,
   ``cwd``, ``children[*].command``) which were then ES256-signed into the
   attestation token.  The fix redacts paths at the source before returning.

2. **VIOLATION verdict count silently dropped** — The ``_build_summary`` method
   counted all non-PERMIT decisions in the aggregate ``denials`` but only
   broke out ``unknowns`` / ``insufficient_evidence`` separately.  VIOLATION
   (credential compromise, chain tampering — the most severe verdict) had no
   separate field, making it indistinguishable from routine denials.  The fix
   adds ``violations`` to both ``_build_summary`` and
   ``_child_lifecycle_summary``.

3. **Missing keys on error-path child summary** — The default child summary
   dict lacked ``unknowns``, ``insufficient_evidence``, and ``violations``
   keys on error paths (child session unavailable), which would cause
   ``KeyError`` in downstream consumers expecting structural consistency.
"""

from __future__ import annotations

import time
from typing import Any

from vibap.proxy import (
    Decision,
    GovernanceProxy,
    GovernanceSession,
    PolicyEvent,
)
from vibap.run_bridge import _build_process_lifecycle_evidence


# ──────────────────────────────────────────────────────────────────────
# Fix 1: Process lifecycle evidence is redacted at the source
# ──────────────────────────────────────────────────────────────────────


class TestProcessLifecycleRedactionAtSource:
    """``_build_process_lifecycle_evidence`` must redact local paths."""

    def _build(self, **kwargs: Any) -> dict[str, Any]:
        defaults: dict[str, Any] = dict(
            proc=None,
            command=["/Users/testuser/project/script.js"],
            launch_monotonic=time.monotonic() - 1.0,
            launch_wall_clock=time.time() - 1.0,
            exit_code=0,
        )
        defaults.update(kwargs)
        return _build_process_lifecycle_evidence(**defaults)

    def test_command_redacted(self):
        """The ``command`` field must not contain ``/Users/<user>``."""
        result = self._build()
        assert "/Users/testuser" not in " ".join(result["command"]), (
            f"Command not redacted: {result['command']}"
        )

    def test_run_command_redacted(self):
        """The ``run_command`` field must not contain ``/Users/<user>``."""
        result = self._build(
            run_command=[
                "claude",
                "--plugin-dir",
                "/Users/testuser/.local/share/ardur/plugin",
            ],
        )
        assert "/Users/testuser" not in " ".join(result["run_command"]), (
            f"run_command not redacted: {result['run_command']}"
        )

    def test_cwd_redacted(self):
        """The ``cwd`` field must not contain ``/Users/<user>``."""
        result = self._build(cwd="/Users/testuser/my-project")
        assert "/Users/testuser" not in result["cwd"], (
            f"cwd not redacted: {result['cwd']}"
        )

    def test_tmp_cwd_redacted(self):
        """The ``cwd`` field under ``/tmp`` must be redacted."""
        result = self._build(cwd="/tmp/ardur-run-abc")
        assert "/tmp/ardur-run-abc" not in result["cwd"], (
            f"cwd /tmp not redacted: {result['cwd']}"
        )

    def test_children_command_redacted(self, monkeypatch):
        """Child process commands must also be redacted."""
        fake_children = [
            {"pid": 1234, "command": ["/Users/testuser/.nvm/versions/node/bin", "node"]},
        ]
        monkeypatch.setattr(
            "vibap.run_bridge._enumerate_child_processes",
            lambda _pid: fake_children,
        )
        result = self._build()
        assert "children" in result
        for child in result["children"]:
            assert "/Users/testuser" not in " ".join(child["command"]), (
                f"Child command not redacted: {child['command']}"
            )

    def test_redacted_payload_is_safe_for_signing(self):
        """No local path roots survive in the entire evidence dict."""
        result = self._build(
            command=["/Users/testuser/.claude/claude"],
            run_command=["claude", "--plugin-dir", "/tmp/ardur-p/"],
            cwd="/Users/testuser/work",
        )
        serialized = repr(result)
        assert "/Users/" not in serialized, f"Path leak in evidence: {serialized}"
        assert "/tmp/ardur" not in serialized, f"Temp leak in evidence: {serialized}"


# ──────────────────────────────────────────────────────────────────────
# Fix 2: VIOLATION verdict count in _build_summary
# ──────────────────────────────────────────────────────────────────────


def _make_event(decision: Decision, step_id: str = "step-1") -> PolicyEvent:
    return PolicyEvent(
        timestamp="2026-08-07T00:00:00Z",
        step_id=step_id,
        actor="agent",
        verifier_id="test-verifier",
        tool_name="Bash",
        arguments={},
        action_class="exec",
        target="target",
        resource_family="shell",
        side_effect_class="process",
        decision=decision,
        reason="test",
        passport_jti="jti-1",
    )


class TestViolationCountInSummary:
    """``_build_summary`` must include a ``violations`` field."""

    def test_violation_counted_separately(self, tmp_path):
        """A VIOLATION decision must appear in ``violations`` count."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        session = GovernanceSession(
            passport_token="token",
            passport_claims={"jti": "jti-1", "sub": "agent", "mission": "test"},
            events=[
                _make_event(Decision.PERMIT, "s1"),
                _make_event(Decision.VIOLATION, "s2"),
                _make_event(Decision.VIOLATION, "s3"),
            ],
        )
        summary = proxy._build_summary(session)
        assert summary["violations"] == 2, (
            f"Expected violations=2, got {summary.get('violations')}"
        )
        # VIOLATION is also counted in denials (fail-closed aggregate)
        assert summary["denials"] == 2

    def test_violation_distinguishable_from_deny(self, tmp_path):
        """A session with 1 DENY + 1 VIOLATION must report both counts."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        session = GovernanceSession(
            passport_token="token",
            passport_claims={"jti": "jti-1", "sub": "agent", "mission": "test"},
            events=[
                _make_event(Decision.PERMIT, "s1"),
                _make_event(Decision.DENY, "s2"),
                _make_event(Decision.VIOLATION, "s3"),
            ],
        )
        summary = proxy._build_summary(session)
        assert summary["violations"] == 1
        assert summary["denials"] == 2  # DENY + VIOLATION aggregate
        # An auditor can compute: pure_denials = denials - violations - unknowns - insufficient_evidence
        pure_denials = (
            summary["denials"]
            - summary["violations"]
            - summary["unknowns"]
            - summary["insufficient_evidence"]
        )
        assert pure_denials == 1

    def test_zero_violations_for_clean_session(self, tmp_path):
        """A session with only PERMITs must report violations=0."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        session = GovernanceSession(
            passport_token="token",
            passport_claims={"jti": "jti-1", "sub": "agent", "mission": "test"},
            events=[_make_event(Decision.PERMIT, "s1")],
        )
        summary = proxy._build_summary(session)
        assert summary["violations"] == 0


# ──────────────────────────────────────────────────────────────────────
# Fix 2+3: VIOLATION count in child lifecycle + structural consistency
# ──────────────────────────────────────────────────────────────────────


def _make_child_session(
    events: list[PolicyEvent],
    summary: dict[str, Any] | None = None,
) -> GovernanceSession:
    return GovernanceSession(
        passport_token="child-token",
        passport_claims={
            "jti": "child-jti-1",
            "sub": "child-agent",
            "mission": "child mission",
        },
        events=events,
        summary=summary,
    )


_CHILD_RECORD = {
    "child_jti": "child-jti-1",
    "parent_jti": "parent-jti",
    "child_agent_id": "child-agent",
    "child_mission": "child mission",
    "child_allowed_tools": ["Bash"],
    "child_tool_scope_mode": "allowlist",
    "child_forbidden_tools": [],
    "child_max_tool_calls": 10,
    "delegated_budget_reserved": 0,
}


class TestViolationCountInChildLifecycle:
    """``_child_lifecycle_summary`` must propagate ``violations``."""

    def test_violation_propagated_from_child_events(self, tmp_path):
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        child_events = [
            _make_event(Decision.PERMIT, "s1"),
            _make_event(Decision.VIOLATION, "s2"),
        ]
        proxy.sessions["child-jti-1"] = _make_child_session(child_events)
        result = proxy._child_lifecycle_summary(dict(_CHILD_RECORD))
        assert result["violations"] == 1, (
            f"Expected violations=1, got {result.get('violations')}"
        )

    def test_violation_propagated_from_precomputed_summary(self, tmp_path):
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        precomputed = {
            "type": "session_end",
            "jti": "child-jti-1",
            "agent": "child-agent",
            "mission": "child mission",
            "total_events": 5,
            "permits": 2,
            "denials": 3,
            "unknowns": 0,
            "insufficient_evidence": 0,
            "violations": 3,
            "elapsed_s": 1.5,
            "scope_compliance": "violated",
            "delegation_count": 0,
            "children_spawned": 0,
            "child_jtis": [],
            "delegated_budget_reserved": 0,
        }
        proxy.sessions["child-jti-1"] = _make_child_session([], summary=precomputed)
        result = proxy._child_lifecycle_summary(dict(_CHILD_RECORD))
        assert result["violations"] == 3


class TestChildSummaryStructuralConsistency:
    """Default child summary must include all verdict keys on error paths."""

    def test_missing_child_jti_has_all_verdict_keys(self, tmp_path):
        """When child_jti is missing, all verdict keys default to 0."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        record = dict(_CHILD_RECORD)
        record["child_jti"] = ""
        result = proxy._child_lifecycle_summary(record)
        assert "unknowns" in result
        assert "insufficient_evidence" in result
        assert "violations" in result
        assert result["unknowns"] == 0
        assert result["insufficient_evidence"] == 0
        assert result["violations"] == 0

    def test_child_session_unavailable_has_all_verdict_keys(self, tmp_path):
        """When child session lookup fails, all verdict keys default to 0."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        # Do NOT register child-jti-1 → get_session will raise
        record = dict(_CHILD_RECORD)
        result = proxy._child_lifecycle_summary(record)
        assert "unknowns" in result
        assert "insufficient_evidence" in result
        assert "violations" in result
        assert result["unknowns"] == 0
        assert result["insufficient_evidence"] == 0
        assert result["violations"] == 0
        # Exception must be sanitized (type name only, not raw message)
        assert "error" in result
        assert "child session unavailable" in result["error"]


class TestExceptionSanitization:
    """Child lifecycle error must not embed raw exception strings."""

    def test_error_uses_type_name_not_raw_message(self, tmp_path):
        """Error message must use ``type(exc).__name__``, not ``str(exc)``."""
        proxy = GovernanceProxy(
            state_dir=tmp_path / "state",
            log_path=tmp_path / "log" / "proxy.log",
            keys_dir=tmp_path / "keys",
        )
        record = dict(_CHILD_RECORD)
        result = proxy._child_lifecycle_summary(record)
        assert "error" in result
        # The error should NOT contain the full exception repr/message
        # which could leak internal state.  It should use the type name.
        error_str = result["error"]
        assert "child session unavailable:" in error_str
        # Should not contain dict repr, traceback, or path-like content
        assert "{" not in error_str
        assert "/" not in error_str or "<" in error_str  # allow placeholder paths

"""Tests for scope-compliance and elapsed-time in ``format_summary()``.

The governance summary dict produced by ``proxy._build_summary()`` includes
``scope_compliance`` (full / violated) and ``elapsed_s`` (session wall-clock
seconds).  Previously these were visible in ``--json`` output but invisible
in the human-readable summary.  Now:

* A ``scope`` line shows the compliance status right after ``tool calls``.
* An ``elapsed`` line shows the session duration before notes.

These tests do not exercise live providers, credentials, or network calls.
"""

from __future__ import annotations

from vibap.run_bridge import GovernanceRunResult, format_summary


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_result(
    *,
    scope_compliance: str | None = "full",
    elapsed_s: float | int | None = 1.5,
    permits: int = 0,
    denials: int = 0,
    notes: list[str] | None = None,
) -> GovernanceRunResult:
    """Build a minimal ``GovernanceRunResult`` for summary-formatting tests."""
    summary: dict[str, object] = {"delegation_count": 0}
    if scope_compliance is not None:
        summary["scope_compliance"] = scope_compliance
    if elapsed_s is not None:
        summary["elapsed_s"] = elapsed_s
    return GovernanceRunResult(
        exit_code=0,
        session_id="test-session",
        mission_id="test-mission",
        agent_id="test-agent",
        adapter="claude",
        via="env",
        proxy_url="http://127.0.0.1:0",
        home="/tmp/ardur-test",
        passport_path="/tmp/ardur-test/passport.json",
        summary=summary,
        permits=permits,
        denials=denials,
        total_events=permits + denials,
        attestation_token="dummy-token-placeholder",
        attestation_digest="sha256:abc123",
        receipts_path="/tmp/ardur-test/receipts.jsonl",
        receipt_count=0,
        correlation={"reason": "none"},
        kernel_policy={"reason": "none"},
        notes=notes or [],
    )


# ---------------------------------------------------------------------------
# scope line
# ---------------------------------------------------------------------------

class TestScopeLine:
    """The ``scope`` line renders the session compliance status."""

    def test_scope_full(self):
        result = _make_result(scope_compliance="full", permits=5)
        out = format_summary(result)
        assert "scope" in out
        assert "full" in out

    def test_scope_violated(self):
        result = _make_result(scope_compliance="violated", denials=2)
        out = format_summary(result)
        assert "scope" in out
        assert "violated" in out

    def test_scope_unknown_when_absent(self):
        result = _make_result(scope_compliance=None, permits=1)
        out = format_summary(result)
        assert "scope" in out
        assert "unknown" in out

    def test_scope_unknown_for_unrecognized_value(self):
        result = _make_result(scope_compliance="bogus", permits=1)
        out = format_summary(result)
        assert "scope" in out
        assert "unknown" in out

    def test_scope_appears_after_tool_calls(self):
        result = _make_result(permits=3)
        out = format_summary(result)
        tool_idx = out.find("tool calls")
        scope_idx = out.find("scope")
        assert tool_idx != -1
        assert scope_idx != -1
        assert scope_idx > tool_idx

    def test_scope_appears_before_receipts(self):
        result = _make_result(permits=3)
        out = format_summary(result)
        scope_idx = out.find("scope")
        receipts_idx = out.find("receipts")
        assert scope_idx != -1
        assert receipts_idx != -1
        assert scope_idx < receipts_idx


# ---------------------------------------------------------------------------
# elapsed line
# ---------------------------------------------------------------------------

class TestElapsedLine:
    """The ``elapsed`` line renders the session wall-clock duration."""

    def test_elapsed_present(self):
        result = _make_result(elapsed_s=2.5)
        out = format_summary(result)
        assert "elapsed" in out
        assert "2.500s" in out

    def test_elapsed_zero(self):
        result = _make_result(elapsed_s=0)
        out = format_summary(result)
        assert "elapsed" in out
        assert "0.000s" in out

    def test_elapsed_fractional(self):
        result = _make_result(elapsed_s=0.123)
        out = format_summary(result)
        assert "elapsed" in out
        assert "0.123s" in out

    def test_elapsed_absent_when_missing(self):
        result = _make_result(elapsed_s=None, permits=1)
        out = format_summary(result)
        assert "elapsed" not in out

    def test_elapsed_absent_for_non_numeric(self):
        """Non-numeric elapsed_s is ignored gracefully."""
        result = _make_result(permits=1)
        result.summary["elapsed_s"] = "not-a-number"
        out = format_summary(result)
        assert "elapsed" not in out

    def test_elapsed_appears_before_notes(self):
        result = _make_result(elapsed_s=1.0, notes=["hello"])
        out = format_summary(result)
        elapsed_idx = out.find("elapsed")
        note_idx = out.find("hello")
        assert elapsed_idx != -1
        assert note_idx != -1
        assert elapsed_idx < note_idx


# ---------------------------------------------------------------------------
# integration: scope + elapsed coexist
# ---------------------------------------------------------------------------

class TestScopeElapsedIntegration:
    """Scope and elapsed lines coexist with other summary fields."""

    def test_scope_and_elapsed_together(self):
        result = _make_result(
            scope_compliance="violated",
            elapsed_s=3.14,
            permits=3,
            denials=1,
        )
        out = format_summary(result)
        assert "scope" in out
        assert "violated" in out
        assert "elapsed" in out
        assert "3.140s" in out

    def test_scope_violated_with_verdicts(self):
        result = _make_result(
            scope_compliance="violated",
            elapsed_s=2.0,
            denials=3,
            notes=None,
        )
        result.summary["unknowns"] = 1
        result.summary["violations"] = 2
        out = format_summary(result)
        assert "scope" in out
        assert "violated" in out
        assert "verdicts" in out
        assert "elapsed" in out

    def test_full_output_structure(self):
        """All summary lines appear in the correct order."""
        result = _make_result(
            scope_compliance="violated",
            elapsed_s=5.0,
            permits=2,
            denials=1,
            notes=["watch this"],
        )
        result.summary["delegation_count"] = 1
        result.summary["children_spawned"] = 1
        result.summary["unknowns"] = 1
        out = format_summary(result)
        lines = out.splitlines()
        # Verify key labels appear in expected order
        scope_line = next(i for i, l in enumerate(lines) if "scope" in l)
        delegations_line = next(i for i, l in enumerate(lines) if "delegations" in l)
        verdicts_line = next(i for i, l in enumerate(lines) if "verdicts" in l)
        elapsed_line = next(i for i, l in enumerate(lines) if "elapsed" in l)
        note_line = next(i for i, l in enumerate(lines) if "watch this" in l)
        assert scope_line < delegations_line < verdicts_line < elapsed_line < note_line

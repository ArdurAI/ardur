"""Tests for the honest-abstention verdict breakdown in ``format_summary()``.

When the governance summary includes non-zero ``unknowns``,
``insufficient_evidence``, or ``violations`` counts, the human-readable
summary now includes a ``verdicts`` line that breaks down these
honest-abstention / violation categories.  Previously these counts were
present in ``--json`` output but invisible in the human-readable summary.

These tests do not exercise live providers, credentials, or network calls.
"""

from __future__ import annotations

from vibap.run_bridge import GovernanceRunResult, format_summary


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_result(
    *,
    unknowns: int = 0,
    insufficient_evidence: int = 0,
    violations: int = 0,
    permits: int = 0,
    denials: int = 0,
    notes: list[str] | None = None,
) -> GovernanceRunResult:
    """Build a minimal ``GovernanceRunResult`` for summary-formatting tests."""
    summary: dict[str, object] = {
        "unknowns": unknowns,
        "insufficient_evidence": insufficient_evidence,
        "violations": violations,
        "delegation_count": 0,
    }
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
# verdicts line present
# ---------------------------------------------------------------------------

class TestVerdictBreakdownPresent:
    """The ``verdicts`` line appears when at least one category is non-zero."""

    def test_unknown_only(self):
        result = _make_result(unknowns=3, denials=3)
        out = format_summary(result)
        assert "verdicts" in out
        assert "3 unknown" in out

    def test_insufficient_only(self):
        result = _make_result(insufficient_evidence=2, denials=2)
        out = format_summary(result)
        assert "verdicts" in out
        assert "2 insufficient" in out

    def test_violations_only(self):
        result = _make_result(violations=1, denials=1)
        out = format_summary(result)
        assert "verdicts" in out
        assert "1 violation" in out

    def test_all_three_categories(self):
        result = _make_result(
            unknowns=2, insufficient_evidence=1, violations=3, denials=6,
        )
        out = format_summary(result)
        assert "verdicts" in out
        assert "3 violation" in out
        assert "2 unknown" in out
        assert "1 insufficient" in out

    def test_verdicts_line_appears_after_delegations(self):
        """When both delegations and verdicts are present, verdicts comes after."""
        result = _make_result(unknowns=1, denials=1)
        result.summary["delegation_count"] = 2
        result.summary["children_spawned"] = 1
        out = format_summary(result)
        delegations_idx = out.find("delegations")
        verdicts_idx = out.find("verdicts")
        assert delegations_idx != -1
        assert verdicts_idx != -1
        assert verdicts_idx > delegations_idx


# ---------------------------------------------------------------------------
# verdicts line absent
# ---------------------------------------------------------------------------

class TestVerdictBreakdownAbsent:
    """The ``verdicts`` line is omitted when all categories are zero."""

    def test_all_zero(self):
        result = _make_result(permits=5)
        out = format_summary(result)
        assert "verdicts" not in out

    def test_permits_only(self):
        result = _make_result(permits=10)
        out = format_summary(result)
        assert "verdicts" not in out

    def test_plain_denials_no_breakdown(self):
        """If denials exist but no unknown/insufficient/violation breakdown."""
        result = _make_result(denials=3)
        out = format_summary(result)
        assert "verdicts" not in out

    def test_missing_summary_keys(self):
        """If the summary dict is missing the keys entirely, no crash."""
        result = _make_result(permits=1)
        result.summary = {}
        out = format_summary(result)
        assert "verdicts" not in out
        # Should still produce valid output
        assert "governance summary" in out


# ---------------------------------------------------------------------------
# edge cases
# ---------------------------------------------------------------------------

class TestVerdictBreakdownEdgeCases:
    """Edge-case handling for verdict breakdown rendering."""

    def test_non_integer_values_raise(self):
        """Non-integer values violate the summary data contract from _build_summary().

        The implementation uses ``int(result.summary.get(key, 0))`` — same pattern
        as the existing ``delegation_count`` code. In practice these values always
        come from ``proxy._build_summary()`` which produces integers. This test
        documents the contract: malformed values raise ValueError rather than
        silently degrading.
        """
        import pytest

        result = _make_result(permits=1)
        result.summary["unknowns"] = "not-a-number"
        with pytest.raises(ValueError):
            format_summary(result)

    def test_large_counts(self):
        result = _make_result(unknowns=999, denials=999)
        out = format_summary(result)
        assert "999 unknown" in out

    def test_verdicts_with_notes(self):
        """Verdicts line and notes can coexist."""
        result = _make_result(
            unknowns=1, denials=1, notes=["custom note here"],
        )
        out = format_summary(result)
        assert "verdicts" in out
        assert "1 unknown" in out
        assert "custom note here" in out
        # Notes come after verdicts
        verdicts_idx = out.find("verdicts")
        note_idx = out.find("custom note here")
        assert note_idx > verdicts_idx

    def test_violation_before_unknown_before_insufficient_order(self):
        """Display order is violation, unknown, insufficient."""
        result = _make_result(
            unknowns=1, insufficient_evidence=1, violations=1, denials=3,
        )
        out = format_summary(result)
        verdicts_line = [
            line for line in out.splitlines() if "verdicts" in line
        ][0]
        v_idx = verdicts_line.find("violation")
        u_idx = verdicts_line.find("unknown")
        i_idx = verdicts_line.find("insufficient")
        assert 0 < v_idx < u_idx < i_idx

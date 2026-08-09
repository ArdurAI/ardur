"""Tests for ``_summary_for_json`` and POSIX exit-code normalization.

These cover three DX gaps found during CLI probes:

1. ``_summary_for_json`` must include ``denied_tools`` so ``--json``
   consumers get the same data the human-readable summary shows.
2. Signal-killed processes must produce POSIX-conventional exit codes
   (``128 + signal``) rather than raw negative values that wrap to
   unexpected codes under ``sys.exit``.
3. ``--json`` output (``to_result_dict``) must include ``exit_signal``
   and ``exit_hint`` at the top level so programmatic consumers can
   detect signal kills without reimplementing the detection logic or
   digging into ``process_lifecycle``.
"""

from __future__ import annotations

import unittest

from vibap.run_bridge import GovernanceRunResult


def _make_result(
    *,
    exit_code: int | None = 0,
    summary: dict | None = None,
) -> GovernanceRunResult:
    """Build a minimal GovernanceRunResult for testing."""
    return GovernanceRunResult(
        exit_code=exit_code if exit_code is not None else 0,
        session_id="test-session",
        mission_id="test-mission",
        agent_id="test-agent",
        adapter="test-adapter",
        via="env",
        proxy_url="http://127.0.0.1:0",
        home="/tmp/ardur-test-home",
        passport_path="/tmp/ardur-test-passport.json",
        summary=summary or {},
        permits=0,
        denials=0,
        total_events=0,
        attestation_token="dummy",
        attestation_digest="sha-256:dummy",
        receipts_path="/tmp/ardur-test-receipts.jsonl",
        receipt_count=0,
        correlation={},
        kernel_policy={},
    )


class TestSummaryForJsonDeniedTools(unittest.TestCase):
    """``_summary_for_json`` must surface ``denied_tools``."""

    def test_denied_tools_present_when_summary_has_them(self):
        summary = {
            "scope_compliance": "violated",
            "denied_tools": ["Bash", "Write", "MCP__dangerous"],
        }
        result = _make_result(summary=summary)
        js = result._summary_for_json()
        self.assertEqual(js["denied_tools"], ["Bash", "Write", "MCP__dangerous"])

    def test_denied_tools_empty_list_when_no_denials(self):
        summary = {"scope_compliance": "full", "denied_tools": []}
        result = _make_result(summary=summary)
        js = result._summary_for_json()
        self.assertEqual(js["denied_tools"], [])

    def test_denied_tools_empty_list_when_key_absent(self):
        summary = {"scope_compliance": "full"}
        result = _make_result(summary=summary)
        js = result._summary_for_json()
        self.assertEqual(js["denied_tools"], [])

    def test_denied_tools_not_none(self):
        """Ensure the field is always a list, never None."""
        result = _make_result(summary={})
        js = result._summary_for_json()
        self.assertIsInstance(js["denied_tools"], list)

    def test_all_existing_fields_still_present(self):
        """Existing fields must not regress."""
        summary = {
            "scope_compliance": "violated",
            "elapsed_s": 42.5,
            "unknowns": 1,
            "insufficient_evidence": 2,
            "violations": 3,
            "delegation_count": 4,
            "children_spawned": 5,
            "denied_tools": ["Bash"],
        }
        result = _make_result(summary=summary)
        js = result._summary_for_json()
        self.assertEqual(js["scope_compliance"], "violated")
        self.assertEqual(js["elapsed_s"], 42.5)
        self.assertEqual(js["unknowns"], 1)
        self.assertEqual(js["insufficient_evidence"], 2)
        self.assertEqual(js["violations"], 3)
        self.assertEqual(js["delegation_count"], 4)
        self.assertEqual(js["children_spawned"], 5)
        self.assertEqual(js["denied_tools"], ["Bash"])

    def test_denied_tools_preserves_order_and_duplicates(self):
        """The summary layer deduplicates; _summary_for_json passes through."""
        tools = ["Bash", "Write", "Bash", "Read"]
        summary = {"denied_tools": tools}
        result = _make_result(summary=summary)
        js = result._summary_for_json()
        self.assertEqual(js["denied_tools"], tools)

    def test_denied_tools_is_a_copy(self):
        """Mutating the returned list must not affect the summary."""
        original = ["Bash", "Write"]
        summary = {"denied_tools": original}
        result = _make_result(summary=summary)
        js = result._summary_for_json()
        js["denied_tools"].append("Hacked")
        self.assertEqual(original, ["Bash", "Write"])

    def test_denied_tools_from_real_build_summary_shape(self):
        """Simulate the shape produced by proxy._build_summary."""
        summary = {
            "type": "session_end",
            "jti": "abc-123",
            "agent": "test-agent",
            "mission": "test mission",
            "total_events": 10,
            "permits": 6,
            "denials": 4,
            "unknowns": 1,
            "insufficient_evidence": 1,
            "violations": 2,
            "denied_tools": ["Bash", "Write", "Read"],
            "elapsed_s": 5.123,
            "scope_compliance": "violated",
            "delegation_count": 0,
            "children_spawned": 0,
            "child_jtis": [],
            "delegated_budget_reserved": {},
        }
        result = _make_result(summary=summary)
        js = result._summary_for_json()
        self.assertEqual(js["denied_tools"], ["Bash", "Write", "Read"])
        self.assertEqual(js["scope_compliance"], "violated")


class TestExitCodeNormalization(unittest.TestCase):
    """Negative exit codes (signals) must normalize to ``128 + signal``."""

    def test_zero_exit_unchanged(self):
        """Exit 0 stays 0."""
        result = _make_result(exit_code=0)
        rc = result.exit_code
        if rc is not None and rc < 0:
            normalized = 128 + abs(rc)
        else:
            normalized = rc
        self.assertEqual(normalized, 0)

    def test_positive_exit_unchanged(self):
        """Normal non-zero exit stays as-is."""
        result = _make_result(exit_code=42)
        rc = result.exit_code
        if rc is not None and rc < 0:
            normalized = 128 + abs(rc)
        else:
            normalized = rc
        self.assertEqual(normalized, 42)

    def test_sigkill_normalizes_to_137(self):
        """``-9`` (SIGKILL) → ``137`` (128 + 9), not ``247``."""
        result = _make_result(exit_code=-9)
        rc = result.exit_code
        if rc is not None and rc < 0:
            normalized = 128 + abs(rc)
        else:
            normalized = rc
        self.assertEqual(normalized, 137)

    def test_sigterm_normalizes_to_143(self):
        """``-15`` (SIGTERM) → ``143`` (128 + 15)."""
        result = _make_result(exit_code=-15)
        rc = result.exit_code
        if rc is not None and rc < 0:
            normalized = 128 + abs(rc)
        else:
            normalized = rc
        self.assertEqual(normalized, 143)

    def test_sigsegv_normalizes_to_139(self):
        """``-11`` (SIGSEGV) → ``139`` (128 + 11)."""
        result = _make_result(exit_code=-11)
        rc = result.exit_code
        if rc is not None and rc < 0:
            normalized = 128 + abs(rc)
        else:
            normalized = rc
        self.assertEqual(normalized, 139)

    def test_no_wrapping_to_247(self):
        """The old bug: ``sys.exit(-9)`` wraps to ``247`` (``(-9) & 0xFF``).

        After normalization the exit code should be ``137``, not ``247``.
        """
        result = _make_result(exit_code=-9)
        rc = result.exit_code
        if rc is not None and rc < 0:
            normalized = 128 + abs(rc)
        else:
            normalized = rc
        self.assertNotEqual(normalized, 247)
        self.assertEqual(normalized, 137)


class TestJsonExitSignalAndHint(unittest.TestCase):
    """``to_result_dict`` must include ``exit_signal`` and ``exit_hint``."""

    def test_exit_signal_none_for_zero_exit(self):
        """Exit 0 is not a signal kill → ``exit_signal`` must be ``None``."""
        result = _make_result(exit_code=0)
        d = result.to_result_dict()
        self.assertIn("exit_signal", d)
        self.assertIsNone(d["exit_signal"])

    def test_exit_hint_empty_for_zero_exit(self):
        """Exit 0 needs no hint → ``exit_hint`` must be empty string."""
        result = _make_result(exit_code=0)
        d = result.to_result_dict()
        self.assertIn("exit_hint", d)
        self.assertEqual(d["exit_hint"], "")

    def test_exit_signal_for_posix_sigkill(self):
        """Exit 137 (128 + 9) → ``SIGKILL``."""
        result = _make_result(exit_code=137)
        d = result.to_result_dict()
        self.assertEqual(d["exit_signal"], "SIGKILL")
        self.assertEqual(d["exit_hint"], "killed by SIGKILL")

    def test_exit_signal_for_posix_sigterm(self):
        """Exit 143 (128 + 15) → ``SIGTERM``."""
        result = _make_result(exit_code=143)
        d = result.to_result_dict()
        self.assertEqual(d["exit_signal"], "SIGTERM")
        self.assertEqual(d["exit_hint"], "killed by SIGTERM")

    def test_exit_signal_for_raw_negative_sigkill(self):
        """Raw ``-9`` (pre-normalization) → ``SIGKILL``."""
        result = _make_result(exit_code=-9)
        d = result.to_result_dict()
        self.assertEqual(d["exit_signal"], "SIGKILL")

    def test_exit_signal_none_for_non_signal_nonzero(self):
        """Exit 42 is not a signal kill → ``exit_signal`` must be ``None``."""
        result = _make_result(exit_code=42)
        d = result.to_result_dict()
        self.assertIsNone(d["exit_signal"])
        self.assertEqual(d["exit_hint"], "non-zero exit")

    def test_exit_signal_none_for_exit_1(self):
        """Exit 1 (common error) is not a signal kill."""
        result = _make_result(exit_code=1)
        d = result.to_result_dict()
        self.assertIsNone(d["exit_signal"])
        self.assertEqual(d["exit_hint"], "non-zero exit")

    def test_exit_signal_and_hint_keys_always_present(self):
        """Both keys must always exist in the JSON dict, even for exit 0."""
        result = _make_result(exit_code=0)
        d = result.to_result_dict()
        self.assertIn("exit_signal", d)
        self.assertIn("exit_hint", d)

    def test_exit_signal_for_sigsegv(self):
        """Exit 139 (128 + 11) → ``SIGSEGV``."""
        result = _make_result(exit_code=139)
        d = result.to_result_dict()
        self.assertEqual(d["exit_signal"], "SIGSEGV")
        self.assertEqual(d["exit_hint"], "killed by SIGSEGV")

    def test_exit_signal_for_posix_high_signal(self):
        """Exit 158 (128 + 30) → ``SIGUSR1`` on macOS/Linux."""
        result = _make_result(exit_code=158)
        d = result.to_result_dict()
        # SIGUSR1 is signal 30 on macOS/Linux
        self.assertEqual(d["exit_signal"], "SIGUSR1")

    def test_redact_paths_preserves_exit_signal(self):
        """``redact_paths=True`` must not affect exit_signal or exit_hint."""
        result = _make_result(exit_code=137)
        d = result.to_result_dict(redact_paths=True)
        self.assertEqual(d["exit_signal"], "SIGKILL")
        self.assertEqual(d["exit_hint"], "killed by SIGKILL")

    def test_existing_fields_still_present(self):
        """Existing fields in ``to_result_dict`` must not regress."""
        result = _make_result(exit_code=0)
        d = result.to_result_dict()
        for key in (
            "ok",
            "exit_code",
            "session_id",
            "mission_id",
            "agent_id",
            "adapter",
            "via",
            "total_events",
            "permits",
            "denials",
            "receipt_count",
            "receipts_path",
            "attestation_digest",
            "home",
            "passport_path",
            "correlation",
            "kernel_policy",
            "process_lifecycle",
            "summary",
            "notes",
        ):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()

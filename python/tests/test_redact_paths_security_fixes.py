"""Regression tests for security fixes to the ``--redact-paths`` redaction.

These tests verify fixes for vulnerabilities found in the adversarial
security review on 2026-08-03:

1. ``notes`` field in ``ardur run --json --redact-paths`` was not redacted,
   leaking local filesystem paths via adapter notes (e.g. ``--plugin-dir``
   path) and seccomp shim paths.

2. ``_redact_local_path`` did not handle bare ``/var/folders/`` (without
   the macOS ``/private/`` prefix), allowing temp-root paths to survive
   redaction on some macOS configurations.

3. The ``/tmp`` prefix check could over-redact sibling directories like
   ``/tmp2/foo`` (substring match without directory-boundary guard).
"""

from __future__ import annotations

import os

from vibap.run_bridge import (
    GovernanceRunResult,
    _redact_local_path,
    _redact_local_path_embedded,
)

_HOME = os.path.expanduser("~")


def _make_result(notes: list[str] | None = None) -> GovernanceRunResult:
    """Build a minimal GovernanceRunResult for testing."""
    return GovernanceRunResult(
        exit_code=0,
        session_id="test-sid",
        mission_id="test-mid",
        agent_id="test-aid",
        adapter="claude-code",
        via="hook",
        proxy_url="",
        home=_HOME + "/.ardur",
        passport_path="/tmp/ardur-test/passport.json",
        summary={},
        permits=0,
        denials=0,
        total_events=0,
        attestation_token="",
        attestation_digest="abc123",
        receipts_path="/tmp/ardur-test/receipts.jsonl",
        receipt_count=0,
        correlation={},
        kernel_policy={},
        notes=notes or [],
    )


class TestNotesRedaction:
    """HIGH severity fix: notes must be redacted when redact_paths=True."""

    def test_notes_with_embedded_tmp_path_redacted(self):
        """Notes containing embedded ``/tmp/`` paths must be redacted."""
        result = _make_result([
            "launched via --plugin-dir /tmp/ardur-test/plugins/claude-code",
        ])
        d = result.to_result_dict(redact_paths=True)
        note = d["notes"][0]
        assert "/tmp/" not in note, f"Path leaked in note: {note}"
        assert "<tmp>" in note, f"Redaction placeholder missing: {note}"

    def test_notes_with_private_tmp_path_redacted(self):
        """Notes containing ``/private/tmp/`` paths must be redacted."""
        result = _make_result([
            "shim at /private/tmp/ardur-test/shim binary",
        ])
        d = result.to_result_dict(redact_paths=True)
        note = d["notes"][0]
        assert "/private/tmp/" not in note, f"Path leaked: {note}"
        assert "<tmp>" in note

    def test_notes_with_home_path_redacted(self):
        """Notes containing the user's home dir must be redacted."""
        result = _make_result([
            f"data stored at {_HOME}/.ardur/receipts",
        ])
        d = result.to_result_dict(redact_paths=True)
        note = d["notes"][0]
        assert _HOME not in note, f"Home leaked in note: {note}"
        assert "<home>" in note

    def test_notes_with_var_folders_path_redacted(self):
        """Notes containing ``/var/folders/`` (bare, no /private/) must be redacted."""
        result = _make_result([
            "temp file at /var/folders/55/abc123/T/ardur/data.json",
        ])
        d = result.to_result_dict(redact_paths=True)
        note = d["notes"][0]
        assert "/var/folders/" not in note, f"var/folders leaked: {note}"
        assert "<var-folders>" in note

    def test_notes_without_paths_preserved(self):
        """Notes without any paths should pass through unchanged."""
        clean = "clean note without any paths"
        result = _make_result([clean])
        d = result.to_result_dict(redact_paths=True)
        assert d["notes"][0] == clean

    def test_notes_preserved_when_redact_false(self):
        """Notes must be preserved verbatim when redact_paths=False."""
        pathy = "plugin at /tmp/ardur-test/plugins/claude-code"
        result = _make_result([pathy])
        d = result.to_result_dict(redact_paths=False)
        assert d["notes"][0] == pathy

    def test_empty_notes(self):
        """Empty notes list should not error."""
        result = _make_result([])
        d = result.to_result_dict(redact_paths=True)
        assert d["notes"] == []


class TestRedactLocalPathBareVarFolders:
    """MEDIUM severity fix: bare /var/folders/ must be redacted."""

    def test_bare_var_folders_redacted(self):
        assert _redact_local_path("/var/folders/55/abc/T/data") == "<var-folders>/55/abc/T/data"

    def test_private_var_folders_still_works(self):
        assert _redact_local_path("/private/var/folders/55/abc/T/data") == "<var-folders>/55/abc/T/data"


class TestRedactLocalPathTmpBoundary:
    """LOW severity fix: /tmp must not over-redact /tmp2 etc."""

    def test_tmp_not_overredacted_on_sibling(self):
        """``/tmp2/foo`` must not be redacted as ``<tmp>2/foo``."""
        assert _redact_local_path("/tmp2/foo/bar") == "/tmp2/foo/bar"

    def test_tmp_still_redacted(self):
        assert _redact_local_path("/tmp/ardur/data") == "<tmp>/ardur/data"


class TestRedactLocalPathEmbedded:
    """Unit tests for _redact_local_path_embedded helper."""

    def test_embedded_tmp(self):
        s = "launched via --plugin-dir /tmp/foo/plugins/cc"
        r = _redact_local_path_embedded(s)
        assert "/tmp/" not in r
        assert "<tmp>" in r

    def test_embedded_var_folders(self):
        s = "file at /var/folders/55/abc/T/data.json not found"
        r = _redact_local_path_embedded(s)
        assert "/var/folders/" not in r
        assert "<var-folders>" in r

    def test_embedded_home(self):
        s = f"data at {_HOME}/.ardur/config.json"
        r = _redact_local_path_embedded(s)
        assert _HOME not in r
        assert "<home>" in r

    def test_empty_string(self):
        assert _redact_local_path_embedded("") == ""

    def test_no_paths(self):
        s = "just a regular note"
        assert _redact_local_path_embedded(s) == s

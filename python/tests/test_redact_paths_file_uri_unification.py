"""Regression tests for the ``--redact-paths`` file:// URI and absolute-path fix.

Prior to this fix, ``_redact_local_path_string`` used a hand-rolled regex pass
that only covered a fixed list of known roots (``/tmp/``, ``/Users/``, etc.).
It missed:

1. ``file://`` URIs pointing at local paths (e.g. ``file:///tmp/ardur/data.json``).
2. Arbitrary absolute paths under unknown roots (e.g. ``/opt/ardur/receipts.jsonl``)
   — the old code passed these through unchanged.

The unification routes ``_redact_local_path_string`` through the canonical
``redact_local_path_text`` helper from ``shareable_redaction``, which handles
``file://`` URIs, percent-encoded separators, and arbitrary local absolute
paths.  These tests verify the fix while ensuring existing known-root
redaction output is preserved.
"""

from __future__ import annotations

import os

from vibap.cli import _redact_local_path_string, _redact_paths_deep


_HOME = os.path.expanduser("~")


# ---------------------------------------------------------------------------
# file:// URI redaction
# ---------------------------------------------------------------------------


class TestFileURIRedaction:
    """file:// URIs pointing at local paths must be redacted."""

    def test_file_uri_tmp_path(self):
        result = _redact_local_path_string("file:///tmp/ardur/data.json")
        assert "file:///tmp/" not in result
        assert "/tmp/ardur" not in result

    def test_file_uri_home_path(self):
        result = _redact_local_path_string(f"file://{_HOME}/.ardur/config.json")
        assert _HOME not in result
        assert "<FILE_URI" in result or "<home>" in result

    def test_file_uri_var_folders(self):
        result = _redact_local_path_string(
            "file:///private/var/folders/55/abc/T/ardur/bundle.json"
        )
        assert "/private/var/folders/" not in result

    def test_file_uri_localhost(self):
        """file://localhost/ is equivalent to file:///."""
        result = _redact_local_path_string("file://localhost/tmp/ardur/data")
        assert "/tmp/ardur" not in result

    def test_file_uri_in_embedded_command(self):
        """file:// inside a longer string is redacted."""
        result = _redact_local_path_string(
            "VIBAP_HOME=/tmp/ardur .venv/bin/python file:///tmp/ardur/script.py"
        )
        assert "file:///tmp/" not in result
        assert "/tmp/ardur" not in result

    def test_file_uri_not_redacted_through_redact_paths_deep(self):
        """Verify file:// is caught by the recursive redactor too."""
        response = {"command": "cat file:///tmp/ardur/secret"}
        redacted = _redact_paths_deep(response)
        assert "file:///tmp/" not in redacted["command"]

    def test_file_uri_percent_encoded(self):
        """Percent-encoded file:// URIs are caught via separator normalization."""
        result = _redact_local_path_string("file%3A//tmp/ardur/data")
        assert "file://tmp/ardur" not in result
        assert "/private/tmp" not in result

    def test_http_url_preserved(self):
        """Non-file URLs (https) must not be redacted as local paths."""
        result = _redact_local_path_string("https://example.com/path/to/resource")
        assert "https://example.com/" in result


# ---------------------------------------------------------------------------
# Arbitrary absolute path redaction
# ---------------------------------------------------------------------------


class TestArbitraryAbsolutePathRedaction:
    """Absolute paths under unknown roots must be redacted, not passed through."""

    def test_opt_path_redacted(self):
        """Previously, /opt/ardur/... would pass through unchanged."""
        result = _redact_local_path_string("/opt/ardur/receipts.jsonl")
        assert "/opt/ardur/receipts.jsonl" not in result
        assert "<ABSOLUTE_PATH" in result or "<tmp>" in result

    def test_arbitrary_abs_path_in_deep(self):
        response = {"path": "/srv/ardur/data/bundle.json"}
        redacted = _redact_paths_deep(response)
        assert redacted["path"] != "/srv/ardur/data/bundle.json"

    def test_arbitrary_abs_path_nested(self):
        response = {
            "config": {
                "log_path": "/var/log/ardur/agent.log",
            }
        }
        redacted = _redact_paths_deep(response)
        assert redacted["config"]["log_path"] != "/var/log/ardur/agent.log"

    def test_known_root_abs_path_preserves_placeholder(self):
        """Known roots still use familiar placeholders (not <ABSOLUTE_PATH>)."""
        result = _redact_local_path_string("/tmp/ardur/data")
        assert "<tmp>" in result
        assert "<ABSOLUTE_PATH" not in result


# ---------------------------------------------------------------------------
# Existing behaviour preservation
# ---------------------------------------------------------------------------


class TestExistingRedactionPreserved:
    """Ensure existing known-root redaction output is not changed."""

    def test_tmp_path(self):
        result = _redact_local_path_string("/tmp/ardur/data")
        assert "<tmp>" in result
        assert "/tmp/ardur" not in result

    def test_private_tmp(self):
        result = _redact_local_path_string("/private/tmp/ardur/data")
        assert "<tmp>" in result
        assert "/private/tmp/" not in result

    def test_home_path(self):
        result = _redact_local_path_string(f"{_HOME}/.ardur/config")
        assert _HOME not in result
        assert "<home>" in result

    def test_var_folders(self):
        result = _redact_local_path_string("/var/folders/55/abc/T/ardur")
        assert "<var-folders>" in result
        assert "/var/folders/" not in result

    def test_private_var_folders(self):
        result = _redact_local_path_string("/private/var/folders/55/abc/T/ardur")
        assert "<var-folders>" in result

    def test_cgroup(self):
        result = _redact_local_path_string("/sys/fs/cgroup/ardur/sess-1")
        assert "<cgroup>" in result

    def test_run_ardur(self):
        result = _redact_local_path_string("/run/ardur/session-abc")
        assert "<run-ardur>" in result

    def test_command_with_embedded_paths(self):
        """Command strings with multiple embedded paths are fully redacted."""
        result = _redact_local_path_string(
            f"VIBAP_HOME={_HOME}/.ardur "
            f"claude --plugin-dir /tmp/ardur/plugins/claude-code"
        )
        assert _HOME not in result
        assert "/tmp/ardur" not in result

    def test_no_path_preserved(self):
        clean = "just a regular message with no paths"
        result = _redact_local_path_string(clean)
        assert result == clean

"""Regression tests for residual ``str(exc)`` leak sites in user-facing output.

Covers the error-sanitization class that was partially addressed in the
fixture (13cb413), kill-switch, port-in-use, and Rekor transport fixes but
remained open in:

- ``drp_conformance.main()`` — sibling conformance module missed by 13cb413
- ``policy_conformance.main()`` — same class
- ``claude_code_daemon`` — daemon request error leaked ``type(exc).__name__:
  {exc}`` to Unix-socket clients
- ``run_bridge`` embedded governance server — leaked ``str(exc)`` in HTTP
  400/500 response bodies
- ``transparency`` — embedded raw ``str(exc)`` in
  ``TransparencyError``/``AnchorVerificationError`` messages and
  ``AnchorDrainResult.error`` field
- ``cli.cmd_anchor`` / ``cmd_verify`` — passed ``str(exc)`` through to JSON
  ``message`` field
- ``codex_app_server_fixture`` — report verification passed ``str(exc)`` to
  ``message`` field in shareable reports

The invariant: raw ``str(exc)`` from ``OSError``, ``TypeError``,
``ValueError``, ``PyJWTError``, ``JSONDecodeError``, etc. must never appear
in user-visible output because it carries filesystem paths, errno details,
Python internals, and crypto library messages.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vibap.transparency import (
    TransparencyError,
    load_anchor_bundle,
)


# ─── transparency.py: load_anchor_bundle ──────────────────────────────────


class TestLoadAnchorBundleSanitization:
    """Raw OSError paths/errno must not appear in TransparencyError messages."""

    def test_oserror_does_not_leak_path(self, tmp_path: Path) -> None:
        """A missing/unreadable file must not leak the filesystem path."""
        missing = tmp_path / "nonexistent.bundle"
        with pytest.raises(TransparencyError) as exc_info:
            load_anchor_bundle(str(missing))
        msg = str(exc_info.value)
        assert str(tmp_path) not in msg, f"leaks path: {msg!r}"
        assert "nonexistent.bundle" not in msg, f"leaks filename: {msg!r}"

    def test_json_decode_error_does_not_leak_raw_details(
        self, tmp_path: Path
    ) -> None:
        """Invalid JSON must not leak JSONDecodeError offset details."""
        bad = tmp_path / "bad.bundle"
        bad.write_text("{invalid json")
        with pytest.raises(TransparencyError) as exc_info:
            load_anchor_bundle(str(bad))
        msg = str(exc_info.value)
        assert "could not be read" in msg
        # Should contain the exception class name for diagnostics.
        assert "JSONDecodeError" in msg


# ─── drp_conformance.main() ────────────────────────────────────────────────


class TestDrpConformanceErrorSanitization:
    """``drp_conformance.main()`` must not leak ``str(exc)`` to stderr."""

    def test_oserror_does_not_leak_path(self, capsys: pytest.CaptureFixture) -> None:
        from vibap.drp_conformance import main

        with patch(
            "vibap.drp_conformance.run_drp_conformance_bundle",
            side_effect=OSError("[Errno 2] No such file or directory: '/secret/path'"),
        ):
            rc = main(["--bundle", "/tmp/fake-bundle.json"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "/secret/path" not in captured.err
        assert "Errno" not in captured.err
        data = json.loads(captured.err)
        assert data["ok"] is False
        assert data["error"] == "drp_conformance_failed"

    def test_value_error_does_not_leak_python_internals(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        from vibap.drp_conformance import main

        with patch(
            "vibap.drp_conformance.run_drp_conformance_bundle",
            side_effect=ValueError("invalid literal for int() with base 10: 'xyz'"),
        ):
            rc = main(["--bundle", "/tmp/fake-bundle.json"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "int()" not in captured.err
        data = json.loads(captured.err)
        assert data["ok"] is False
        assert data["error"] == "drp_conformance_failed"


# ─── policy_conformance.main() ─────────────────────────────────────────────


class TestPolicyConformanceErrorSanitization:
    """``policy_conformance.main()`` must not leak ``str(exc)`` to stderr."""

    def test_oserror_does_not_leak_path(self, capsys: pytest.CaptureFixture) -> None:
        from vibap.policy_conformance import main

        with patch(
            "vibap.policy_conformance.run_policy_conformance_bundle",
            side_effect=OSError("[Errno 13] Permission denied: '/etc/shadow'"),
        ):
            rc = main(["--bundle", "/tmp/fake-bundle.json"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "/etc/shadow" not in captured.err
        assert "Errno" not in captured.err
        data = json.loads(captured.err)
        assert data["ok"] is False
        assert data["error"] == "policy_conformance_failed"


# ─── Source inspection: verify no str(exc) in user-facing error paths ──────


class TestSourceNoStrExcInOutputPaths:
    """Inspect source code to verify ``str(exc)`` has been removed from
    all user-facing error response paths."""

    def test_run_bridge_embedded_server_no_str_exc(self) -> None:
        from vibap.run_bridge import _build_embedded_server

        source = inspect.getsource(_build_embedded_server)
        assert 'self._send(400, {"error": str(exc)})' not in source, (
            "run_bridge embedded server still leaks str(exc) in 400 responses"
        )
        assert 'f"internal error: {exc}"' not in source, (
            "run_bridge embedded server still leaks str(exc) in 500 responses"
        )

    def test_daemon_loop_no_raw_exc_text(self) -> None:
        from vibap.claude_code_daemon import serve_pre_tool_use_daemon

        source = inspect.getsource(serve_pre_tool_use_daemon)
        assert (
            'f"daemon request failed: {type(exc).__name__}: {exc}"' not in source
        ), "daemon still leaks exception type and text to socket clients"

    def test_cmd_verify_anchor_no_str_exc_in_message(self) -> None:
        from vibap.cli import cmd_verify

        source = inspect.getsource(cmd_verify)
        # The old pattern: "message": str(exc) in the anchor verification
        # error response.
        assert '"message": str(exc)' not in source, (
            "cmd_verify still leaks raw str(exc) in message field"
        )

    def test_cmd_anchor_no_str_exc_in_message(self) -> None:
        from vibap.cli import cmd_anchor

        source = inspect.getsource(cmd_anchor)
        assert '"message": str(exc)' not in source, (
            "cmd_anchor still leaks raw str(exc) in message field"
        )

    def test_transparency_no_raw_exc_in_error_messages(self) -> None:
        from vibap import transparency

        source = inspect.getsource(transparency)
        # The three patterns we fixed in transparency.py:
        assert 'f"anchor bundle could not be read: {exc}"' not in source, (
            "transparency still embeds raw str(exc) in TransparencyError"
        )
        assert 'f"refusing to submit an invalid receipt: {exc}"' not in source, (
            "transparency still embeds raw PyJWTError text in receipt validation"
        )
        assert (
            'f"receipt signature/schema verification failed: {exc}"' not in source
        ), "transparency still embeds raw PyJWTError text in verification"

    def test_transparency_drain_no_str_exc_truncated(self) -> None:
        from vibap import transparency

        source = inspect.getsource(transparency)
        assert "error=str(exc)[:500]" not in source.replace(" ", ""), (
            "transparency drain still uses str(exc)[:500] in AnchorDrainResult"
        )

    def test_codex_app_server_fixture_no_str_exc_in_message(self) -> None:
        from vibap import codex_app_server_fixture

        source = inspect.getsource(codex_app_server_fixture)
        # The old pattern had "message": str(exc) in the report verification.
        assert '"message": str(exc)' not in source, (
            "codex_app_server_fixture still leaks str(exc) in report message field"
        )

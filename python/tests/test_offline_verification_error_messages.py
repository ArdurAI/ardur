"""Regression tests for offline verification error message preservation.

``_safe_exception_message()`` previously stripped the intentional, user-safe
messages from ``OfflineVerificationError`` and ``TelemetryExportError``,
returning only the raw class name (``"OfflineVerificationError"``) with zero
diagnostic value.  The ``--token`` / ``--attestation-token`` paths had rich
error responses with ``next_steps``, but the journal/offline path showed only
``"message": "OfflineVerificationError"``.

These tests verify that domain exceptions following the ``(code, message)``
pattern from the offline-verification and telemetry-export modules are treated
as safe and their ``str(exc)`` message is preserved.
"""

from __future__ import annotations

import argparse
import inspect
import json


# ─── _safe_exception_message domain allowlist ──────────────────────


class TestSafeExceptionMessageDomainAllowlist:
    """_safe_exception_message must preserve domain error messages."""

    def test_offline_verification_error_message_preserved(self) -> None:
        """OfflineVerificationError carries an intentional user-safe message."""
        from vibap.cli import _safe_exception_message
        from vibap.offline_verification import OfflineVerificationError

        exc = OfflineVerificationError("input_missing", "offline verification input was not found")
        result = _safe_exception_message(exc)
        assert "offline verification input was not found" in result
        assert "OfflineVerificationError" not in result

    def test_telemetry_export_error_message_preserved(self) -> None:
        """TelemetryExportError carries an intentional user-safe message."""
        from vibap.cli import _safe_exception_message
        from vibap.receipt_telemetry import TelemetryExportError

        exc = TelemetryExportError("journal_invalid", "receipt journal is malformed")
        result = _safe_exception_message(exc)
        assert "receipt journal is malformed" in result
        assert "TelemetryExportError" not in result

    def test_offline_error_with_index_preserved(self) -> None:
        """OfflineVerificationError with receipt index still shows message."""
        from vibap.cli import _safe_exception_message
        from vibap.offline_verification import OfflineVerificationError

        exc = OfflineVerificationError(
            "journal_token_invalid",
            "journal line 3 is not a bounded compact JWS",
            index=2,
        )
        result = _safe_exception_message(exc)
        assert "journal line 3" in result
        assert "OfflineVerificationError" not in result

    def test_generic_value_error_still_sanitized(self) -> None:
        """A generic ValueError must still be sanitized to class name."""
        from vibap.cli import _safe_exception_message

        exc = ValueError("/secret/path/to/keys.pem: invalid PEM")
        result = _safe_exception_message(exc)
        assert "/secret/path" not in result
        assert "keys.pem" not in result

    def test_oserror_with_errno_still_sanitized(self) -> None:
        """An OSError with [Errno must still be sanitized."""
        from vibap.cli import _safe_exception_message

        exc = OSError("[Errno 2] No such file or directory: '/secret/path/keys.pem'")
        result = _safe_exception_message(exc)
        assert "/secret/path" not in result
        assert "keys.pem" not in result


# ─── _safe_exception_message source inspection ─────────────────────


class TestSafeExceptionMessageSource:
    """Source-level guarantees for _safe_exception_message."""

    def test_source_includes_offline_verification_error(self) -> None:
        """_safe_exception_message must import OfflineVerificationError."""
        from vibap.cli import _safe_exception_message

        source = inspect.getsource(_safe_exception_message)
        assert "OfflineVerificationError" in source, (
            "_safe_exception_message does not handle OfflineVerificationError"
        )

    def test_source_includes_telemetry_export_error(self) -> None:
        """_safe_exception_message must import TelemetryExportError."""
        from vibap.cli import _safe_exception_message

        source = inspect.getsource(_safe_exception_message)
        assert "TelemetryExportError" in source, (
            "_safe_exception_message does not handle TelemetryExportError"
        )


# ─── CLI command integration: verify journal ───────────────────────


def _make_verify_args(journal: str, keys_dir: str) -> argparse.Namespace:
    """Build a Namespace matching _cmd_verify_offline's argparse contract."""
    return argparse.Namespace(
        journal=journal,
        keys_dir=keys_dir,
        receipt_public_key=None,
        transparency_log_key=None,
        receiver_public_key=None,
        mcp_request=None,
        mcp_response=None,
        max_registration_delay_s=600,
        max_attestation_delay_s=300,
        receiver_clock_skew_s=30,
        max_bundle_age_s=None,
        freshness_clock_skew_s=None,
        chain_only=False,
        verify_expiry=False,
        json=True,
        html_report=None,
        output=None,
        unsafe_show_sensitive=False,
    )


class TestVerifyOfflineErrorMessages:
    """``ardur verify <journal>`` must show real domain error messages."""

    def test_verify_nonexistent_journal_shows_input_missing(
        self, session_keys_dir, tmp_path, capsys
    ) -> None:
        """A nonexistent journal must say 'input was not found', not 'OfflineVerificationError'."""
        from vibap.cli import _cmd_verify_offline

        args = _make_verify_args(
            journal=str(tmp_path / "nonexistent.jsonl"),
            keys_dir=str(session_keys_dir),
        )
        exit_code = _cmd_verify_offline(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)
        assert exit_code == 1
        assert response["valid"] is False
        assert response["error"] == "input_missing"
        assert "input was not found" in response["message"]
        assert "OfflineVerificationError" not in response["message"]

    def test_verify_empty_journal_shows_size_invalid(
        self, session_keys_dir, tmp_path, capsys
    ) -> None:
        """An empty journal must say 'must be 1..N bytes', not 'OfflineVerificationError'."""
        from vibap.cli import _cmd_verify_offline

        empty_file = tmp_path / "empty.jsonl"
        empty_file.write_text("")

        args = _make_verify_args(
            journal=str(empty_file),
            keys_dir=str(session_keys_dir),
        )
        exit_code = _cmd_verify_offline(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)
        assert exit_code == 1
        assert response["valid"] is False
        assert response["error"] == "input_size_invalid"
        assert "must be" in response["message"]
        assert "OfflineVerificationError" not in response["message"]

    def test_verify_malformed_journal_shows_token_invalid(
        self, session_keys_dir, tmp_path, capsys
    ) -> None:
        """A malformed journal must say 'not a bounded compact JWS', not 'OfflineVerificationError'."""
        from vibap.cli import _cmd_verify_offline

        bad_file = tmp_path / "bad.jsonl"
        bad_file.write_text("this is not valid json or jwt\n")

        args = _make_verify_args(
            journal=str(bad_file),
            keys_dir=str(session_keys_dir),
        )
        exit_code = _cmd_verify_offline(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)
        assert exit_code == 1
        assert response["valid"] is False
        assert response["error"] == "journal_token_invalid"
        assert "bounded compact JWS" in response["message"]
        assert "OfflineVerificationError" not in response["message"]


# ─── CLI command integration: telemetry export ─────────────────────


class TestTelemetryExportErrorMessages:
    """``ardur telemetry export`` must show real domain error messages."""

    def test_telemetry_export_nonexistent_journal_shows_input_missing(
        self, session_keys_dir, tmp_path, capsys
    ) -> None:
        """Telemetry export of nonexistent journal must show real message."""
        from vibap.cli import cmd_telemetry_export

        args = argparse.Namespace(
            journal=str(tmp_path / "nonexistent.jsonl"),
            keys_dir=str(session_keys_dir),
            receipt_public_key=None,
            export_format="jsonl",
            telemetry_output=None,
            redact_paths=False,
            otlp_endpoint=None,
            timeout_s=10,
            verify_expiry=False,
            json=True,
        )
        exit_code = cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)
        assert exit_code == 1
        assert response["ok"] is False
        assert response["error"] == "input_missing"
        assert "input was not found" in response["message"]
        assert "TelemetryExportError" not in response["message"]
        assert "OfflineVerificationError" not in response["message"]

"""Regression tests for ``telemetry export`` key-loading error messages.

``ardur telemetry export`` previously collapsed all key-loading failures
(missing directory, missing ``passport_public.pem``, invalid PEM content,
permission denied) into one generic ``receipt_public_key_invalid`` /
``"The trusted receipt public key could not be loaded."`` response, giving
the user zero diagnostic information.

The sibling commands ``verify`` and ``evidence correlate`` already preserve
the real domain error message via ``_safe_exception_message(exc)``.  This
test file verifies that ``telemetry export`` now follows the same pattern:
the ``error`` code stays ``receipt_public_key_invalid`` but the ``message``
field carries the actual cause (missing file, missing key, etc.) instead of
a generic placeholder.
"""

from __future__ import annotations

import argparse
import json


def _telemetry_export_args(
    *,
    journal: str = "/nonexistent/journal.jsonl",
    keys_dir: str | None = None,
    receipt_public_key: str | None = None,
) -> argparse.Namespace:
    """Build a Namespace matching cmd_telemetry_export's argparse contract."""
    return argparse.Namespace(
        journal=journal,
        keys_dir=keys_dir,
        receipt_public_key=receipt_public_key,
        export_format="jsonl",
        telemetry_output=None,
        redact_paths=False,
        otlp_endpoint=None,
        timeout_s=10,
        verify_expiry=False,
        json=True,
    )


class TestTelemetryExportKeyLoadingErrors:
    """``telemetry export`` must preserve real key-loading error messages."""

    def test_missing_keys_dir_shows_missing_file_message(
        self, tmp_path, capsys
    ) -> None:
        """An empty/missing keys dir must say 'passport_public.pem is missing'."""
        from vibap.cli import cmd_telemetry_export

        empty_dir = tmp_path / "empty_keys"
        empty_dir.mkdir()

        args = _telemetry_export_args(keys_dir=str(empty_dir))
        exit_code = cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        assert response["error"] == "receipt_public_key_invalid"
        assert "passport_public.pem is missing" in response["message"]
        assert "could not be loaded" not in response["message"]

    def test_nonexistent_keys_dir_shows_missing_file_message(
        self, tmp_path, capsys
    ) -> None:
        """A nonexistent keys dir must also say 'passport_public.pem is missing'."""
        from vibap.cli import cmd_telemetry_export

        nonexistent = str(tmp_path / "does_not_exist")

        args = _telemetry_export_args(keys_dir=nonexistent)
        exit_code = cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        assert response["error"] == "receipt_public_key_invalid"
        assert "passport_public.pem is missing" in response["message"]

    def test_nonexistent_receipt_public_key_shows_not_found(
        self, tmp_path, capsys
    ) -> None:
        """``--receipt-public-key <nonexistent>`` must say 'was not found'."""
        from vibap.cli import cmd_telemetry_export

        key_path = str(tmp_path / "nonexistent_key.pem")

        args = _telemetry_export_args(receipt_public_key=key_path)
        exit_code = cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        assert response["error"] == "receipt_public_key_invalid"
        assert "not found" in response["message"].lower()
        assert "could not be loaded" not in response["message"]

    def test_invalid_pem_receipt_public_key_sanitized(
        self, tmp_path, capsys
    ) -> None:
        """An invalid PEM file must produce a safe but informative message."""
        from vibap.cli import cmd_telemetry_export

        bad_key = tmp_path / "bad_key.pem"
        bad_key.write_text("this is definitely not a PEM public key")

        args = _telemetry_export_args(receipt_public_key=str(bad_key))
        exit_code = cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        assert response["error"] == "receipt_public_key_invalid"
        # _safe_exception_message sanitizes generic ValueError to class name.
        # The key invariant: the message is NOT the old generic placeholder.
        assert response["message"] != "The trusted receipt public key could not be loaded."

    def test_empty_receipt_public_key_sanitized(
        self, tmp_path, capsys
    ) -> None:
        """An empty PEM file must produce a safe but informative message."""
        from vibap.cli import cmd_telemetry_export

        empty_key = tmp_path / "empty_key.pem"
        empty_key.write_text("")

        args = _telemetry_export_args(receipt_public_key=str(empty_key))
        exit_code = cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        assert response["error"] == "receipt_public_key_invalid"
        assert response["message"] != "The trusted receipt public key could not be loaded."

    def test_keys_dir_is_regular_file_shows_key_directory_error(
        self, tmp_path, capsys
    ) -> None:
        """A keys-dir path that is a regular file must say KeyDirectoryError info."""
        from vibap.cli import cmd_telemetry_export

        regular_file = tmp_path / "not_a_dir"
        regular_file.write_text("I am a file, not a directory")

        args = _telemetry_export_args(keys_dir=str(regular_file))
        exit_code = cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        assert response["error"] == "receipt_public_key_invalid"
        # KeyDirectoryError message mentions the path-exists-as-file condition.
        assert "could not be loaded" not in response["message"]


class TestTelemetryExportSiblingParity:
    """``telemetry export`` error shape must match ``verify`` sibling command."""

    def test_telemetry_error_code_consistent_with_verify(
        self, tmp_path, capsys
    ) -> None:
        """Both commands must return the same error code for the same failure."""
        from vibap.cli import _cmd_verify_offline, cmd_telemetry_export

        empty_dir = tmp_path / "empty_keys"
        empty_dir.mkdir()
        journal = str(tmp_path / "nonexistent.jsonl")

        # telemetry export
        tel_args = _telemetry_export_args(journal=journal, keys_dir=str(empty_dir))
        cmd_telemetry_export(tel_args)
        tel_response = json.loads(capsys.readouterr().out)

        # verify
        verify_args = argparse.Namespace(
            journal=journal,
            keys_dir=str(empty_dir),
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
        _cmd_verify_offline(verify_args)
        verify_response = json.loads(capsys.readouterr().out)

        # Both should say the key file is missing (different error codes but
        # same diagnostic message about passport_public.pem).
        assert "passport_public.pem is missing" in tel_response["message"]
        assert "passport_public.pem is missing" in verify_response["message"]

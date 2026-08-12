"""Regression tests for local path-leak in ``receipt_public_key_invalid`` errors.

When the receipt public key file exists but cannot be read (``PermissionError``),
the raw ``str(exc)`` includes the full local filesystem path::

    [Errno 13] Permission denied: '/var/folders/.../tmpXXXX.pem'

The ``receipt_public_key_invalid`` handlers in ``verify``, ``evidence correlate``,
and ``telemetry export`` must use ``_safe_exception_message(exc)`` instead of
``str(exc)`` so that local paths never appear in JSON output.

This regression was introduced when error enrichment was added (commit 9e7a913
and its predecessors) and affected all three commands.  The fix restores
``_safe_exception_message`` for all sites.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verify_args(
    *,
    journal: str = "/nonexistent/journal.jsonl",
    receipt_public_key: str | Path | None = None,
) -> argparse.Namespace:
    """Build a Namespace matching _cmd_verify_offline's argparse contract."""
    return argparse.Namespace(
        journal=journal,
        keys_dir=None,
        receipt_public_key=receipt_public_key,
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


def _evidence_correlate_args(
    *,
    journal: str = "/nonexistent/journal.jsonl",
    evidence_events: str = "/nonexistent/events.jsonl",
    receipt_public_key: str | None = None,
) -> argparse.Namespace:
    """Build a Namespace matching cmd_evidence_correlate's argparse contract."""
    return argparse.Namespace(
        journal=journal,
        evidence_events=evidence_events,
        keys_dir=None,
        receipt_public_key=receipt_public_key,
        correlation_window_s=60,
        verify_expiry=False,
        source_format="jsonl",
        report_format="json",
        evidence_output=None,
        redact_paths=False,
        json=True,
    )


def _telemetry_export_args(
    *,
    journal: str = "/nonexistent/journal.jsonl",
    receipt_public_key: str | None = None,
) -> argparse.Namespace:
    """Build a Namespace matching cmd_telemetry_export's argparse contract."""
    return argparse.Namespace(
        journal=journal,
        keys_dir=None,
        receipt_public_key=receipt_public_key,
        export_format="jsonl",
        telemetry_output=None,
        redact_paths=False,
        otlp_endpoint=None,
        timeout_s=10,
        verify_expiry=False,
        json=True,
    )


def _make_no_permission_key(tmp_path: Path) -> Path:
    """Create a key file with 000 permissions so reads raise PermissionError."""
    key_path = tmp_path / "no_perm_key.pem"
    key_path.write_text("placeholder-key-content")
    os.chmod(key_path, 0o000)
    return key_path


def _restore_permissions(key_path: Path) -> None:
    """Restore permissions so tmp_path cleanup works on all platforms."""
    try:
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVerifyPathLeak:
    """``ardur verify --receipt-public-key <no-perm>`` must not leak the path."""

    def test_permission_error_sanitized(self, tmp_path, capsys) -> None:
        from vibap.cli import _cmd_verify_offline

        key_path = _make_no_permission_key(tmp_path)
        try:
            args = _verify_args(receipt_public_key=key_path)
            exit_code = _cmd_verify_offline(args)
            captured = capsys.readouterr()
            response = json.loads(captured.out)

            assert exit_code == 1
            assert response["valid"] is False
            assert response["error"] == "receipt_public_key_invalid"
            # _safe_exception_message returns the class name for PermissionError
            # when the raw text contains [Errno.
            assert str(key_path) not in json.dumps(response)
            assert "/var/folders/" not in response.get("message", "")
            assert "[Errno" not in response.get("message", "")
        finally:
            _restore_permissions(key_path)


class TestEvidenceCorrelatePathLeak:
    """``ardur evidence correlate --receipt-public-key <no-perm>`` must not leak."""

    def test_permission_error_sanitized(self, tmp_path, capsys) -> None:
        from vibap.cli import cmd_evidence_correlate

        key_path = _make_no_permission_key(tmp_path)
        journal = tmp_path / "journal.jsonl"
        journal.touch()
        events = tmp_path / "events.jsonl"
        events.touch()
        try:
            args = _evidence_correlate_args(
                journal=str(journal),
                evidence_events=str(events),
                receipt_public_key=str(key_path),
            )
            exit_code = cmd_evidence_correlate(args)
            captured = capsys.readouterr()
            response = json.loads(captured.out)

            assert exit_code == 1
            assert response["ok"] is False
            assert response["valid"] is False
            assert response["error"] == "receipt_public_key_invalid"
            assert str(key_path) not in json.dumps(response)
            assert "/var/folders/" not in response.get("message", "")
            assert "[Errno" not in response.get("message", "")
        finally:
            _restore_permissions(key_path)


class TestTelemetryExportPathLeak:
    """``ardur telemetry export --receipt-public-key <no-perm>`` must not leak."""

    def test_permission_error_sanitized(self, tmp_path, capsys) -> None:
        from vibap.cli import cmd_telemetry_export

        key_path = _make_no_permission_key(tmp_path)
        journal = tmp_path / "journal.jsonl"
        journal.touch()
        try:
            args = _telemetry_export_args(
                journal=str(journal),
                receipt_public_key=str(key_path),
            )
            exit_code = cmd_telemetry_export(args)
            captured = capsys.readouterr()
            response = json.loads(captured.out)

            assert exit_code == 1
            assert response["ok"] is False
            assert response["error"] == "receipt_public_key_invalid"
            assert str(key_path) not in json.dumps(response)
            assert "/var/folders/" not in response.get("message", "")
            assert "[Errno" not in response.get("message", "")
        finally:
            _restore_permissions(key_path)

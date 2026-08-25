"""Regression tests for enriched error responses in offline verification commands.

``ardur verify``, ``ardur evidence correlate``, and ``ardur telemetry export``
previously produced legacy minimal error responses (``error`` + ``message`` only)
for domain exceptions, while the rest of the CLI had rich structured responses
with ``error_code``, ``condition``, ``detail``, and ``next_steps``.

This test file verifies that all three commands now produce enriched error
responses with the full set of fields, while preserving backward compatibility
(the existing ``error`` and ``message`` fields are still present).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a real P-256 key pair for test fixtures."""
    private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key()


def _write_public_key_pem(public_key: ec.EllipticCurvePublicKey, path: Path) -> Path:
    """Write a P-256 public key as PEM to the given path."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)
    return path


def _verify_args(
    *,
    journal: str = "/nonexistent/journal.jsonl",
    keys_dir: str | None = None,
    receipt_public_key: str | Path | None = None,
) -> argparse.Namespace:
    """Build a Namespace matching _cmd_verify_offline's argparse contract.

    Note: _cmd_verify_offline does NOT call _path_arg_invalid_failure, so
    receipt_public_key is passed directly to _load_p256_public_key which
    expects a Path. Pass Path objects for receipt_public_key.
    """
    return argparse.Namespace(
        journal=journal,
        keys_dir=keys_dir,
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
    keys_dir: str | None = None,
    receipt_public_key: str | None = None,
) -> argparse.Namespace:
    """Build a Namespace matching cmd_evidence_correlate's argparse contract.

    cmd_evidence_correlate calls _path_arg_invalid_failure which coerces
    str values to Path, so str is fine here.
    """
    return argparse.Namespace(
        journal=journal,
        evidence_events=evidence_events,
        keys_dir=keys_dir,
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
    keys_dir: str | None = None,
    receipt_public_key: str | None = None,
) -> argparse.Namespace:
    """Build a Namespace matching cmd_telemetry_export's argparse contract.

    cmd_telemetry_export calls _path_arg_invalid_failure which coerces
    str values to Path, so str is fine here.
    """
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


# ---------------------------------------------------------------------------
# Verify offline
# ---------------------------------------------------------------------------


class TestVerifyOfflineErrorEnrichment:
    """``verify`` must return enriched error responses with error_code, condition,
    detail, and next_steps."""

    def test_nonexistent_journal_returns_enriched_error(
        self, tmp_path, capsys
    ) -> None:
        """A nonexistent journal file must produce an enriched error response."""
        from vibap.cli import _cmd_verify_offline

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        # _cmd_verify_offline does NOT call _path_arg_invalid_failure, so
        # receipt_public_key must be a Path, not str.
        args = _verify_args(journal=journal, receipt_public_key=key_path)
        exit_code = _cmd_verify_offline(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["valid"] is False
        # Backward compat: existing fields still present
        assert "error" in response
        assert "message" in response
        # New enriched fields
        assert "error_code" in response
        assert "condition" in response
        assert "detail" in response
        assert "next_steps" in response
        # error_code and condition match error
        assert response["error_code"] == response["error"]
        assert response["condition"] == response["error"]
        # detail is a non-empty string
        assert isinstance(response["detail"], str)
        assert len(response["detail"]) > 0
        # next_steps is a non-empty list of dicts with required keys
        assert isinstance(response["next_steps"], list)
        assert len(response["next_steps"]) > 0
        for step in response["next_steps"]:
            assert isinstance(step, dict)
            assert "condition" in step
            assert "action" in step
            assert "command" in step
            assert "detail" in step

    def test_nonexistent_journal_input_missing_next_steps(
        self, tmp_path, capsys
    ) -> None:
        """A nonexistent journal should produce input_missing-specific next steps."""
        from vibap.cli import _cmd_verify_offline

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        args = _verify_args(journal=journal, receipt_public_key=key_path)
        _cmd_verify_offline(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        # The error code should be input_missing for a nonexistent file
        assert response["error"] == "input_missing"
        assert response["error_code"] == "input_missing"
        assert response["condition"] == "input_missing"
        # next_steps should reference checking the journal path
        steps = response["next_steps"]
        assert any("check_journal_path" in step["action"] for step in steps)

    def test_journal_is_directory_returns_enriched_error(
        self, tmp_path, capsys
    ) -> None:
        """A directory passed as journal must produce an enriched error response."""
        from vibap.cli import _cmd_verify_offline

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal_dir = tmp_path / "journal_dir"
        journal_dir.mkdir()

        args = _verify_args(journal=str(journal_dir), receipt_public_key=key_path)
        exit_code = _cmd_verify_offline(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["valid"] is False
        assert response["error"] == "input_not_file"
        assert response["error_code"] == "input_not_file"
        assert response["condition"] == "input_not_file"
        assert "detail" in response
        assert "next_steps" in response
        steps = response["next_steps"]
        assert any("use_regular_file" in step["action"] for step in steps)


# ---------------------------------------------------------------------------
# Evidence correlate
# ---------------------------------------------------------------------------


class TestEvidenceCorrelateErrorEnrichment:
    """``evidence correlate`` must return enriched error responses."""

    def test_nonexistent_journal_returns_enriched_error(
        self, tmp_path, capsys
    ) -> None:
        """A nonexistent journal must produce an enriched error response."""
        from vibap.cli import cmd_evidence_correlate

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        events = str(tmp_path / "nonexistent_events.jsonl")
        args = _evidence_correlate_args(
            journal=journal,
            evidence_events=events,
            receipt_public_key=str(key_path),
        )
        exit_code = cmd_evidence_correlate(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        assert response["valid"] is False
        # Backward compat
        assert "error" in response
        assert "message" in response
        # New enriched fields
        assert "error_code" in response
        assert "condition" in response
        assert "detail" in response
        assert "next_steps" in response
        assert response["error_code"] == response["error"]
        assert response["condition"] == response["error"]
        assert isinstance(response["detail"], str)
        assert len(response["detail"]) > 0
        assert isinstance(response["next_steps"], list)
        assert len(response["next_steps"]) > 0
        for step in response["next_steps"]:
            assert isinstance(step, dict)
            assert "condition" in step
            assert "action" in step
            assert "command" in step
            assert "detail" in step

    def test_nonexistent_journal_input_missing_code(
        self, tmp_path, capsys
    ) -> None:
        """A nonexistent journal should produce input_missing error code."""
        from vibap.cli import cmd_evidence_correlate

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        events = str(tmp_path / "nonexistent_events.jsonl")
        args = _evidence_correlate_args(
            journal=journal,
            evidence_events=events,
            receipt_public_key=str(key_path),
        )
        cmd_evidence_correlate(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert response["error"] == "input_missing"
        assert response["error_code"] == "input_missing"
        assert response["condition"] == "input_missing"


# ---------------------------------------------------------------------------
# Telemetry export
# ---------------------------------------------------------------------------


class TestTelemetryExportErrorEnrichment:
    """``telemetry export`` must return enriched error responses."""

    def test_nonexistent_journal_returns_enriched_error(
        self, tmp_path, capsys
    ) -> None:
        """A nonexistent journal must produce an enriched error response."""
        from vibap.cli import cmd_telemetry_export

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        args = _telemetry_export_args(
            journal=journal,
            receipt_public_key=str(key_path),
        )
        exit_code = cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        # Backward compat
        assert "error" in response
        assert "message" in response
        # New enriched fields
        assert "error_code" in response
        assert "condition" in response
        assert "detail" in response
        assert "next_steps" in response
        assert response["error_code"] == response["error"]
        assert response["condition"] == response["error"]
        assert isinstance(response["detail"], str)
        assert len(response["detail"]) > 0
        assert isinstance(response["next_steps"], list)
        assert len(response["next_steps"]) > 0
        for step in response["next_steps"]:
            assert isinstance(step, dict)
            assert "condition" in step
            assert "action" in step
            assert "command" in step
            assert "detail" in step

    def test_nonexistent_journal_input_missing_code(
        self, tmp_path, capsys
    ) -> None:
        """A nonexistent journal should produce input_missing error code."""
        from vibap.cli import cmd_telemetry_export

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        args = _telemetry_export_args(
            journal=journal,
            receipt_public_key=str(key_path),
        )
        cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert response["error"] == "input_missing"
        assert response["error_code"] == "input_missing"
        assert response["condition"] == "input_missing"


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Existing ``error`` and ``message`` fields must still be present."""

    def test_verify_error_and_message_still_present(
        self, tmp_path, capsys
    ) -> None:
        """The legacy error and message fields are preserved in verify."""
        from vibap.cli import _cmd_verify_offline

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        args = _verify_args(journal=journal, receipt_public_key=key_path)
        _cmd_verify_offline(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert response["error"] == "input_missing"
        assert isinstance(response["message"], str)
        assert len(response["message"]) > 0

    def test_evidence_correlate_error_and_message_still_present(
        self, tmp_path, capsys
    ) -> None:
        """The legacy error and message fields are preserved in evidence correlate."""
        from vibap.cli import cmd_evidence_correlate

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        events = str(tmp_path / "nonexistent_events.jsonl")
        args = _evidence_correlate_args(
            journal=journal,
            evidence_events=events,
            receipt_public_key=str(key_path),
        )
        cmd_evidence_correlate(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert response["error"] == "input_missing"
        assert isinstance(response["message"], str)
        assert len(response["message"]) > 0

    def test_telemetry_export_error_and_message_still_present(
        self, tmp_path, capsys
    ) -> None:
        """The legacy error and message fields are preserved in telemetry export."""
        from vibap.cli import cmd_telemetry_export

        _, public_key = _generate_p256_keypair()
        key_path = _write_public_key_pem(public_key, tmp_path / "receipt_key.pem")

        journal = str(tmp_path / "nonexistent.jsonl")
        args = _telemetry_export_args(
            journal=journal,
            receipt_public_key=str(key_path),
        )
        cmd_telemetry_export(args)
        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert response["error"] == "input_missing"
        assert isinstance(response["message"], str)
        assert len(response["message"]) > 0

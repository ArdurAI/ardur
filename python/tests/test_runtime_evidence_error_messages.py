"""Regression tests for RuntimeEvidenceError message preservation.

``RuntimeEvidenceError`` carries safe, hardcoded user-facing messages (e.g.
"runtime evidence input is empty", "runtime evidence input must be a regular
file") with no filesystem paths, errno patterns, or Python internals.

Previously, ``_safe_exception_message`` did not whitelist
``RuntimeEvidenceError``, so these messages were silently replaced with just
the class name ``"RuntimeEvidenceError"`` in JSON error responses from
``ardur evidence correlate``.

These tests verify that:
1. ``_safe_exception_message`` preserves ``RuntimeEvidenceError`` messages.
2. ``cmd_evidence_correlate`` produces error responses containing the actual
   domain message, not just the class name.
3. Bare ``ValueError`` is still sanitized (RuntimeEvidenceError is a subclass).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import patch

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
        source_format="normalized",
        report_format="json",
        evidence_output=None,
        redact_paths=False,
        json=True,
    )


# ---------------------------------------------------------------------------
# Unit tests: _safe_exception_message
# ---------------------------------------------------------------------------


class TestSafeExceptionMessagePreservesRuntimeEvidenceError:
    """``_safe_exception_message`` must preserve ``RuntimeEvidenceError`` messages."""

    def test_runtime_evidence_error_message_preserved(self):
        """The safe message of a RuntimeEvidenceError must be returned verbatim."""
        from vibap.cli import _safe_exception_message
        from vibap.runtime_evidence import RuntimeEvidenceError

        exc = RuntimeEvidenceError("input_empty", "runtime evidence input is empty")
        result = _safe_exception_message(exc)
        assert result == "runtime evidence input is empty"
        assert result != "RuntimeEvidenceError"

    def test_runtime_evidence_error_with_line_preserved(self):
        """The safe message must be preserved even when line metadata is set."""
        from vibap.cli import _safe_exception_message
        from vibap.runtime_evidence import RuntimeEvidenceError

        exc = RuntimeEvidenceError(
            "malformed_json",
            "runtime evidence line 5 is malformed JSON at column 10",
            line=5,
        )
        result = _safe_exception_message(exc)
        assert "malformed JSON at column 10" in result
        assert result != "RuntimeEvidenceError"

    def test_runtime_evidence_error_subclass_of_value_error_still_preserved(self):
        """RuntimeEvidenceError subclasses ValueError but must still be safe."""
        from vibap.cli import _safe_exception_message
        from vibap.runtime_evidence import RuntimeEvidenceError

        assert issubclass(RuntimeEvidenceError, ValueError)
        exc = RuntimeEvidenceError(
            "input_not_regular",
            "runtime evidence input must be a regular file",
        )
        result = _safe_exception_message(exc)
        assert "must be a regular file" in result
        assert result != "RuntimeEvidenceError"

    def test_bare_value_error_still_sanitized(self):
        """A bare ValueError (not RuntimeEvidenceError) must still be sanitized."""
        from vibap.cli import _safe_exception_message

        exc = ValueError("could not convert string to float: /etc/passwd")
        result = _safe_exception_message(exc)
        assert result == "ValueError"
        assert "/etc/passwd" not in result

    def test_multiple_error_codes_preserved(self):
        """Multiple RuntimeEvidenceError codes must all preserve their messages."""
        from vibap.cli import _safe_exception_message
        from vibap.runtime_evidence import RuntimeEvidenceError

        cases = [
            ("input_empty", "runtime evidence input is empty"),
            ("input_not_regular", "runtime evidence input must be a regular file"),
            ("input_too_large", "runtime evidence input exceeds the byte limit"),
            ("duplicate_json_key", "runtime evidence repeats a JSON object key"),
            (
                "nonfinite_json_number",
                "runtime evidence contains a non-finite JSON number",
            ),
        ]
        for code, message in cases:
            exc = RuntimeEvidenceError(code, message)
            result = _safe_exception_message(exc)
            assert result == message, f"Code {code!r} message was not preserved"


# ---------------------------------------------------------------------------
# Integration tests: cmd_evidence_correlate
# ---------------------------------------------------------------------------


class TestEvidenceCorrelatePreservesRuntimeEvidenceError:
    """``ardur evidence correlate`` must preserve ``RuntimeEvidenceError`` messages."""

    def test_runtime_evidence_error_message_in_json_response(
        self, tmp_path, capsys
    ):
        """When RuntimeEvidenceError is raised during correlation, the JSON
        response must contain the domain message, not just the class name."""
        from vibap.cli import cmd_evidence_correlate
        from vibap.runtime_evidence import RuntimeEvidenceError

        _, public = _generate_p256_keypair()
        key_path = _write_public_key_pem(public, tmp_path / "receipt_key.pem")

        args = _evidence_correlate_args(
            receipt_public_key=str(key_path),
        )

        error_message = "runtime evidence input is empty"
        with patch(
            "vibap.offline_verification.verify_offline_path",
            side_effect=RuntimeEvidenceError("input_empty", error_message),
        ):
            exit_code = cmd_evidence_correlate(args)

        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert exit_code == 1
        assert response["ok"] is False
        assert response["valid"] is False
        # The domain message must be present in both message and detail.
        assert response["message"] == error_message
        assert response["detail"] == error_message
        # Must NOT be just the class name.
        assert response["message"] != "RuntimeEvidenceError"

    def test_runtime_evidence_error_code_in_json_response(
        self, tmp_path, capsys
    ):
        """The error_code field must match the RuntimeEvidenceError code attribute."""
        from vibap.cli import cmd_evidence_correlate
        from vibap.runtime_evidence import RuntimeEvidenceError

        _, public = _generate_p256_keypair()
        key_path = _write_public_key_pem(public, tmp_path / "receipt_key.pem")

        args = _evidence_correlate_args(
            receipt_public_key=str(key_path),
        )

        with patch(
            "vibap.offline_verification.verify_offline_path",
            side_effect=RuntimeEvidenceError(
                "input_not_regular",
                "runtime evidence input must be a regular file",
            ),
        ):
            cmd_evidence_correlate(args)

        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert response["ok"] is False
        assert response["error"] == "input_not_regular"
        assert response["error_code"] == "input_not_regular"
        assert response["condition"] == "input_not_regular"
        assert "regular file" in response["message"]

    def test_runtime_evidence_error_with_line_metadata(self, tmp_path, capsys):
        """When RuntimeEvidenceError has line metadata, event_line must be present."""
        from vibap.cli import cmd_evidence_correlate
        from vibap.runtime_evidence import RuntimeEvidenceError

        _, public = _generate_p256_keypair()
        key_path = _write_public_key_pem(public, tmp_path / "receipt_key.pem")

        args = _evidence_correlate_args(
            receipt_public_key=str(key_path),
        )

        exc = RuntimeEvidenceError(
            "malformed_json",
            "runtime evidence line 5 is malformed JSON at column 10",
            line=5,
        )
        with patch("vibap.offline_verification.verify_offline_path", side_effect=exc):
            cmd_evidence_correlate(args)

        captured = capsys.readouterr()
        response = json.loads(captured.out)

        assert response["ok"] is False
        assert response.get("event_line") == 5
        assert "malformed JSON" in response["message"]

"""Tests for receipt public key loading error messages.

DX probe found that ``verify``, ``evidence correlate``, and ``telemetry export``
all returned ``"message": "ValueError"`` (raw Python class name) when the user
passed a non-P-256 public key via ``--receipt-public-key``. The root cause was
that ``_load_p256_public_key`` raises ``ValueError`` with intentional safe
messages (e.g. "receipt public key must be an ES256 P-256 key"), but the catch
sites either used ``_safe_exception_message(exc)`` which sanitizes generic
``ValueError`` to the class name only, or caught it inside a broader
``except (TypeError, ValueError)`` block alongside other verification errors.

The fix separates key-loading errors into their own try/except at each call
site, mapping them to ``receipt_public_key_invalid`` with the actual message
preserved via ``str(exc)``.

Additionally, ``_load_p256_public_key`` now catches
``serialization.load_pem_public_key`` failures and re-raises with a safe,
user-facing message instead of letting the cryptography library's raw
``ValueError`` (which may include internal details like "MalformedFraming")
leak through.

These tests verify all three commands produce clear, user-facing error messages
when the public key is wrong type, malformed, empty, or a symlink.
"""

import json
import subprocess
import sys
from pathlib import Path


def _run_cli(args: list[str], tmp_path: Path) -> tuple[int, dict]:
    """Run ardur CLI with the given args, return (exit_code, json_response)."""
    proc = subprocess.run(
        [sys.executable, "-m", "vibap.cli", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    try:
        response = json.loads(proc.stderr if proc.stderr.strip() else proc.stdout)
    except json.JSONDecodeError:
        response = {"raw_stderr": proc.stderr, "raw_stdout": proc.stdout}
    return proc.returncode, response


def _write_ed25519_key(path: Path) -> None:
    """Write an Ed25519 public key PEM (wrong type for ES256 verification)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def _write_rsa_key(path: Path) -> None:
    """Write an RSA public key PEM (wrong type for ES256 verification)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    key = generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def _write_garbage_pem(path: Path) -> None:
    """Write a file that is not a valid PEM at all."""
    path.write_text("this is not a valid PEM file")


class TestVerifyReceiptPublicKeyErrors:
    """``ardur verify <journal> --receipt-public-key <key> --json`` should show
    the actual domain error message, not the raw Python class name."""

    def test_verify_wrong_key_type_ed25519(self, tmp_path: Path) -> None:
        journal = tmp_path / "journal.jsonl"
        journal.write_text('{"jwt": "a.b.c"}\n')
        key_file = tmp_path / "ed25519.pem"
        _write_ed25519_key(key_file)

        exit_code, result = _run_cli(
            ["verify", str(journal), "--receipt-public-key", str(key_file), "--json"],
            tmp_path,
        )
        assert exit_code == 1
        assert result["error"] == "receipt_public_key_invalid"
        assert "ES256 P-256" in result["message"]
        assert "ValueError" not in result["message"]

    def test_verify_wrong_key_type_rsa(self, tmp_path: Path) -> None:
        journal = tmp_path / "journal.jsonl"
        journal.write_text('{"jwt": "a.b.c"}\n')
        key_file = tmp_path / "rsa.pem"
        _write_rsa_key(key_file)

        exit_code, result = _run_cli(
            ["verify", str(journal), "--receipt-public-key", str(key_file), "--json"],
            tmp_path,
        )
        assert exit_code == 1
        assert result["error"] == "receipt_public_key_invalid"
        assert "ES256 P-256" in result["message"]
        assert "ValueError" not in result["message"]

    def test_verify_malformed_pem(self, tmp_path: Path) -> None:
        journal = tmp_path / "journal.jsonl"
        journal.write_text('{"jwt": "a.b.c"}\n')
        key_file = tmp_path / "garbage.pem"
        _write_garbage_pem(key_file)

        exit_code, result = _run_cli(
            ["verify", str(journal), "--receipt-public-key", str(key_file), "--json"],
            tmp_path,
        )
        assert exit_code == 1
        assert result["error"] == "receipt_public_key_invalid"
        assert "valid PEM" in result["message"]
        assert "ValueError" not in result["message"]

    def test_verify_empty_key_file(self, tmp_path: Path) -> None:
        journal = tmp_path / "journal.jsonl"
        journal.write_text('{"jwt": "a.b.c"}\n')
        key_file = tmp_path / "empty.pem"
        key_file.write_bytes(b"")

        exit_code, result = _run_cli(
            ["verify", str(journal), "--receipt-public-key", str(key_file), "--json"],
            tmp_path,
        )
        assert exit_code == 1
        assert result["error"] == "receipt_public_key_invalid"
        assert "empty" in result["message"] or "size limit" in result["message"]
        assert "ValueError" not in result["message"]

    def test_verify_symlink_key(self, tmp_path: Path) -> None:
        journal = tmp_path / "journal.jsonl"
        journal.write_text('{"jwt": "a.b.c"}\n')
        real_key = tmp_path / "real.pem"
        _write_ed25519_key(real_key)
        symlink_key = tmp_path / "symlink.pem"
        symlink_key.symlink_to(real_key)

        exit_code, result = _run_cli(
            ["verify", str(journal), "--receipt-public-key", str(symlink_key), "--json"],
            tmp_path,
        )
        assert exit_code == 1
        assert result["error"] == "receipt_public_key_invalid"
        assert "symlink" in result["message"].lower()
        assert "ValueError" not in result["message"]


class TestTelemetryExportReceiptPublicKeyErrors:
    """``ardur telemetry export <journal> --receipt-public-key <key> --json``
    should show the actual domain error message."""

    def test_telemetry_wrong_key_type(self, tmp_path: Path) -> None:
        journal = tmp_path / "journal.jsonl"
        journal.write_text('{"jwt": "a.b.c"}\n')
        key_file = tmp_path / "ed25519.pem"
        _write_ed25519_key(key_file)

        exit_code, result = _run_cli(
            [
                "telemetry", "export", str(journal),
                "--receipt-public-key", str(key_file),
                "--otlp-endpoint", "http://localhost:4318",
                "--json",
            ],
            tmp_path,
        )
        assert exit_code == 1
        assert result["error"] == "receipt_public_key_invalid"
        assert "ES256 P-256" in result["message"]
        assert "ValueError" not in result["message"]


class TestEvidenceCorrelateReceiptPublicKeyErrors:
    """``ardur evidence correlate <journal> <events> --receipt-public-key <key> --json``
    should show the actual domain error message."""

    def test_correlate_wrong_key_type(self, tmp_path: Path) -> None:
        journal = tmp_path / "journal.jsonl"
        journal.write_text('{"jwt": "a.b.c"}\n')
        events = tmp_path / "events.jsonl"
        events.write_text('{"timestamp": "2026-01-01T00:00:00Z"}\n')
        key_file = tmp_path / "ed25519.pem"
        _write_ed25519_key(key_file)

        exit_code, result = _run_cli(
            [
                "evidence", "correlate",
                str(journal), str(events),
                "--source-format", "normalized",
                "--receipt-public-key", str(key_file),
                "--json",
            ],
            tmp_path,
        )
        assert exit_code == 1
        assert result["error"] == "receipt_public_key_invalid"
        assert "ES256 P-256" in result["message"]
        assert "ValueError" not in result["message"]

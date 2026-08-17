"""Tests that JWT verification errors preserve their safe domain messages.

The _safe_exception_message() function sanitizes generic exceptions to their
class name to avoid leaking filesystem paths or Python internals.  PyJWT's
InvalidTokenError family carries intentionally-safe, user-facing messages
("Signature has expired", "Signature verification failed", etc.) with no
paths, credentials, or internals, so they should be preserved verbatim.

This was the same DX gap as the offline verification error message fix
(commit 0547618): users saw "ExpiredSignatureError" instead of
"Signature has expired".
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

REPO_ROOT = Path(__file__).resolve().parents[2]


def _safe_exception_message(exc):
    """Import the real function for direct unit testing."""
    from vibap.cli import _safe_exception_message as _impl

    return _impl(exc)


# ---------------------------------------------------------------------------
# Direct unit tests for _safe_exception_message with JWT errors
# ---------------------------------------------------------------------------


class TestSafeExceptionMessageJWT:
    """Verify that PyJWT InvalidTokenError subclasses are treated as safe."""

    def test_expired_signature_preserves_message(self):
        """ExpiredSignatureError -> "Signature has expired" not class name."""
        exc = jwt.ExpiredSignatureError("Signature has expired")
        assert _safe_exception_message(exc) == "Signature has expired"

    def test_immature_signature_preserves_message(self):
        """ImmatureSignatureError -> "The token is not yet valid" not class name."""
        exc = jwt.ImmatureSignatureError("The token is not yet valid")
        assert _safe_exception_message(exc) == "The token is not yet valid"

    def test_invalid_signature_preserves_message(self):
        """InvalidSignatureError -> "Signature verification failed" not class name."""
        exc = jwt.InvalidSignatureError("Signature verification failed")
        assert _safe_exception_message(exc) == "Signature verification failed"

    def test_decode_error_preserves_message(self):
        """DecodeError -> "Not enough segments" not class name."""
        exc = jwt.DecodeError("Not enough segments")
        assert _safe_exception_message(exc) == "Not enough segments"

    def test_invalid_audience_preserves_message(self):
        """InvalidAudienceError -> "Invalid audience" not class name."""
        exc = jwt.InvalidAudienceError("Invalid audience")
        assert _safe_exception_message(exc) == "Invalid audience"

    def test_invalid_issuer_preserves_message(self):
        """InvalidIssuerError -> "Invalid issuer" not class name."""
        exc = jwt.InvalidIssuerError("Invalid issuer")
        assert _safe_exception_message(exc) == "Invalid issuer"

    def test_missing_required_claim_preserves_message(self):
        """MissingRequiredClaimError -> safe message not class name."""
        exc = jwt.MissingRequiredClaimError("exp")
        msg = _safe_exception_message(exc)
        assert "exp" in msg
        assert msg != type(exc).__name__

    def test_invalid_token_base_class_preserves_message(self):
        """InvalidTokenError -> safe message not class name."""
        exc = jwt.InvalidTokenError("Token is invalid")
        assert _safe_exception_message(exc) == "Token is invalid"

    def test_invalid_key_error_is_sanitized(self):
        """InvalidKeyError can carry key material -> should be sanitized."""
        exc = jwt.InvalidKeyError("The specified key is too short")
        msg = _safe_exception_message(exc)
        # InvalidKeyError is NOT an InvalidTokenError subclass, so it falls
        # through to the generic sanitizer and returns only the class name.
        assert msg == type(exc).__name__

    def test_pyjwt_error_base_is_sanitized(self):
        """Base PyJWTError is NOT an InvalidTokenError -> should be sanitized."""
        exc = jwt.PyJWTError("some error")
        msg = _safe_exception_message(exc)
        assert msg == type(exc).__name__


# ---------------------------------------------------------------------------
# Integration tests through the CLI verify --token path
# ---------------------------------------------------------------------------


def _run_verify(args_list, keys_dir):
    """Run ardur verify through the CLI and return parsed JSON response."""
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "python")}
    result = subprocess.run(
        [sys.executable, "-m", "vibap.cli", "verify"] + args_list,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT / "python"),
        env=env,
    )
    return result


class TestVerifyTokenJWTErrorMessages:
    """Integration: verify --token with bad JWTs should show safe detail messages."""

    def test_malformed_token_detail(self, tmp_path):
        """Malformed token -> detail should say "malformed" not class name."""
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        from vibap.passport import generate_keypair

        generate_keypair(keys_dir=str(keys_dir))

        result = _run_verify(
            ["--token", "not-a-valid-jwt", "--keys-dir", str(keys_dir), "--json"],
            keys_dir,
        )

        assert result.returncode == 1
        response = json.loads(result.stdout)
        assert response["ok"] is False
        assert response["valid"] is False
        # The detail should say the token is malformed (not just class name)
        assert "malformed" in response.get("detail", "").lower()

    def test_wrong_signature_detail(self, tmp_path):
        """Token signed by different key -> safe detail not class name."""
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        from vibap.passport import generate_keypair

        generate_keypair(keys_dir=str(keys_dir))

        # Generate a different keypair and create a token signed by it
        other_keys = tmp_path / "other-keys"
        other_keys.mkdir()
        other_priv, _ = generate_keypair(keys_dir=str(other_keys))

        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "iss": "vibap-governance-proxy",
                "sub": "test-agent",
                "aud": "vibap-proxy",
                "mission": "test-mission-v1",
                "iat": now,
                "exp": now + timedelta(hours=1),
            },
            other_priv,
            algorithm="ES256",
        )

        result = _run_verify(
            ["--token", token, "--keys-dir", str(keys_dir), "--json"],
            keys_dir,
        )

        assert result.returncode == 1
        response = json.loads(result.stdout)
        assert response["ok"] is False
        assert response["valid"] is False
        # Detail should contain "Signature" not just "InvalidSignatureError"
        detail_lower = response.get("detail", "").lower()
        assert "signature" in detail_lower


class TestVerifyAttestationTokenJWTErrorMessages:
    """Integration: verify --attestation-token with bad JWTs should show safe detail."""

    def test_malformed_attestation_token_detail(self, tmp_path):
        """Malformed attestation token -> detail should say "malformed"."""
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        from vibap.passport import generate_keypair

        generate_keypair(keys_dir=str(keys_dir))

        result = _run_verify(
            [
                "--attestation-token",
                "garbage.token.here",
                "--keys-dir",
                str(keys_dir),
                "--json",
            ],
            keys_dir,
        )

        assert result.returncode == 1
        response = json.loads(result.stdout)
        assert response["ok"] is False
        assert response["valid"] is False
        assert "malformed" in response.get("detail", "").lower()

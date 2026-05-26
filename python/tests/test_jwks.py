"""JWKS endpoint tests.

Verifies that:
1. GET /.well-known/jwks.json returns a valid JWK Set without auth
2. The returned JWK actually verifies real passport tokens (roundtrip)
"""

from __future__ import annotations

import base64
import json
import signal as _signal
import threading
import time
import urllib.request

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import GovernanceProxy, _public_key_to_jwk, serve_proxy


def _jwk_to_public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    """Reconstruct an EC public key from a JWK dict."""

    def b64url_decode(s: str) -> bytes:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)

    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return numbers.public_key()


class TestJWKSerialization:
    def test_jwk_has_required_fields(self, public_key):
        jwk = _public_key_to_jwk(public_key)
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["alg"] == "ES256"
        assert jwk["use"] == "sig"
        assert "kid" in jwk
        assert "x" in jwk
        assert "y" in jwk

    def test_jwk_coordinates_are_32_bytes(self, public_key):
        jwk = _public_key_to_jwk(public_key)

        def b64url_decode(s: str) -> bytes:
            pad = "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s + pad)

        assert len(b64url_decode(jwk["x"])) == 32
        assert len(b64url_decode(jwk["y"])) == 32

    def test_jwk_roundtrip_verifies_token(self, private_key, public_key):
        """The JWK must reconstruct a key that actually verifies real tokens."""
        mission = MissionPassport(
            agent_id="jwk-test",
            mission="roundtrip",
            allowed_tools=["read"],
            max_tool_calls=1,
        )
        token = issue_passport(mission, private_key, ttl_s=60)

        jwk = _public_key_to_jwk(public_key)
        reconstructed = _jwk_to_public_key(jwk)

        claims = jwt.decode(
            token,
            reconstructed,
            algorithms=["ES256"],
            audience="vibap-proxy",
        )
        assert claims["sub"] == "jwk-test"


class TestJWKSEndpoint:
    """End-to-end HTTP test of /.well-known/jwks.json."""

    @pytest.fixture
    def http_proxy(self, proxy, private_key, unused_tcp_port):
        original = _signal.signal
        _signal.signal = lambda *_a, **_kw: None  # type: ignore[assignment]

        def run() -> None:
            serve_proxy(
                proxy=proxy,
                private_key=private_key,
                host="127.0.0.1",
                port=unused_tcp_port,
                require_auth=True,  # Prove JWKS works even with auth required
                no_tls=True,
            )

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        base = f"http://127.0.0.1:{unused_tcp_port}"
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(base + "/health", timeout=0.5) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                time.sleep(0.05)

        yield base
        _signal.signal = original

    def test_jwks_endpoint_returns_valid_jwk_set(self, http_proxy):
        """JWKS endpoint must be publicly accessible (no Bearer token required)."""
        with urllib.request.urlopen(http_proxy + "/.well-known/jwks.json") as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))

        assert "keys" in body
        assert len(body["keys"]) == 1
        jwk = body["keys"][0]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"

    def test_jwks_key_verifies_real_passport(self, http_proxy, private_key):
        """Full external-verifier flow: fetch JWKS, verify a real passport."""
        # Fetch JWKS (no auth)
        with urllib.request.urlopen(http_proxy + "/.well-known/jwks.json") as resp:
            jwks = json.loads(resp.read().decode("utf-8"))

        # Issue a passport (signed with the proxy's private key)
        mission = MissionPassport(
            agent_id="external-verifier-test",
            mission="prove jwks works",
            allowed_tools=["x"],
            max_tool_calls=1,
        )
        token = issue_passport(mission, private_key, ttl_s=60)

        # An external verifier uses JWKS to verify WITHOUT needing the private key
        reconstructed = _jwk_to_public_key(jwks["keys"][0])
        claims = jwt.decode(
            token,
            reconstructed,
            algorithms=["ES256"],
            audience="vibap-proxy",
        )
        assert claims["sub"] == "external-verifier-test"

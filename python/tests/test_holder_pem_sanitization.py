"""Regression tests for holder_public_key_pem cryptography leak sanitization.

The proxy /session/start handler accepts a ``holder_public_key_pem`` field
for AAT sessions with proof-of-possession. When the ``cryptography`` library
fails to parse the PEM, the exception text (e.g. "Could not deserialize key
data") must NOT leak into the HTTP 400 response body. The ``ValueError``
raised at the load site must use a fixed code
(``holder_public_key_pem_invalid``) instead of interpolating ``str(exc)``
from cryptography internals.

Same defect class as the SVID (``peer_jwt_svid_verification_failed``) and
AAT (``parent_token_aat_validation_failed``) leak closures.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

import jwt
import pytest

from vibap.passport import ALGORITHM, MissionPassport, issue_passport
from vibap.proxy import GovernanceProxy, serve_proxy


def _build_server_thread(proxy: GovernanceProxy, private_key, port: int):
    import signal as _signal

    original = _signal.signal
    _signal.signal = lambda *_a, **_kw: None  # type: ignore[assignment]

    def run() -> None:
        try:
            serve_proxy(
                proxy=proxy,
                private_key=private_key,
                host="127.0.0.1",
                port=port,
                require_auth=False,
                no_tls=True,
            )
        except Exception:  # noqa: BLE001
            pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(0.05)
    else:
        _signal.signal = original
        raise RuntimeError(f"proxy never became healthy: {last_exc}")

    def shutdown() -> None:
        _signal.signal = original

    return thread, base, shutdown


def _post(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"raw": body}
        return exc.code, parsed


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _issue_aat_like_token(
    private_key,
    *,
    aat_type: str = "delegation",
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": "https://tenuo.example/issuer",
            "sub": "holder-pem-sanitize-agent",
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "aat_type": aat_type,
            "del_depth": 0,
            "del_max_depth": 2,
            "mission_ref": {"uri": "https://issuer.example/md/holder-pem.jwt"},
            "authorization_details": [
                {
                    "type": "attenuating_agent_token",
                    "tools": {"read": {}},
                    "max_tool_calls": 2,
                }
            ],
        },
        private_key,
        algorithm=ALGORITHM,
    )


class TestHolderPemSanitization:
    """Verify cryptography library internals don't leak into HTTP 400 body."""

    @pytest.fixture
    def http_proxy(self, proxy, private_key):
        port = _free_port()
        thread, base, shutdown = _build_server_thread(proxy, private_key, port)
        yield base
        shutdown()

    def test_garbage_pem_does_not_leak_cryptography_internals(
        self, http_proxy, private_key
    ):
        """An invalid PEM should produce a fixed error code, not library text."""
        base = http_proxy
        aat_token = _issue_aat_like_token(private_key)
        status, body = _post(
            base + "/session/start",
            {
                "token": aat_token,
                "token_type": "aat",
                "holder_public_key_pem": "-----BEGIN PUBLIC KEY-----\nNOT_A_REAL_KEY\n-----END PUBLIC KEY-----",
            },
        )
        rendered = json.dumps(body)
        assert status == 400
        assert "holder_public_key_pem_invalid" in rendered
        # No cryptography internals leaked
        for sentinel in (
            "Could not deserialize",
            "cryptography",
            "openssl",
            "Malformed",
            "Bad digest",
            "asn1",
        ):
            assert sentinel not in rendered
            assert sentinel.lower() not in rendered.lower()

    def test_random_bytes_pem_does_not_leak(self, http_proxy, private_key):
        """Random garbage PEM should not leak library error details."""
        base = http_proxy
        aat_token = _issue_aat_like_token(private_key)
        status, body = _post(
            base + "/session/start",
            {
                "token": aat_token,
                "token_type": "aat",
                "holder_public_key_pem": "GARBAGE_DATA_12345",
            },
        )
        rendered = json.dumps(body)
        assert status == 400
        assert "holder_public_key_pem_invalid" in rendered
        for sentinel in (
            "Could not deserialize",
            "Unsupported key type",
            "openssl",
            "asn1",
            "Malformed",
        ):
            assert sentinel not in rendered
            assert sentinel.lower() not in rendered.lower()

    def test_non_ec_key_gets_ec_only_error(self, http_proxy, private_key):
        """A valid RSA key should get the 'must encode an EC public key' error."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        base = http_proxy
        aat_token = _issue_aat_like_token(private_key)
        status, body = _post(
            base + "/session/start",
            {
                "token": aat_token,
                "token_type": "aat",
                "holder_public_key_pem": rsa_pem,
            },
        )
        rendered = json.dumps(body)
        assert status == 400
        assert "EC public key" in rendered

"""Hub client must trust the Personal Hub's pinned self-signed TLS cert.

The Personal Hub auto-generates a self-signed certificate under
``<home>/tls/cert.pem`` and serves HTTPS on loopback. That certificate is not
installed in the system trust store, so the default ``urlopen`` SSL context
rejects it and the client reports ``hub_unavailable`` even when the Hub is
healthy. ``hub_request`` must build a client context that trusts *only* the
pinned cert for loopback https URLs and keep default (system) verification for
every other case.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from vibap.personal_hub import hub_request


_PYTHON_ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _hub_command(home: Path, port: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "vibap.cli",
        "hub",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--home",
        str(home),
    ]


def _hub_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(_PYTHON_ROOT)
    environment.pop("ARDUR_NO_TLS", None)
    return environment


def _stop_process(process: subprocess.Popen[str]) -> tuple[str, str]:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return process.communicate(timeout=5)


def _wait_for_health(process: subprocess.Popen[str], url: str) -> int:
    """Poll the Hub healthz with the pinned-trust path disabled so we know the
    server is up regardless of client trust configuration."""

    deadline = time.monotonic() + 8
    verifier = ssl.create_default_context()
    verifier.check_hostname = False
    verifier.verify_mode = ssl.CERT_NONE
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError(
                f"Hub exited before health check: rc={process.returncode}; "
                f"stdout={stdout!r}; stderr={stderr!r}"
            )
        try:
            with urllib.request.urlopen(url, timeout=0.5, context=verifier) as response:
                return int(response.status)
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(0.05)
    raise AssertionError(f"Hub health check did not become ready: {last_error}")


def test_hub_request_trusts_pinned_self_signed_cert(tmp_path: Path) -> None:
    """``hub_request`` returns ``ok: True`` against a loopback Hub that serves
    the auto-generated ``<home>/tls/cert.pem`` self-signed certificate."""

    home = tmp_path / "personal-home"
    port = _free_port()
    hub_url = f"https://127.0.0.1:{port}"
    process = subprocess.Popen(
        _hub_command(home, port),
        cwd=tmp_path,
        env=_hub_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert (
            _wait_for_health(process, f"{hub_url}/health") == 200
        ), "Hub never became healthy"
        # The pinned cert must exist for the client-trust path to engage.
        assert (home / "tls" / "cert.pem").is_file()

        response = hub_request(
            "GET",
            "/health",
            hub_url=hub_url,
            home=str(home),
        )
    finally:
        _stop_process(process)

    assert response.get("ok") is True
    assert response.get("error_code") in (None, "")
    assert response.get("error") in (None, "")


def test_hub_request_rejects_non_pinned_self_signed_cert(tmp_path: Path) -> None:
    """A loopback https Hub whose cert differs from ``<home>/tls/cert.pem``
    must still be rejected. This proves the client trusts ONLY the pinned cert,
    not arbitrary loopback self-signed certs."""

    home = tmp_path / "personal-home"
    # Pre-create the home with a pinned cert that the Hub will NOT use: we run
    # the Hub with an explicit, different cert pair, but the client will load
    # ``<home>/tls/cert.pem`` and must reject the mismatched server cert.
    home.mkdir(parents=True)
    home_tls_dir = home / "tls"
    home_tls_dir.mkdir()
    bogus_cert = home_tls_dir / "cert.pem"
    bogus_key = home_tls_dir / "key.pem"
    bogus_cert.write_text("not-a-real-cert", encoding="utf-8")
    bogus_key.write_text("not-a-real-key", encoding="utf-8")

    # Generate a real, different cert for the server to use.
    from vibap.tls import generate_self_signed_cert

    server_tls_dir = tmp_path / "server-tls"
    server_key_path, server_cert_path, _fingerprint = generate_self_signed_cert(
        server_tls_dir
    )

    port = _free_port()
    hub_url = f"https://127.0.0.1:{port}"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "vibap.cli",
            "hub",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--home",
            str(home),
            "--tls-cert",
            str(server_cert_path),
            "--tls-key",
            str(server_key_path),
        ],
        cwd=tmp_path,
        env=_hub_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # Wait for the server to be ready using the SERVER's real cert.
        verifier = ssl.create_default_context()
        verifier.check_hostname = False
        verifier.verify_mode = ssl.CERT_NONE
        deadline = time.monotonic() + 8
        ready = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(
                    f"{hub_url}/health", timeout=0.5, context=verifier
                ) as response:
                    ready = int(response.status) == 200
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        assert ready, "Hub never became healthy with the server's real cert"

        response = hub_request(
            "GET",
            "/health",
            hub_url=hub_url,
            home=str(home),
        )
    finally:
        _stop_process(process)

    # The pinned ``<home>/tls/cert.pem`` is bogus and does not match the
    # server's real cert, so verification must fail closed → hub_unavailable.
    assert response.get("ok") is False
    assert response.get("error_code") == "hub_unavailable"


@pytest.mark.parametrize(
    "hub_url",
    [
        "http://127.0.0.1:8765",
        "https://hub.example.test:8765",
        "https://192.168.1.10:8765",
    ],
)
def test_loopback_hub_ssl_context_returns_none_for_non_loopback_or_http(
    hub_url: str,
) -> None:
    """The pinned-trust path must not engage for plain http, non-loopback
    hosts, or RFC1918 addresses — those keep the default system trust store."""

    from vibap.personal_hub import _loopback_hub_ssl_context

    assert _loopback_hub_ssl_context(hub_url, home=None) is None


def test_loopback_hub_ssl_context_returns_none_when_cert_missing(
    tmp_path: Path,
) -> None:
    """If the pinned cert file does not exist, fall back to default trust."""

    from vibap.personal_hub import _loopback_hub_ssl_context

    home = tmp_path / "empty-home"
    home.mkdir()
    assert (
        _loopback_hub_ssl_context("https://127.0.0.1:8765", home=str(home)) is None
    )

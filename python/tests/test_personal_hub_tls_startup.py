"""Organic startup tests for the Personal Hub TLS boundary."""

from __future__ import annotations

import json
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

from vibap.tls import generate_self_signed_cert


_PYTHON_ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _hub_command(tmp_path: Path, port: int, *extra: str) -> list[str]:
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
        str(tmp_path / "personal-home"),
        *extra,
    ]


def _hub_environment(*, disable_tls: bool = False) -> dict[str, str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(_PYTHON_ROOT)
    if disable_tls:
        environment["ARDUR_NO_TLS"] = "1"
    else:
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


def _wait_for_health(
    process: subprocess.Popen[str],
    url: str,
    *,
    context: ssl.SSLContext | None = None,
) -> int:
    deadline = time.monotonic() + 8
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError(
                f"Hub exited before health check: rc={process.returncode}; "
                f"stdout={stdout!r}; stderr={stderr!r}"
            )
        try:
            with urllib.request.urlopen(url, timeout=0.5, context=context) as response:
                return int(response.status)
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(0.05)
    raise AssertionError(f"Hub health check did not become ready: {last_error}")


@pytest.mark.parametrize(
    ("extra_args", "disable_tls"),
    [
        ((), True),
        (("--tls-cert", "missing-cert.pem"), False),
        (("--tls-key", "missing-key.pem"), False),
        (
            (
                "--tls-cert",
                "missing-cert.pem",
                "--tls-key",
                "missing-key.pem",
            ),
            False,
        ),
    ],
    ids=(
        "environment-disable",
        "certificate-only",
        "key-only",
        "missing-pair",
    ),
)
def test_tls_expected_hub_never_starts_plain_http(
    tmp_path: Path,
    extra_args: tuple[str, ...],
    disable_tls: bool,
) -> None:
    port = _free_port()
    process = subprocess.Popen(
        _hub_command(tmp_path, port, *extra_args),
        cwd=tmp_path,
        env=_hub_environment(disable_tls=disable_tls),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        try:
            return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            plaintext_status: int | None = None
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/health", timeout=1
                ) as response:
                    plaintext_status = int(response.status)
            except (OSError, urllib.error.URLError):
                # Refusal or protocol failure is the expected fail-closed outcome.
                plaintext_status = None
            pytest.fail(
                "TLS-expected Personal Hub stayed alive instead of failing closed; "
                f"plaintext_health_status={plaintext_status}"
            )
        stdout, stderr = process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            _stop_process(process)

    assert return_code == 1
    assert stderr == ""
    payload = json.loads(stdout)
    assert payload["condition"] == "hub_tls_material_invalid"
    assert "--no-tls" in json.dumps(payload)
    assert str(tmp_path) not in stdout
    assert "missing-cert.pem" not in stdout
    assert "missing-key.pem" not in stdout
    assert not (tmp_path / "personal-home").exists()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as replacement:
        replacement.bind(("127.0.0.1", port))


def test_default_hub_startup_serves_real_https(tmp_path: Path) -> None:
    port = _free_port()
    process = subprocess.Popen(
        _hub_command(tmp_path, port),
        cwd=tmp_path,
        env=_hub_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        assert (
            _wait_for_health(
                process,
                f"https://127.0.0.1:{port}/health",
                context=context,
            )
            == 200
        )
    finally:
        _stdout, stderr = _stop_process(process)

    assert "auto-generated self-signed cert" in stderr
    assert "TLS disabled" not in stderr


def test_explicit_valid_hub_tls_pair_serves_real_https(tmp_path: Path) -> None:
    key_path, cert_path, _fingerprint = generate_self_signed_cert(
        tmp_path / "explicit-tls"
    )
    port = _free_port()
    process = subprocess.Popen(
        _hub_command(
            tmp_path,
            port,
            "--tls-cert",
            str(cert_path),
            "--tls-key",
            str(key_path),
        ),
        cwd=tmp_path,
        env=_hub_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        assert (
            _wait_for_health(
                process,
                f"https://127.0.0.1:{port}/health",
                context=context,
            )
            == 200
        )
    finally:
        _stdout, stderr = _stop_process(process)

    assert "cert fingerprint" in stderr
    assert "TLS disabled" not in stderr


def test_existing_but_invalid_hub_tls_pair_fails_before_bind(
    tmp_path: Path,
) -> None:
    cert_path = tmp_path / "invalid-cert.pem"
    key_path = tmp_path / "invalid-key.pem"
    cert_path.write_text("not a certificate", encoding="utf-8")
    key_path.write_text("not a private key", encoding="utf-8")
    port = _free_port()
    result = subprocess.run(
        _hub_command(
            tmp_path,
            port,
            "--tls-cert",
            str(cert_path),
            "--tls-key",
            str(key_path),
        ),
        cwd=tmp_path,
        env=_hub_environment(),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 1
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["condition"] == "hub_tls_material_invalid"
    assert "Traceback" not in result.stdout
    assert str(tmp_path) not in result.stdout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as replacement:
        replacement.bind(("127.0.0.1", port))


def test_explicit_no_tls_remains_the_hub_plain_http_control(tmp_path: Path) -> None:
    port = _free_port()
    process = subprocess.Popen(
        _hub_command(tmp_path, port, "--no-tls"),
        cwd=tmp_path,
        env=_hub_environment(disable_tls=True),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert _wait_for_health(process, f"http://127.0.0.1:{port}/health") == 200
    finally:
        _stdout, stderr = _stop_process(process)

    assert "WARNING: TLS disabled" in stderr


def test_personal_home_validation_precedes_hub_tls_validation(tmp_path: Path) -> None:
    existing_file_home = tmp_path / "personal-home"
    existing_file_home.write_text("not a directory", encoding="utf-8")
    port = _free_port()
    result = subprocess.run(
        _hub_command(tmp_path, port),
        cwd=tmp_path,
        env=_hub_environment(disable_tls=True),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 1
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["condition"] == "path_not_directory"
    assert "hub_tls_material_invalid" not in result.stdout
    assert str(tmp_path) not in result.stdout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as replacement:
        replacement.bind(("127.0.0.1", port))

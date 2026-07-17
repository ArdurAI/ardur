"""Organic startup tests for the governance proxy TLS boundary."""

from __future__ import annotations

import os
import json
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


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _proxy_command(tmp_path: Path, port: int, *extra: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "vibap.proxy",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--keys-dir",
        str(tmp_path / "keys"),
        "--state-dir",
        str(tmp_path / "state"),
        "--log-path",
        str(tmp_path / "audit.jsonl"),
        "--no-require-auth",
        *extra,
    ]


def _proxy_environment(tmp_path: Path, *, disable_tls: bool = False) -> dict[str, str]:
    environment = dict(os.environ)
    environment["VIBAP_HOME"] = str(tmp_path / "home")
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
    stdout, stderr = process.communicate(timeout=5)
    return stdout, stderr


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
                f"proxy exited before health check: rc={process.returncode}; "
                f"stdout={stdout!r}; stderr={stderr!r}"
            )
        try:
            with urllib.request.urlopen(url, timeout=0.5, context=context) as response:
                return int(response.status)
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(0.05)
    raise AssertionError(f"proxy health check did not become ready: {last_error}")


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
def test_tls_expected_never_starts_plain_http(
    tmp_path: Path,
    extra_args: tuple[str, ...],
    disable_tls: bool,
) -> None:
    port = _free_port()
    process = subprocess.Popen(
        _proxy_command(tmp_path, port, *extra_args),
        cwd=tmp_path,
        env=_proxy_environment(tmp_path, disable_tls=disable_tls),
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
                "TLS-expected proxy stayed alive instead of failing closed; "
                f"plaintext_health_status={plaintext_status}"
            )
        stdout, stderr = process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            _stop_process(process)

    assert return_code == 1
    assert stdout == ""
    assert "TLS configuration is unavailable" in stderr
    assert "--no-tls" in stderr
    assert "Traceback" not in stderr
    assert str(tmp_path) not in stderr
    assert "missing-cert.pem" not in stderr
    assert "missing-key.pem" not in stderr
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as replacement:
        replacement.bind(("127.0.0.1", port))


def test_default_startup_serves_real_https(tmp_path: Path) -> None:
    port = _free_port()
    process = subprocess.Popen(
        _proxy_command(tmp_path, port),
        cwd=tmp_path,
        env=_proxy_environment(tmp_path),
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


def test_explicit_valid_tls_pair_serves_real_https(tmp_path: Path) -> None:
    key_path, cert_path, _fingerprint = generate_self_signed_cert(
        tmp_path / "explicit-tls"
    )
    port = _free_port()
    process = subprocess.Popen(
        _proxy_command(
            tmp_path,
            port,
            "--tls-cert",
            str(cert_path),
            "--tls-key",
            str(key_path),
        ),
        cwd=tmp_path,
        env=_proxy_environment(tmp_path),
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


def test_existing_but_invalid_tls_pair_fails_without_binding_or_traceback(
    tmp_path: Path,
) -> None:
    cert_path = tmp_path / "invalid-cert.pem"
    key_path = tmp_path / "invalid-key.pem"
    cert_path.write_text("not a certificate", encoding="utf-8")
    key_path.write_text("not a private key", encoding="utf-8")
    port = _free_port()
    result = subprocess.run(
        _proxy_command(
            tmp_path,
            port,
            "--tls-cert",
            str(cert_path),
            "--tls-key",
            str(key_path),
        ),
        cwd=tmp_path,
        env=_proxy_environment(tmp_path),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "TLS configuration is unavailable" in result.stderr
    assert "Traceback" not in result.stderr
    assert str(tmp_path) not in result.stderr
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as replacement:
        replacement.bind(("127.0.0.1", port))


def test_explicit_no_tls_remains_the_plain_http_control(tmp_path: Path) -> None:
    port = _free_port()
    process = subprocess.Popen(
        _proxy_command(tmp_path, port, "--no-tls"),
        cwd=tmp_path,
        env=_proxy_environment(tmp_path, disable_tls=True),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert _wait_for_health(process, f"http://127.0.0.1:{port}/health") == 200
    finally:
        _stdout, stderr = _stop_process(process)

    assert "WARNING: TLS disabled" in stderr


def test_ardur_start_rejects_environment_only_tls_disable_before_side_effects(
    tmp_path: Path,
) -> None:
    keys_dir = tmp_path / "cli-keys"
    state_dir = tmp_path / "cli-state"
    audit_log = tmp_path / "cli-audit.jsonl"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "vibap.cli",
            "start",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(audit_log),
        ],
        cwd=tmp_path,
        env=_proxy_environment(tmp_path, disable_tls=True),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 1
    assert result.stderr == ""
    assert payload["condition"] == "start_tls_material_invalid"
    assert "--no-tls" in json.dumps(payload)
    assert str(tmp_path) not in result.stdout
    assert not keys_dir.exists()
    assert not state_dir.exists()
    assert not audit_log.exists()

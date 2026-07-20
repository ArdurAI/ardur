"""Regression tests for generated TLS certificate identities."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from vibap.tls import generate_self_signed_cert, resolve_tls_paths


def _subject_alt_name(cert_path: Path) -> x509.SubjectAlternativeName:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value


def test_generated_certificate_uses_dns_san_for_dns_identity(tmp_path: Path) -> None:
    _key_path, cert_path, _fingerprint = generate_self_signed_cert(
        tmp_path / "tls",
        hostname="localhost",
    )

    san = _subject_alt_name(cert_path)
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert san.get_values_for_type(x509.IPAddress) == []


def test_existing_managed_certificate_preserves_original_identity(
    tmp_path: Path,
) -> None:
    tls_dir = tmp_path / "tls"
    _key_path, cert_path, original_fingerprint = generate_self_signed_cert(
        tls_dir,
        hostname="localhost",
    )
    original_certificate = cert_path.read_bytes()

    _key_path, reused_cert_path, reused_fingerprint = generate_self_signed_cert(
        tls_dir,
        hostname="127.0.0.1",
    )

    assert reused_cert_path.read_bytes() == original_certificate
    assert reused_fingerprint == original_fingerprint
    san = _subject_alt_name(reused_cert_path)
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert san.get_values_for_type(x509.IPAddress) == []


@pytest.mark.parametrize("identity", ["127.0.0.1", "::1"])
def test_generated_certificate_uses_ip_san_for_ip_identity(
    tmp_path: Path,
    identity: str,
) -> None:
    _key_path, cert_path, _fingerprint = generate_self_signed_cert(
        tmp_path / "tls",
        hostname=identity,
    )

    san = _subject_alt_name(cert_path)
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address(identity)]
    assert san.get_values_for_type(x509.DNSName) == []


@pytest.mark.parametrize("wildcard_bind", ["0.0.0.0", "::"])
def test_auto_generated_certificate_does_not_use_wildcard_bind_as_identity(
    tmp_path: Path,
    wildcard_bind: str,
) -> None:
    result = resolve_tls_paths(home=tmp_path, hostname=wildcard_bind)

    assert result is not None
    cert_path, _key_path, _fingerprint = result
    san = _subject_alt_name(cert_path)
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert san.get_values_for_type(x509.IPAddress) == []

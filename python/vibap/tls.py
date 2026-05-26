"""TLS utilities — self-signed cert generation and SSL context for the proxy/hub."""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _default_tls_dir(home: Path | None = None) -> Path:
    from .passport import DEFAULT_HOME

    return (home or DEFAULT_HOME) / "tls"


def generate_self_signed_cert(
    tls_dir: Path,
    *,
    hostname: str = "127.0.0.1",
    key_filename: str = "key.pem",
    cert_filename: str = "cert.pem",
) -> tuple[Path, Path, str]:
    """Generate a self-signed EC P-256 cert with a SHA-256 fingerprint."""
    tls_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    key_path = tls_dir / key_filename
    cert_path = tls_dir / cert_filename

    if key_path.exists() and cert_path.exists():
        fingerprint = _cert_fingerprint(cert_path)
        return key_path, cert_path, fingerprint

    private_key = ec.generate_private_key(ec.SECP256R1())
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address(hostname))]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert_path.chmod(0o644)

    fingerprint = _cert_fingerprint(cert_path)
    return key_path, cert_path, fingerprint


def _cert_fingerprint(cert_path: Path) -> str:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    fp_bytes = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in fp_bytes)


def create_ssl_context(
    cert_path: str | Path,
    key_path: str | Path,
) -> ssl.SSLContext:
    """Create a server-side SSL context with secure defaults."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def resolve_tls_paths(
    tls_cert: str | Path | None = None,
    tls_key: str | Path | None = None,
    *,
    home: Path | None = None,
    hostname: str = "127.0.0.1",
) -> tuple[Path, Path, str] | None:
    """Resolve TLS cert/key or auto-generate. Returns (cert_path, key_path, fingerprint) or None if TLS disabled."""
    no_tls = os.environ.get("ARDUR_NO_TLS", "").strip().lower() in ("1", "true", "yes")

    if tls_cert and tls_key:
        cert_path = Path(tls_cert)
        key_path = Path(tls_key)
        if not cert_path.exists():
            print(f"TLS cert not found: {cert_path}", file=sys.stderr)
            return None
        if not key_path.exists():
            print(f"TLS key not found: {key_path}", file=sys.stderr)
            return None
        fingerprint = _cert_fingerprint(cert_path)
        return cert_path, key_path, fingerprint

    if not tls_cert and not tls_key and not no_tls:
        tls_dir = _default_tls_dir(home)
        key_path, cert_path, fingerprint = generate_self_signed_cert(tls_dir, hostname=hostname)
        print(f"[tls] auto-generated self-signed cert for {hostname}", file=sys.stderr)
        print(f"[tls] fingerprint: {fingerprint}", file=sys.stderr)
        return cert_path, key_path, fingerprint

    return None

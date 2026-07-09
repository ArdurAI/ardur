#!/usr/bin/env python3
"""Validate the static contract for the Ardur proxy OCI release."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "python" / "pyproject.toml"
DOCKERFILE = REPO_ROOT / "Dockerfile.proxy"
RUNTIME_LOCK = REPO_ROOT / "packaging" / "oci" / "runtime-requirements.lock"

EXPECTED_IMAGE = "ghcr.io/ardurai/ardur-proxy"
EXPECTED_RUNTIME_PACKAGES = {
    "attrs",
    "cffi",
    "cryptography",
    "jsonschema",
    "jsonschema-specifications",
    "pycparser",
    "pyjwt",
    "referencing",
    "rpds-py",
}


class ValidationError(ValueError):
    pass


def project_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    project_match = re.search(r"(?ms)^\[project\]\s*$(.*?)(?=^\[|\Z)", text)
    if project_match is None:
        raise ValidationError("python/pyproject.toml has no [project] table")
    version_match = re.search(
        r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',
        project_match.group(1),
        flags=re.MULTILINE,
    )
    if version_match is None:
        raise ValidationError("project.version must be a stable X.Y.Z version")
    return version_match.group(1)


def validate_runtime_lock() -> None:
    lock = RUNTIME_LOCK.read_text(encoding="utf-8")
    packages = {
        match.group(1).lower().replace("_", "-")
        for match in re.finditer(r"^([A-Za-z0-9_-]+)==[^\s]+\s*\\$", lock, re.MULTILINE)
    }
    if packages != EXPECTED_RUNTIME_PACKAGES:
        raise ValidationError(
            "runtime lock package set drifted: "
            f"expected {sorted(EXPECTED_RUNTIME_PACKAGES)}, got {sorted(packages)}"
        )
    if lock.count("--hash=sha256:") < len(packages) * 2:
        raise ValidationError("every runtime dependency must retain artifact hashes")
    forbidden = (
        "--index-url",
        "--extra-index-url",
        "--trusted-host",
        "git+",
        "http://",
    )
    if any(value in lock.lower() for value in forbidden):
        raise ValidationError(
            "runtime lock contains a forbidden package source override"
        )


def validate_dockerfile() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    required_patterns = {
        "digest-pinned Python 3.13 base": (
            r"^ARG PYTHON_IMAGE=python:3\.13\.14-slim-trixie@sha256:[0-9a-f]{64}$"
        ),
        "hashed runtime dependency install": r"--require-hashes",
        "installed dependency consistency check": r"python -m pip check",
        "non-root numeric runtime user": r"^USER 65532:65532$",
        "durable Ardur home": r"VIBAP_HOME=/home/ardur/\.ardur",
        "declared state volume": r'^VOLUME \["/home/ardur/\.ardur"\]$',
        "canonical source label": r"org\.opencontainers\.image\.source=",
        "revision label": r"org\.opencontainers\.image\.revision=",
        "version label": r"org\.opencontainers\.image\.version=",
        "license label": r'org\.opencontainers\.image\.licenses="MIT"',
        "explicit key path": r'"--keys-dir", "/home/ardur/\.ardur/keys"',
        "explicit state path": r'"--state-dir", "/home/ardur/\.ardur/sessions"',
        "explicit audit path": r'"--log-path", "/home/ardur/\.ardur/governance\.jsonl"',
    }
    missing = [
        name
        for name, pattern in required_patterns.items()
        if re.search(pattern, dockerfile, flags=re.MULTILINE) is None
    ]
    if missing:
        raise ValidationError("Dockerfile.proxy is missing: " + ", ".join(missing))
    if re.search(r"(?im)^ENV .*?(TOKEN|PASSWORD|SECRET|PRIVATE_KEY)=", dockerfile):
        raise ValidationError("Dockerfile.proxy must not embed credentials")


def validate_release_tag(version: str, release_tag: str | None) -> None:
    if release_tag is None:
        return
    expected = f"v{version}"
    if release_tag != expected:
        raise ValidationError(f"release tag must be {expected}, got {release_tag}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-tag", help="require the exact vX.Y.Z release tag")
    parser.add_argument(
        "--print-version",
        action="store_true",
        help="print only the validated project version",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        version = project_version()
        validate_runtime_lock()
        validate_dockerfile()
        validate_release_tag(version, args.expected_tag)
    except (OSError, ValidationError) as exc:
        print(f"OCI release validation failed: {exc}", file=sys.stderr)
        return 1

    if args.print_version:
        print(version)
    else:
        print(f"validated {EXPECTED_IMAGE}:{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Supply-chain invariants for the published governance demo images."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
DIGEST_PIN = re.compile(r"^.+:[^@\s]+@sha256:[0-9a-f]{64}$")
PYTHON_BISCUIT_COMPATIBLE_BASE = re.compile(
    r"^python:3\.(?:10|11|12|13)(?:[.-])"
)


@pytest.mark.parametrize(
    ("relative_path", "expected_base_count"),
    [
        ("examples/autogen-quickstart/Dockerfile", 2),
        ("examples/langchain-quickstart/Dockerfile", 1),
    ],
)
def test_published_demo_images_digest_pin_external_bases(
    relative_path: str,
    expected_base_count: int,
) -> None:
    dockerfile = REPO_ROOT / relative_path
    from_lines = [
        line.strip()
        for line in dockerfile.read_text(encoding="utf-8").splitlines()
        if line.startswith("FROM ")
    ]

    assert len(from_lines) == expected_base_count
    for line in from_lines:
        reference = line.split()[1]
        assert DIGEST_PIN.fullmatch(reference), (
            f"{relative_path} must pin {reference!r} to a full sha256 digest"
        )
        if reference.startswith("python:"):
            assert PYTHON_BISCUIT_COMPATIBLE_BASE.match(reference), (
                "biscuit-python 0.4.0 requires Python 3.13 or older; "
                f"{relative_path} uses {reference!r}"
            )

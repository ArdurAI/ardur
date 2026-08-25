"""Focused DX test for scripts/setup-dev.sh Python minimum-version enforcement.

Covers the fresh-user defect closed on origin/dev=b4763a1:

``scripts/setup-dev.sh`` had a Go toolchain version check (``version_lt``) but
no equivalent Python version check. When ``PYTHON_BIN`` resolved to a Python
below Ardur's ``requires-python`` floor (``>=3.10`` in ``python/pyproject.toml``),
the script passed ``command -v``, created a broken venv, and failed deep inside
a pyproject.toml build-dependency traceback instead of a clear, actionable
"Python X is below Ardur's minimum (Y)" message.

The fix mirrors the Go block: extract the minimum from ``pyproject.toml``, get
the interpreter's ``major.minor``, compare via ``version_lt``, and exit 1 with a
clear message before venv creation.

This test uses a stub interpreter script so it is deterministic and does not
depend on the host having a real below-3.10 Python installed.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP_DEV = REPO_ROOT / "scripts" / "setup-dev.sh"


def _make_stub_python(tmp_path: Path, version: str) -> Path:
    """Create an executable ``python`` stub that reports ``version`` via -c."""
    stub = tmp_path / f"python-{version}"
    major, minor = version.split(".")[:2]
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'if [ "$1" = "-c" ]; then\n'
        f'  echo "{major}.{minor}"\n'
        f"  exit 0\n"
        "fi\n"
        f'echo "stub python {version}"\n',
        encoding="utf-8",
    )
    os.chmod(stub, stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return stub


def test_setup_dev_rejects_below_minimum_python(tmp_path: Path) -> None:
    """setup-dev.sh exits 1 with a clear message when PYTHON_BIN is below 3.10."""
    stub_python = _make_stub_python(tmp_path, "3.9")
    env = {**os.environ, "PYTHON_BIN": str(stub_python)}
    result = subprocess.run(
        ["bash", str(SETUP_DEV), "--skip-go"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 1, (
        f"expected exit 1 for below-minimum Python, got {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # The clear, actionable message must appear on stderr.
    assert "below Ardur's minimum" in result.stderr, (
        f"expected clear 'below minimum' message on stderr, got:\n{result.stderr}"
    )
    assert "3.9" in result.stderr, (
        f"expected actual version '3.9' in message, got:\n{result.stderr}"
    )
    assert "3.10" in result.stderr, (
        f"expected minimum version '3.10' in message, got:\n{result.stderr}"
    )
    # Must NOT reach venv creation (the opaque failure path).
    assert "Creating/updating python/.venv" not in result.stdout, (
        "setup-dev.sh created the venv despite a below-minimum Python; "
        "the version check must run BEFORE venv creation."
    )


def test_setup_dev_reports_interpreter_and_minimum(tmp_path: Path) -> None:
    """Even a below-minimum Python prints the interpreter + minimum diagnostic line."""
    stub_python = _make_stub_python(tmp_path, "3.9")
    env = {**os.environ, "PYTHON_BIN": str(stub_python)}
    result = subprocess.run(
        ["bash", str(SETUP_DEV), "--skip-go"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # The informational line mirrors the Go block's toolchain version echo.
    combined = result.stdout + result.stderr
    assert "Ardur minimum: 3.10" in combined, (
        f"expected 'Ardur minimum: 3.10' diagnostic, got:\n{combined}"
    )
    assert "3.9" in combined, (
        f"expected actual interpreter version '3.9' in diagnostic, got:\n{combined}"
    )


@pytest.mark.skipif(
    sys.version_info < (3, 10),
    reason="above-minimum path requires the test host Python to meet Ardur's floor",
)
def test_setup_dev_accepts_meeting_python_skips_venv() -> None:
    """With --skip-python the version check is bypassed entirely (no regression)."""
    result = subprocess.run(
        ["bash", str(SETUP_DEV), "--skip-python", "--skip-go"],
        cwd=REPO_ROOT,
        env={**os.environ},
        capture_output=True,
        text=True,
        timeout=60,
    )
    # --skip-python short-circuits the whole Python block, including the new check.
    assert result.returncode == 0, (
        f"expected exit 0 for --skip-python, got {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "setup complete" in result.stdout

"""Focused DX test for scripts/conductor-bootstrap.sh and scripts/check-local.sh
Python minimum-version enforcement.

Siblings of the defect closed on origin/dev=65e54be for scripts/setup-dev.sh.
Both ``conductor-bootstrap.sh`` and ``check-local.sh`` resolve ``PYTHON_BIN``
with a ``python3`` fallback and no minimum-version check. ``conductor-bootstrap.sh``
is documented in AGENTS.md as the first command in every new session (before
``setup-dev.sh``), so a fresh macOS user with only the system Python 3.9.6 hits
it with no version guard.

The fix mirrors the established ``version_lt`` pattern from ``setup-dev.sh``:
extract the minimum from ``python/pyproject.toml``, get the interpreter's
``major.minor``, compare via ``version_lt``, and exit 1 with a clear message
before running any graph/validation Python.

This test uses a stub interpreter script so it is deterministic and does not
depend on the host having a real below-3.10 Python installed.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONDUCTOR_BOOTSTRAP = REPO_ROOT / "scripts" / "conductor-bootstrap.sh"
CHECK_LOCAL = REPO_ROOT / "scripts" / "check-local.sh"


def _make_stub_python(tmp_path: Path, version: str) -> Path:
    """Create an executable ``python`` stub that reports ``version`` via -c."""
    stub = tmp_path / f"python-{version}"
    major, minor = version.split(".")[:2]
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "-c" ]; then\n'
        f'  echo "{major}.{minor}"\n'
        "  exit 0\n"
        "fi\n"
        f'echo "stub python {version}"\n',
        encoding="utf-8",
    )
    os.chmod(stub, stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return stub


def test_conductor_bootstrap_rejects_below_minimum_python(tmp_path: Path) -> None:
    """conductor-bootstrap.sh exits 1 with a clear message when PYTHON_BIN < 3.10."""
    stub_python = _make_stub_python(tmp_path, "3.9")
    env = {**os.environ, "PYTHON_BIN": str(stub_python)}
    result = subprocess.run(
        ["bash", str(CONDUCTOR_BOOTSTRAP)],
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
    assert "below Ardur's minimum" in result.stderr, (
        f"expected clear 'below minimum' message on stderr, got:\n{result.stderr}"
    )
    assert "3.9" in result.stderr, (
        f"expected actual version '3.9' in message, got:\n{result.stderr}"
    )
    assert "3.10" in result.stderr, (
        f"expected minimum version '3.10' in message, got:\n{result.stderr}"
    )
    # Must NOT reach context generation (the opaque failure path).
    assert "wrote .context" not in result.stdout, (
        "conductor-bootstrap.sh wrote context despite a below-minimum Python; "
        "the version check must run BEFORE context generation."
    )


def test_check_local_rejects_below_minimum_python(tmp_path: Path) -> None:
    """check-local.sh exits 1 with a clear message when PYTHON_BIN < 3.10."""
    stub_python = _make_stub_python(tmp_path, "3.9")
    env = {**os.environ, "PYTHON_BIN": str(stub_python)}
    result = subprocess.run(
        ["bash", str(CHECK_LOCAL), "--quick"],
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
    assert "below Ardur's minimum" in result.stderr, (
        f"expected clear 'below minimum' message on stderr, got:\n{result.stderr}"
    )
    assert "3.9" in result.stderr, (
        f"expected actual version '3.9' in message, got:\n{result.stderr}"
    )
    assert "3.10" in result.stderr, (
        f"expected minimum version '3.10' in message, got:\n{result.stderr}"
    )
    # Must NOT reach any validation steps (the opaque failure path).
    assert "checks passed" not in result.stdout, (
        "check-local.sh ran validation steps despite a below-minimum Python; "
        "the version check must run BEFORE any validation."
    )

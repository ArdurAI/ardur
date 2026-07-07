"""Regression tests for DEFAULT_HOME lazy-init: import must not create .vibap."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Modules whose import must NOT create .vibap in cwd or HOME.
_IMPORT_SIDE_EFFECT_MODULES = [
    "passport",
    "cli",
    "proxy",
    "claude_code_hook",
    "gemini_cli_hook",
    "codex_app_server_fixture",
    "personal_hub",
    "tls",
    "claude_code_report",
]


def _run_in_clean_env(module: str, *, extra_code: str = "") -> subprocess.CompletedProcess[str]:
    """Run a Python snippet in a subprocess with isolated cwd and HOME."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cwd = Path(tmpdir) / "cwd"
        home = Path(tmpdir) / "home"
        cwd.mkdir()
        home.mkdir()
        code = f"from vibap import {module}"
        if extra_code:
            code += "\n" + extra_code
        return subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=str(cwd),
            env={
                **os.environ,
                "HOME": str(home),
                "VIBAP_HOME": "",
                "PYTHONPATH": os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
            },
            timeout=30,
        )


@pytest.mark.parametrize("module", _IMPORT_SIDE_EFFECT_MODULES)
def test_import_does_not_create_vibap_home(module: str) -> None:
    """Importing each vibap module must not create .vibap in cwd or HOME."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cwd = Path(tmpdir) / "cwd"
        home = Path(tmpdir) / "home"
        cwd.mkdir()
        home.mkdir()
        result = subprocess.run(
            [sys.executable, "-c", f"from vibap import {module}"],
            capture_output=True,
            text=True,
            cwd=str(cwd),
            env={
                **os.environ,
                "HOME": str(home),
                "VIBAP_HOME": "",
                "PYTHONPATH": os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
            },
            timeout=30,
        )
        assert result.returncode == 0, (
            f"import vibap.{module} failed: {result.stderr}"
        )
        assert not (cwd / ".vibap").exists(), (
            f"import vibap.{module} created .vibap in cwd"
        )
        assert not (home / ".vibap").exists(), (
            f"import vibap.{module} created .vibap in HOME"
        )


def test_ensure_default_home_dir_creates_0o700() -> None:
    """_ensure_default_home_dir() creates the home with mode 0o700."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir) / "home"
        home.mkdir()
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from vibap.passport import _ensure_default_home_dir; "
                    "import os; "
                    "target = _ensure_default_home_dir(); "
                    "mode = target.stat().st_mode & 0o777; "
                    "print(f'MODE={mode:o}'); "
                    "print(f'PATH={target}')"
                ),
            ],
            capture_output=True,
            text=True,
            cwd=str(home),
            env={
                **os.environ,
                "HOME": str(home),
                "VIBAP_HOME": "",
                "PYTHONPATH": os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
            },
            timeout=30,
        )
        assert result.returncode == 0, f"_ensure_default_home_dir failed: {result.stderr}"
        # Parse the MODE= line from stdout
        mode_line = [l for l in result.stdout.splitlines() if l.startswith("MODE=")]
        assert mode_line, f"No MODE= line in output: {result.stdout}"
        mode_str = mode_line[0].split("=", 1)[1]
        assert mode_str == "700", f"Expected mode 700, got {mode_str}"


def test_keygen_creates_home_with_0o700() -> None:
    """generate_keypair() triggers home creation at 0o700 on first actual use."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir) / "home"
        home.mkdir()
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from vibap.passport import generate_keypair, DEFAULT_HOME; "
                    "import os; "
                    "generate_keypair(); "
                    "mode = DEFAULT_HOME.stat().st_mode & 0o777; "
                    "print(f'MODE={mode:o}'); "
                    "print(f'PATH={DEFAULT_HOME}')"
                ),
            ],
            capture_output=True,
            text=True,
            cwd=str(home),
            env={
                **os.environ,
                "HOME": str(home),
                "VIBAP_HOME": "",
                "PYTHONPATH": os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
            },
            timeout=30,
        )
        assert result.returncode == 0, f"generate_keypair failed: {result.stderr}"
        mode_line = [l for l in result.stdout.splitlines() if l.startswith("MODE=")]
        assert mode_line, f"No MODE= line in output: {result.stdout}"
        mode_str = mode_line[0].split("=", 1)[1]
        assert mode_str == "700", f"Expected mode 700, got {mode_str}"


def test_explicit_vibap_home_not_recreated() -> None:
    """An existing $VIBAP_HOME with a custom mode is NOT silently changed to 0o700."""
    with tempfile.TemporaryDirectory() as tmpdir:
        explicit_home = Path(tmpdir) / "explicit_home"
        explicit_home.mkdir(mode=0o750)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from vibap.passport import _ensure_default_home_dir; "
                    "import os; "
                    "target = _ensure_default_home_dir(); "
                    "mode = target.stat().st_mode & 0o777; "
                    "print(f'MODE={mode:o}'); "
                    "print(f'PATH={target}')"
                ),
            ],
            capture_output=True,
            text=True,
            cwd=str(tmpdir),
            env={
                **os.environ,
                "HOME": str(tmpdir),
                "VIBAP_HOME": str(explicit_home),
                "PYTHONPATH": os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
            },
            timeout=30,
        )
        assert result.returncode == 0, f"_ensure_default_home_dir failed: {result.stderr}"
        mode_line = [l for l in result.stdout.splitlines() if l.startswith("MODE=")]
        assert mode_line, f"No MODE= line in output: {result.stdout}"
        mode_str = mode_line[0].split("=", 1)[1]
        assert mode_str == "750", (
            f"Explicit VIBAP_HOME mode was changed from 750 to {mode_str}"
        )


def test_empty_vibap_home_treated_as_unset() -> None:
    """VIBAP_HOME='' falls through to the cwd candidate (treated as unset)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cwd = Path(tmpdir) / "cwd"
        home = Path(tmpdir) / "home"
        cwd.mkdir()
        home.mkdir()
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from vibap.passport import _default_home_dir; "
                    "import os; "
                    "target = _default_home_dir(); "
                    "print(f'PATH={target}')"
                ),
            ],
            capture_output=True,
            text=True,
            cwd=str(cwd),
            env={
                **os.environ,
                "HOME": str(home),
                "VIBAP_HOME": "",
                "PYTHONPATH": os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
            },
            timeout=30,
        )
        assert result.returncode == 0, f"_default_home_dir failed: {result.stderr}"
        path_line = [l for l in result.stdout.splitlines() if l.startswith("PATH=")]
        assert path_line, f"No PATH= line in output: {result.stdout}"
        resolved = path_line[0].split("=", 1)[1]
        expected = str((cwd / ".vibap").resolve())
        assert Path(resolved).resolve() == Path(expected).resolve(), (
            f"Empty VIBAP_HOME should resolve to cwd/.vibap ({expected}), got {resolved}"
        )

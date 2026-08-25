"""Focused DX tests for the rwt-phase1-fresh-user harness venv/symlink fixes.

Covers two fresh-user defects closed on origin/dev=7074c90:

1. ``copy_python_source_for_wheel`` must not crash when the canonical
   dev-install ``python/.venv/`` directory exists in the repo worktree. That
   directory is gitignored (created by ``scripts/setup-dev.sh``) and its
   ``bin/python*`` symlinks are expected. The fail-closed symlink guard must
   still reject any non-gitignored symlink.
2. ``version_info`` must resolve ``versions.ardur`` from the harness venv
   (``ctx.venv/bin/python -c "import vibap; print(vibap.__version__)"``) after
   ``install_ardur`` succeeds, not from the ambient interpreter. ``"missing"``
   remains the ImportError / exit-nonzero fallback.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS = REPO_ROOT / "scripts" / "run-rwt-phase1-fresh-user.py"


def _load_harness():
    spec = importlib.util.spec_from_file_location("rwt_phase1_harness", HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _init_git_repo(repo_root: Path) -> None:
    """Create a minimal git repo with ``python/.venv/`` gitignored."""
    repo_root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=str(repo_root), check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=str(repo_root), check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo_root), check=True)
    # Mirror the real repo root .gitignore which ignores ``.venv/`` so the
    # dev-install directory created by ``scripts/setup-dev.sh`` is not treated
    # as tracked/dirty source by the symlink guard.
    (repo_root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    (repo_root / "python" / "vibap").mkdir(parents=True, exist_ok=True)
    (repo_root / "python" / "vibap" / "__init__.py").write_text(
        "__version__ = '0.0.0-test'\n", encoding="utf-8"
    )
    (repo_root / "python" / "pyproject.toml").write_text(
        "[project]\nname = 'fake'\nversion = '0.0.0-test'\n", encoding="utf-8"
    )
    subprocess.run(["git", "add", "."], cwd=str(repo_root), check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=str(repo_root), check=True)


def test_rwt_phase1_harness_copy_python_source_skips_gitignored_venv_symlinks(tmp_path):
    """D1: the canonical dev-install ``python/.venv/`` must not trip the guard.

    A user following the documented README quickstart runs
    ``scripts/setup-dev.sh`` before ``scripts/run-rwt-phase1-fresh-user.py``.
    That creates ``python/.venv/bin/python`` -> system python symlinks. The
    symlink guard must honor ``.gitignore`` and skip them; before the fix the
    harness emitted ``status: PASS`` and then raised ``RuntimeError``.
    """
    harness = _load_harness()
    repo_root = tmp_path / "repo"
    _init_git_repo(repo_root)

    # Simulate the dev-install venv created by scripts/setup-dev.sh: a gitignored
    # python/.venv/ directory containing the standard bin/python* symlinks.
    venv_bin = repo_root / "python" / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    real_python = sys.executable
    for link_name in ("python", "python3", "python3.13"):
        try:
            (venv_bin / link_name).symlink_to(real_python)
        except (NotImplementedError, OSError):
            pytest.skip("symlink creation is not supported in this test environment")

    # Sanity: the gitignored assertion under test.
    check = subprocess.run(
        ["git", "check-ignore", "--quiet", "python/.venv/bin/python"],
        cwd=str(repo_root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    assert check.returncode == 0, "test setup precondition: python/.venv must be gitignored"

    ctx = SimpleNamespace(repo=repo_root, temp_root=tmp_path / "temp")

    # Must NOT raise. Pre-fix this raised RuntimeError about symlinks.
    copied = harness.copy_python_source_for_wheel(ctx)

    assert copied == tmp_path / "temp" / "source" / "python"
    assert (copied / "pyproject.toml").is_file()
    assert (copied / "vibap" / "__init__.py").is_file()
    # The gitignored dev venv must not be copied into the wheel source tree.
    assert not (copied / ".venv").exists()


def test_rwt_phase1_harness_copy_python_source_still_rejects_tracked_symlink(tmp_path):
    """D1 regression guard: non-gitignored symlinks must still fail closed.

    The gitignore skip is scoped to ignored paths only; a tracked/dirty
    symlink elsewhere under ``python/`` must still raise ``RuntimeError`` so
    future tracked-symlink drift cannot be silently dereferenced into the wheel.
    """
    harness = _load_harness()
    repo_root = tmp_path / "repo"
    _init_git_repo(repo_root)

    secret_file = tmp_path / "outside-secret.txt"
    secret_file.write_text("do-not-copy\n", encoding="utf-8")
    link_path = repo_root / "python" / "vibap" / "linked-secret.txt"
    try:
        link_path.symlink_to(secret_file)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is not supported in this test environment")

    ctx = SimpleNamespace(repo=repo_root, temp_root=tmp_path / "temp")
    with pytest.raises(RuntimeError, match="symlink"):
        harness.copy_python_source_for_wheel(ctx)


def test_rwt_phase1_harness_version_info_resolves_ardur_from_harness_venv(tmp_path):
    """D2: ``versions.ardur`` comes from ``ctx.venv/bin/python``, not ambient.

    After ``install_ardur`` the freshly-created harness venv is the
    authoritative location of the ardur package. Probing the ambient
    interpreter would always yield ``"missing"`` on a clean host. This test
    points ``ctx.venv`` at the worktree's own dev venv (created by
    ``scripts/setup-dev.sh``) which has ardur installed, and asserts the
    resolved version matches ``vibap.__version__`` exactly.
    """
    harness = _load_harness()
    dev_venv = REPO_ROOT / "python" / ".venv"
    if not (dev_venv / "bin" / "python").exists():
        pytest.skip("worktree dev venv (python/.venv) not present; run scripts/setup-dev.sh first")

    ctx = SimpleNamespace(
        python_bin=sys.executable,
        ardur_bin=dev_venv / "bin" / "ardur",
        venv=dev_venv,
        repo=REPO_ROOT,
        project=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
    )

    versions = harness.version_info(ctx)

    expected = harness.redact_text(_vibap_version_from(dev_venv / "bin" / "python"))
    assert versions["ardur"] == expected
    # Sanity: a real dev install must not report the fallback sentinel.
    assert versions["ardur"] != "missing"
    assert versions["ardur"]  # non-empty


def test_rwt_phase1_harness_version_info_ardur_missing_when_venv_python_lacks_vibap(tmp_path):
    """D2 fallback: a venv python that cannot import vibap yields ``"missing"``.

    Constructs a throwaway venv that does NOT have ardur installed and asserts
    the harness reports ``"missing"`` instead of raising or emitting an
    ``exit_<code>`` string. This pins the fail-soft contract for the
    ImportError / exit-nonzero branch.
    """
    harness = _load_harness()
    bare_venv = tmp_path / "bare-venv"
    result = subprocess.run(
        [sys.executable, "-m", "venv", str(bare_venv)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0 or not (bare_venv / "bin" / "python").exists():
        pytest.skip("python -m venv is not available in this environment")

    ctx = SimpleNamespace(
        python_bin=sys.executable,
        ardur_bin=bare_venv / "bin" / "ardur",
        venv=bare_venv,
        repo=tmp_path,
        project=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
    )

    versions = harness.version_info(ctx)

    assert versions["ardur"] == "missing"


def _vibap_version_from(venv_python: Path) -> str:
    """Return ``vibap.__version__`` as resolved by ``venv_python``."""
    proc = subprocess.run(
        [str(venv_python), "-c", "import vibap; print(vibap.__version__)"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"vibap not importable from {venv_python}: {proc.stderr}"
    return proc.stdout.strip()

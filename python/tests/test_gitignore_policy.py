"""Regression coverage for generated key and runtime artifact ignore policy."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

GENERATED_ARTIFACTS = (
    "passport_private.pem",
    "passport_public.pem",
    "scratch/private.pem",
    "scratch/private.key",
    "passport_state.lock",
    "replay_cache.json",
    "revoked.json",
    "lineage_hashes.json",
)

# Runtime artifacts that ``ardur protect`` writes to the project root.
# These carry signed mission tokens and private key material — never commit.
ROOT_RUNTIME_ARTIFACTS = (
    "active_mission.jwt",
    "keys/passport_private.pem",
    "keys/passport_public.pem",
    "claude-code-hook-python",
    "claude-code-pre_tool_use",
    "claude-code-pre_tool_use.sha256",
)

VISIBLE_FILES = (
    "ordinary.txt",
    "runtime/replay_cache.json",
    "docs/specs/fixtures/new-public.pem",
    "docs/specs/conformance/runtime-evidence-v0.1/new-public.pem",
    "site/static/repo/docs/specs/fixtures/new-public.pem",
)

REVIEWED_PEM_PREFIXES = (
    "docs/specs/",
    "site/static/repo/docs/specs/",
)


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args),
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def test_recursive_staging_skips_generated_artifacts_but_keeps_public_fixtures(
    tmp_path: Path,
) -> None:
    """Normal recursive staging must exclude runtime output without hiding fixtures."""

    shutil.copy2(REPO_ROOT / ".gitignore", tmp_path / ".gitignore")
    _git("init", "--quiet", cwd=tmp_path)

    for relative in (*GENERATED_ARTIFACTS, *VISIBLE_FILES):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")

    _git("add", "--all", cwd=tmp_path)
    staged = set(
        _git("diff", "--cached", "--name-only", "-z", cwd=tmp_path)
        .stdout.rstrip("\0")
        .split("\0")
    )

    assert set(GENERATED_ARTIFACTS).isdisjoint(staged)
    assert {".gitignore", *VISIBLE_FILES} == staged


def test_root_runtime_artifacts_are_ignored(tmp_path: Path) -> None:
    """Root-level ``ardur protect`` outputs must never be accidentally staged."""

    shutil.copy2(REPO_ROOT / ".gitignore", tmp_path / ".gitignore")
    _git("init", "--quiet", cwd=tmp_path)

    for relative in ROOT_RUNTIME_ARTIFACTS:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")

    _git("add", "--all", cwd=tmp_path)
    staged = set(
        _git("diff", "--cached", "--name-only", "-z", cwd=tmp_path)
        .stdout.rstrip("\0")
        .split("\0")
    )

    assert set(ROOT_RUNTIME_ARTIFACTS).isdisjoint(staged)
    assert {".gitignore"} == staged


def test_tracked_pem_files_stay_in_reviewed_public_fixture_trees() -> None:
    """A force-added PEM outside the public fixture trees must fail repository tests."""

    tracked = (
        _git("ls-files", "-z", "*.pem", cwd=REPO_ROOT).stdout.rstrip("\0").split("\0")
    )

    assert tracked
    assert all(path.startswith(REVIEWED_PEM_PREFIXES) for path in tracked)

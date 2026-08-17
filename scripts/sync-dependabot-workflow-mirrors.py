#!/usr/bin/env python3
"""Prepare workflow-mirror updates for a trusted Dependabot PR."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = Path(".github/workflows")
MIRROR_ROOT = Path("site/static/repo/.github/workflows")
SOURCE_SYNC = REPO_ROOT / "site" / "scripts" / "sync_source_docs.py"


def _git(*args: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=text,
    )
    return completed.stdout


def _is_workflow(path: Path) -> bool:
    return path.parent == WORKFLOW_ROOT and path.suffix == ".yml"


def _mirror_for(source: Path) -> Path:
    return Path("site/static/repo") / source


def validate_changed_paths(changes: list[tuple[str, Path]]) -> list[Path]:
    """Return changed workflows or reject anything outside the narrow contract."""
    sources: set[Path] = set()
    mirrors: set[Path] = set()
    unexpected: list[str] = []

    for status, path in changes:
        if status != "M":
            unexpected.append(f"{status} {path.as_posix()}")
        elif _is_workflow(path):
            sources.add(path)
        elif path.parent == MIRROR_ROOT and path.suffix == ".yml":
            mirrors.add(path)
        else:
            unexpected.append(f"{status} {path.as_posix()}")

    expected_mirrors = {_mirror_for(source) for source in sources}
    unexpected.extend(
        f"M {path.as_posix()}" for path in sorted(mirrors - expected_mirrors)
    )
    if not sources:
        unexpected.append("no modified .github/workflows/*.yml source")
    if unexpected:
        details = ", ".join(unexpected)
        raise ValueError(f"Dependabot workflow mirror sync refused: {details}")
    return sorted(sources, key=lambda path: path.as_posix())


def _changed_paths(base_sha: str, head_sha: str) -> list[tuple[str, Path]]:
    raw = _git(
        "diff",
        "--name-status",
        "--no-renames",
        "-z",
        f"{base_sha}...{head_sha}",
        text=False,
    )
    assert isinstance(raw, bytes)
    fields = raw.rstrip(b"\0").split(b"\0") if raw else []
    if len(fields) % 2:
        raise ValueError("Dependabot workflow mirror sync refused: malformed git diff")
    return [
        (os.fsdecode(fields[index]), Path(os.fsdecode(fields[index + 1])))
        for index in range(0, len(fields), 2)
    ]


def _paths_from_git(*args: str) -> set[Path]:
    raw = _git(*args, "-z", text=False)
    assert isinstance(raw, bytes)
    return {Path(os.fsdecode(value)) for value in raw.split(b"\0") if value}


def prepare(base_sha: str, head_sha: str) -> list[Path]:
    if _git("status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("Dependabot workflow mirror sync refused: checkout is dirty")

    base_commit = str(_git("rev-parse", "--verify", f"{base_sha}^{{commit}}")).strip()
    head_commit = str(_git("rev-parse", "--verify", f"{head_sha}^{{commit}}")).strip()
    sources = validate_changed_paths(_changed_paths(base_commit, head_commit))
    mirrors = [_mirror_for(source) for source in sources]

    for source in sources:
        content = _git("show", f"{head_commit}:{source.as_posix()}", text=False)
        assert isinstance(content, bytes)
        (REPO_ROOT / source).write_bytes(content)

    subprocess.run([sys.executable, str(SOURCE_SYNC)], cwd=REPO_ROOT, check=True)

    changed = _paths_from_git("diff", "--name-only")
    untracked = _paths_from_git("ls-files", "--others", "--exclude-standard")
    allowed = set(sources) | set(mirrors)
    unexpected = (changed | untracked) - allowed
    if unexpected:
        details = ", ".join(path.as_posix() for path in sorted(unexpected))
        raise ValueError(
            f"Dependabot workflow mirror sync refused generated paths: {details}"
        )

    mirror_content = {mirror: (REPO_ROOT / mirror).read_bytes() for mirror in mirrors}
    subprocess.run(["git", "reset", "--hard", base_commit], cwd=REPO_ROOT, check=True)
    subprocess.run(["git", "checkout", "--detach", head_commit], cwd=REPO_ROOT, check=True)

    for mirror, content in mirror_content.items():
        (REPO_ROOT / mirror).write_bytes(content)
    subprocess.run(
        ["git", "add", "--", *(mirror.as_posix() for mirror in mirrors)],
        cwd=REPO_ROOT,
        check=True,
    )

    staged = _paths_from_git("diff", "--cached", "--name-only")
    unexpected_staged = staged - set(mirrors)
    if unexpected_staged:
        details = ", ".join(path.as_posix() for path in sorted(unexpected_staged))
        raise ValueError(
            f"Dependabot workflow mirror sync refused staged paths: {details}"
        )
    print(f"prepared {len(staged)} workflow mirror update(s)")
    return sorted(staged, key=lambda path: path.as_posix())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="trusted pull-request base commit")
    parser.add_argument("--head", required=True, help="Dependabot pull-request head commit")
    args = parser.parse_args()
    prepare(args.base, args.head)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Synchronize repository assets that must ship inside the Python wheel."""

from __future__ import annotations

import argparse
import shutil
import stat
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PLUGIN = REPO_ROOT / "plugins" / "claude-code"
PACKAGED_PLUGIN = REPO_ROOT / "python" / "vibap" / "_plugins" / "claude-code"
LICENSE_SOURCE = REPO_ROOT / "LICENSE"
LICENSE_TARGET = REPO_ROOT / "python" / "LICENSE"
PLUGIN_ASSETS = (
    Path(".claude-plugin/plugin.json"),
    Path("hooks/hooks.json"),
    Path("hooks/post_tool_use"),
    Path("hooks/post_tool_use_failure"),
    Path("hooks/pre_tool_use"),
    Path("hooks/subagent_start"),
    Path("hooks/subagent_stop"),
)


def source_files() -> dict[Path, Path]:
    files: dict[Path, Path] = {}
    for relative_path in PLUGIN_ASSETS:
        path = SOURCE_PLUGIN / relative_path
        if path.is_symlink():
            raise RuntimeError(f"refusing symlinked package asset: {path}")
        if not path.is_file():
            raise RuntimeError(f"missing canonical package asset: {path}")
        files[relative_path] = path
    return files


def packaged_files() -> dict[Path, Path]:
    if not PACKAGED_PLUGIN.is_dir():
        return {}
    return {
        path.relative_to(PACKAGED_PLUGIN): path
        for path in PACKAGED_PLUGIN.rglob("*")
        if path.is_file() or path.is_symlink()
    }


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def check() -> list[str]:
    failures: list[str] = []
    expected = source_files()
    actual = packaged_files()
    for relative_path in sorted(expected.keys() - actual.keys()):
        failures.append(f"missing packaged plugin asset: {relative_path}")
    for relative_path in sorted(actual.keys() - expected.keys()):
        failures.append(f"unexpected packaged plugin asset: {relative_path}")
    for relative_path in sorted(expected.keys() & actual.keys()):
        source = expected[relative_path]
        target = actual[relative_path]
        if target.is_symlink():
            failures.append(
                f"packaged plugin asset must not be a symlink: {relative_path}"
            )
        elif source.read_bytes() != target.read_bytes():
            failures.append(f"stale packaged plugin asset: {relative_path}")
        elif mode(source) != mode(target):
            failures.append(f"mode drift for packaged plugin asset: {relative_path}")
    if not LICENSE_TARGET.is_file():
        failures.append("missing python/LICENSE")
    elif LICENSE_SOURCE.read_bytes() != LICENSE_TARGET.read_bytes():
        failures.append("python/LICENSE differs from root LICENSE")
    return failures


def sync() -> None:
    if PACKAGED_PLUGIN.exists():
        shutil.rmtree(PACKAGED_PLUGIN)
    for relative_path, source in source_files().items():
        target = PACKAGED_PLUGIN / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)
    shutil.copy2(LICENSE_SOURCE, LICENSE_TARGET)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift without modifying generated package assets",
    )
    args = parser.parse_args()
    if not args.check:
        sync()
    failures = check()
    if failures:
        for failure in failures:
            print(f"error: {failure}")
        return 1
    print(f"verified {len(source_files()) + 1} Python package assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

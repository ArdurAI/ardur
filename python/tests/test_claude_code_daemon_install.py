from __future__ import annotations

import errno
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from vibap import claude_code_daemon as daemon


def _fake_compiler(
    monkeypatch: pytest.MonkeyPatch,
    *,
    binary: bytes,
) -> None:
    monkeypatch.setattr(daemon, "_candidate_native_compilers", lambda: ["fake-cc"])

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        output = Path(command[command.index("-o") + 1])
        output.write_bytes(binary)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(daemon.subprocess, "run", fake_run)


def _stamp_path(command: Path) -> Path:
    return command.with_name(f"{command.name}.sha256")


def _staging_files(home: Path) -> list[Path]:
    return sorted(home.glob(".*.tmp"))


def test_native_hook_install_replaces_only_destination_staging_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_compiler(monkeypatch, binary=b"native-hook-v1")
    real_replace = daemon.os.replace
    replacements: list[tuple[Path, Path]] = []

    def require_same_directory(
        source: os.PathLike[str], destination: os.PathLike[str]
    ) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        assert source_path.parent == destination_path.parent
        replacements.append((source_path, destination_path))
        real_replace(source_path, destination_path)

    monkeypatch.setattr(daemon.os, "replace", require_same_directory)

    installed = daemon.install_native_pre_tool_use_command(home=tmp_path, force=True)

    assert installed is not None
    stamp = _stamp_path(installed)
    assert installed.read_bytes() == b"native-hook-v1"
    assert stat.S_IMODE(installed.stat().st_mode) == 0o700
    assert stat.S_IMODE(stamp.stat().st_mode) == 0o600
    assert daemon._native_pre_tool_use_stamp_matches(
        installed,
        daemon._native_pre_tool_use_source_digest(
            daemon._native_pre_tool_use_client_c_source()
        ),
    )
    assert len(replacements) == 2
    assert _staging_files(tmp_path) == []


def test_native_hook_install_restores_valid_pair_when_stamp_commit_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_compiler(monkeypatch, binary=b"native-hook-original")
    installed = daemon.install_native_pre_tool_use_command(home=tmp_path, force=True)
    assert installed is not None
    stamp = _stamp_path(installed)
    original_command = installed.read_bytes()
    original_stamp = stamp.read_bytes()

    _fake_compiler(monkeypatch, binary=b"native-hook-replacement")
    real_replace = daemon.os.replace
    failed = False

    def fail_first_stamp_replace(
        source: os.PathLike[str],
        destination: os.PathLike[str],
    ) -> None:
        nonlocal failed
        destination_path = Path(destination)
        if destination_path == stamp and not failed:
            failed = True
            raise OSError(errno.EIO, "simulated stamp replacement failure")
        real_replace(source, destination)

    monkeypatch.setattr(daemon.os, "replace", fail_first_stamp_replace)

    with pytest.raises(OSError, match="simulated stamp replacement failure"):
        daemon.install_native_pre_tool_use_command(home=tmp_path, force=True)

    assert failed is True
    assert installed.read_bytes() == original_command
    assert stamp.read_bytes() == original_stamp
    assert stat.S_IMODE(installed.stat().st_mode) == 0o700
    assert stat.S_IMODE(stamp.stat().st_mode) == 0o600
    assert _staging_files(tmp_path) == []


def test_native_hook_install_across_real_filesystems_when_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system_tmp = Path("/tmp")
    if not system_tmp.is_dir() or not os.access(system_tmp, os.W_OK):
        pytest.skip("/tmp is not writable on this host")
    if system_tmp.stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("host exposes only one writable test filesystem")

    build_parent = Path(tempfile.mkdtemp(prefix="ardur-exdev-build-", dir=system_tmp))
    try:
        monkeypatch.setattr(tempfile, "tempdir", str(build_parent))
        installed = daemon.install_native_pre_tool_use_command(
            home=tmp_path,
            force=True,
        )
    finally:
        shutil.rmtree(build_parent, ignore_errors=True)

    if installed is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")
    assert installed.stat().st_dev == tmp_path.stat().st_dev
    assert _stamp_path(installed).stat().st_dev == tmp_path.stat().st_dev
    assert _staging_files(tmp_path) == []

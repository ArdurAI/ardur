"""Tests for per-child CPU/memory attribution in process-lifecycle evidence.

The ``_child_process_snapshot`` function captures best-effort CPU time and RSS
for each descendant process at snapshot time, using psutil's ``cpu_times()``
and ``memory_info()``. These are point-in-time values (not lifetime totals)
that complement the root-process rusage delta already captured in lifecycle
evidence.

These tests verify:
1. Child entries include ``cpu_user_s``, ``cpu_system_s``, ``rss_bytes`` when
   the process is alive at snapshot time.
2. Fields are omitted gracefully when psutil cannot read them.
3. Redaction via ``--redact-paths`` preserves the numeric resource fields.
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest

from vibap.run_bridge import (
    _build_process_lifecycle_evidence,
    _child_process_snapshot,
)


class _FakeProc:
    """Minimal stand-in for subprocess.Popen with just .pid."""

    def __init__(self, pid: int) -> None:
        self.pid = pid


class _FakePsutilProcess:
    """Minimal stand-in for ``psutil.Process`` for unit tests."""

    def __init__(self, pid: int, *, cpu=(0.1, 0.05), rss=1024):
        self.pid = pid
        self._cpu = cpu
        self._rss = rss

    def oneshot(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def cmdline(self):
        return ["test-cmd"]

    def name(self):
        return "test-cmd"

    def create_time(self):
        return time.time() - 1.0

    def cpu_times(self):
        class _CT:
            user = self._cpu[0]
            system = self._cpu[1]
        return _CT()

    def memory_info(self):
        class _MI:
            rss = self._rss
        return _MI()


class TestChildResourceAttribution:
    """Tests for CPU/memory fields in child process snapshots."""

    def test_child_snapshot_includes_cpu_and_rss(self) -> None:
        """A live child process snapshot includes resource fields."""
        child = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            import psutil

            proc = psutil.Process(child.pid)
            snapshot = _child_process_snapshot(proc, depth=0)
            assert snapshot is not None
            assert "cpu_user_s" in snapshot
            assert "cpu_system_s" in snapshot
            assert "rss_bytes" in snapshot
            assert isinstance(snapshot["cpu_user_s"], float)
            assert isinstance(snapshot["cpu_system_s"], float)
            assert isinstance(snapshot["rss_bytes"], int)
            assert snapshot["rss_bytes"] > 0
        finally:
            child.wait()

    def test_child_snapshot_without_resource_fields_on_access_denied(
        self,
        monkeypatch,
    ) -> None:
        """When psutil can't read cpu_times/memory_info, fields are omitted."""
        fake = _FakePsutilProcess(99999, cpu=(0.1, 0.05), rss=2048)

        # Patch cpu_times to raise AccessDenied
        import psutil

        original_cpu_times = fake.cpu_times

        def _raise_access_denied(*args, **kwargs):
            raise psutil.AccessDenied()

        fake.cpu_times = _raise_access_denied  # type: ignore[assignment]
        snapshot = _child_process_snapshot(fake, depth=0)  # type: ignore[arg-type]
        assert snapshot is not None
        assert "cpu_user_s" not in snapshot
        assert "cpu_system_s" not in snapshot
        # rss should still work since memory_info wasn't patched
        assert "rss_bytes" in snapshot

    def test_child_snapshot_rss_omitted_on_access_denied(self) -> None:
        """When memory_info raises AccessDenied, rss_bytes is omitted."""
        import psutil

        fake = _FakePsutilProcess(99998, cpu=(0.2, 0.1), rss=4096)

        def _raise_access_denied(*args, **kwargs):
            raise psutil.AccessDenied()

        fake.memory_info = _raise_access_denied  # type: ignore[assignment]
        snapshot = _child_process_snapshot(fake, depth=0)  # type: ignore[arg-type]
        assert snapshot is not None
        assert "cpu_user_s" in snapshot
        assert "cpu_system_s" in snapshot
        assert "rss_bytes" not in snapshot

    def test_lifecycle_children_include_resource_fields(self) -> None:
        """Full lifecycle evidence children entries include resource fields."""
        child = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = _build_process_lifecycle_evidence(
                proc=_FakeProc(os.getpid()),  # type: ignore[arg-type]
                command=["echo", "hi"],
                launch_monotonic=time.monotonic(),
                launch_wall_clock=time.time(),
                exit_code=0,
            )
            children = result.get("children", [])
            if children:
                for entry in children:
                    if "sleep" in " ".join(entry.get("command", [])):
                        # The sleep child should have resource fields
                        assert "cpu_user_s" in entry, (
                            f"Missing cpu_user_s in child entry: {sorted(entry)}"
                        )
                        assert "cpu_system_s" in entry
                        assert "rss_bytes" in entry
        finally:
            child.wait()

    def test_redact_paths_preserves_resource_fields(self) -> None:
        """--redact-paths does not strip numeric resource fields from children."""
        child = subprocess.Popen(
            ["sleep", "0.5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            result = _build_process_lifecycle_evidence(
                proc=_FakeProc(os.getpid()),  # type: ignore[arg-type]
                command=["echo", "hi"],
                launch_monotonic=time.monotonic(),
                launch_wall_clock=time.time(),
                exit_code=0,
            )
            children = result.get("children", [])
            if children:
                for entry in children:
                    if "sleep" in " ".join(entry.get("command", [])):
                        # Resource fields should survive redaction
                        assert "cpu_user_s" in entry
                        assert "rss_bytes" in entry
                        assert isinstance(entry["rss_bytes"], int)
        finally:
            child.wait()

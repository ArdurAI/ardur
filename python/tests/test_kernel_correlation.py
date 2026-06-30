"""Unit tests for the kernelcapture daemon client + cgroup helpers.

These run on any platform: the cgroup helpers are parameterized by a root
directory (env ``ARDUR_RUN_CGROUP_ROOT``) so a temp dir stands in for
``/sys/fs/cgroup``, and the daemon client speaks AF_UNIX which works on macOS
and Linux alike.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from vibap import kernel_correlation as kc


@pytest.fixture
def sockdir():
    """A short-pathed temp dir for AF_UNIX sockets.

    AF_UNIX paths are capped (104 bytes on macOS, 108 on Linux); the deep
    pytest ``tmp_path`` blows past that on macOS, so bind sockets under /tmp.
    """
    path = Path(tempfile.mkdtemp(dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


# ── cgroup helpers ─────────────────────────────────────────────────────────────


def _fake_cgroup_root(base: Path, *, unified: bool) -> Path:
    root = base / "cgroup"
    root.mkdir(parents=True, exist_ok=True)
    if unified:
        (root / "cgroup.controllers").write_text("cpu memory\n", encoding="utf-8")
    return root


def test_cgroup_v2_available_requires_controllers_file(tmp_path: Path) -> None:
    unified = _fake_cgroup_root(tmp_path / "a", unified=True)
    legacy = _fake_cgroup_root(tmp_path / "b", unified=False)
    assert kc.cgroup_v2_available(unified) is True
    assert kc.cgroup_v2_available(legacy) is False


def test_create_run_cgroup_returns_handle_with_inode_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _fake_cgroup_root(tmp_path, unified=True)
    monkeypatch.setenv(kc.CGROUP_ROOT_ENV, str(root))

    handle = kc.create_run_cgroup("sess-abc/123")
    assert handle is not None
    assert handle.path.is_dir()
    # cgroup id == inode of the cgroup directory (what bpf_get_current_cgroup_id returns)
    assert handle.cgroup_id == os.stat(handle.path).st_ino

    handle.adopt_pid(4242)
    assert (handle.path / "cgroup.procs").read_text().strip() == "4242"


def test_cleanup_removes_empty_cgroup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _fake_cgroup_root(tmp_path, unified=True)
    monkeypatch.setenv(kc.CGROUP_ROOT_ENV, str(root))
    handle = kc.create_run_cgroup("empty")
    assert handle is not None
    # On real cgroupfs the only entries are virtual files that rmdir ignores; an
    # empty cgroup dir on a normal FS is removed cleanly. cleanup never raises.
    handle.cleanup()
    assert not handle.path.exists()


def test_create_run_cgroup_none_when_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    legacy = _fake_cgroup_root(tmp_path, unified=False)
    monkeypatch.setenv(kc.CGROUP_ROOT_ENV, str(legacy))
    assert kc.create_run_cgroup("sess") is None


# ── daemon client ──────────────────────────────────────────────────────────────


class _FakeDaemon:
    """A one-shot AF_UNIX server that replays canned JSON-line responses."""

    def __init__(self, socket_path: Path, response: dict) -> None:
        self.socket_path = socket_path
        self.response = response
        self.received: dict | None = None
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(socket_path))
        self._server.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._server.accept()
        except OSError:
            return
        with conn:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            try:
                self.received = json.loads(line.decode("utf-8"))
            except ValueError:
                self.received = None
            conn.sendall(json.dumps(self.response).encode("utf-8") + b"\n")

    def close(self) -> None:
        self._server.close()


def test_register_session_roundtrip(sockdir: Path) -> None:
    sock = sockdir / "c.sock"
    daemon = _FakeDaemon(
        sock,
        {
            "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
            "ok": True,
            "method": "register_session",
            "session_id": "sess-1",
            "status": "registered",
        },
    )
    daemon.start()
    try:
        client = kc.KernelCaptureClient(sock)
        resp = client.register_session(
            session_id="sess-1",
            root_pid=1234,
            cgroup_id=99887766,
            ttl_seconds=3600,
            mission_id="mission-1",
            trace_id="trace-1",
        )
    finally:
        daemon.close()

    assert resp["status"] == "registered"
    assert daemon.received is not None
    assert daemon.received["method"] == "register_session"
    payload = daemon.received["register_session"]
    assert payload["session_id"] == "sess-1"
    assert payload["root_pid"] == 1234
    assert payload["cgroup_id"] == 99887766
    assert payload["event_classes"] == [kc.EVENT_CLASS_PROCESS_LIFECYCLE]
    assert payload["ttl_seconds"] == 3600


def test_client_raises_on_daemon_error(sockdir: Path) -> None:
    sock = sockdir / "c.sock"
    daemon = _FakeDaemon(
        sock,
        {
            "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
            "ok": False,
            "method": "register_session",
            "error": "cgroup_id is required",
        },
    )
    daemon.start()
    try:
        client = kc.KernelCaptureClient(sock)
        with pytest.raises(kc.DaemonProtocolError, match="cgroup_id is required"):
            client.register_session(session_id="s", root_pid=1, cgroup_id=1, ttl_seconds=60)
    finally:
        daemon.close()


def test_client_raises_unavailable_when_socket_missing(sockdir: Path) -> None:
    client = kc.KernelCaptureClient(sockdir / "absent.sock")
    with pytest.raises(kc.DaemonUnavailable):
        client.health()


def test_daemon_available_false_for_missing_socket(tmp_path: Path) -> None:
    assert kc.daemon_available(tmp_path / "nope.sock") is False


def test_register_session_validates_inputs(tmp_path: Path) -> None:
    client = kc.KernelCaptureClient(tmp_path / "x.sock")
    with pytest.raises(ValueError):
        client.register_session(session_id="", root_pid=1, cgroup_id=1, ttl_seconds=60)
    with pytest.raises(ValueError):
        client.register_session(session_id="s", root_pid=0, cgroup_id=1, ttl_seconds=60)
    with pytest.raises(ValueError):
        client.register_session(session_id="s", root_pid=1, cgroup_id=0, ttl_seconds=60)

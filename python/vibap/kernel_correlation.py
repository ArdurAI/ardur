"""Bridge from a launched agent's cgroup to the eBPF kernelcapture daemon.

This module is the Python client side of the Go kernelcapture daemon's Unix
socket control plane (``go/pkg/kernelcapture/daemon_socket_server.go`` +
``daemon_session_registry.go``). It lets ``ardur run`` close the
detect→session link: when the kernel detector sees the launched agent process,
the daemon already knows which governance session owns that cgroup.

Everything here degrades gracefully. On non-Linux hosts (no cgroup v2), or when
the daemon socket is absent, or when the unprivileged launcher cannot create a
cgroup, the helpers return ``None``/``unavailable`` results instead of raising.
The caller (``run_bridge``) still governs the agent through the hook/env path —
kernel correlation is an enhancement, never a hard dependency.

Wire protocol (one JSON object + ``\\n`` per message, JSON-line framed):

    request:  {"protocol_version": "kernelcapture.daemon.v1",
               "method": "register_session",
               "register_session": {"session_id": ..., "root_pid": ...,
                                    "cgroup_id": ..., "ttl_seconds": ...,
                                    "event_classes": ["process_lifecycle"]}}
    response: {"protocol_version": "kernelcapture.daemon.v1", "ok": true,
               "method": "register_session", "session_id": ..., "status": ...}

The daemon authenticates the peer at the socket layer (SO_PEERCRED on Linux),
so the client carries no token. Daemon-owned path fields and peer-identity
fields are rejected by the daemon if a client tries to smuggle them in; this
client never sends them.
"""

from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Must track go/pkg/kernelcapture/daemon_protocol.go.
DAEMON_PROTOCOL_VERSION = "kernelcapture.daemon.v1"
EVENT_CLASS_PROCESS_LIFECYCLE = "process_lifecycle"
MAX_TTL_SECONDS = 24 * 60 * 60

# Defaults mirror DaemonCustodyPlan.SocketPath in the Go daemon. Override with
# ARDUR_KERNELCAPTURE_SOCKET for tests or a non-default deployment.
DEFAULT_DAEMON_SOCKET = "/run/ardur/kernelcapture/control.sock"
DAEMON_SOCKET_ENV = "ARDUR_KERNELCAPTURE_SOCKET"

# cgroup v2 unified hierarchy root. Override with ARDUR_RUN_CGROUP_ROOT (used by
# tests to point at a writable temp dir without root, and by deployments that
# mount cgroupfs elsewhere).
DEFAULT_CGROUP_ROOT = "/sys/fs/cgroup"
CGROUP_ROOT_ENV = "ARDUR_RUN_CGROUP_ROOT"

# Subdirectory under the cgroup root that holds Ardur's per-run cgroups.
RUN_CGROUP_NAMESPACE = "ardur.run"


class DaemonProtocolError(RuntimeError):
    """Raised when the daemon rejects a request or replies malformed data."""


class DaemonUnavailable(RuntimeError):
    """Raised when the daemon socket cannot be reached at all."""


def daemon_socket_path() -> Path:
    """Resolve the kernelcapture daemon control socket path."""
    return Path(os.environ.get(DAEMON_SOCKET_ENV, DEFAULT_DAEMON_SOCKET)).expanduser()


def daemon_available(socket_path: Path | None = None) -> bool:
    """Return True only when a Unix-socket file exists at the daemon path.

    This is a cheap pre-check; an actual connect may still fail (and that is
    handled where it matters). We deliberately do not connect here so a missing
    daemon costs a single ``stat`` rather than a connection timeout.
    """
    path = socket_path or daemon_socket_path()
    try:
        return path.is_socket()
    except OSError:
        return False


class KernelCaptureClient:
    """Minimal JSON-line client for the kernelcapture daemon control socket."""

    def __init__(self, socket_path: Path | None = None, *, timeout_s: float = 2.0) -> None:
        self.socket_path = socket_path or daemon_socket_path()
        self.timeout_s = timeout_s

    def _roundtrip(self, request: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(request, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout_s)
                sock.connect(str(self.socket_path))
                sock.sendall(payload)
                chunks: list[bytes] = []
                while b"\n" not in b"".join(chunks):
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            raise DaemonUnavailable(f"kernelcapture daemon not reachable at {self.socket_path}: {exc}") from exc
        except OSError as exc:
            raise DaemonUnavailable(f"kernelcapture daemon I/O error at {self.socket_path}: {exc}") from exc

        raw = b"".join(chunks).split(b"\n", 1)[0]
        if not raw:
            raise DaemonProtocolError("empty response from kernelcapture daemon")
        try:
            response = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise DaemonProtocolError(f"malformed daemon response: {exc}") from exc
        if not isinstance(response, dict):
            raise DaemonProtocolError("daemon response was not a JSON object")
        if response.get("protocol_version") != DAEMON_PROTOCOL_VERSION:
            raise DaemonProtocolError(
                f"unexpected daemon protocol version: {response.get('protocol_version')!r}"
            )
        if not response.get("ok", False):
            raise DaemonProtocolError(str(response.get("error") or "daemon returned ok=false"))
        return response

    def health(self) -> dict[str, Any]:
        return self._roundtrip(
            {
                "protocol_version": DAEMON_PROTOCOL_VERSION,
                "method": "health",
                "health": {},
            }
        )

    def register_session(
        self,
        *,
        session_id: str,
        root_pid: int,
        cgroup_id: int,
        ttl_seconds: int,
        mission_id: str | None = None,
        trace_id: str | None = None,
        event_classes: tuple[str, ...] = (EVENT_CLASS_PROCESS_LIFECYCLE,),
    ) -> dict[str, Any]:
        if not session_id:
            raise ValueError("session_id is required")
        if root_pid <= 0:
            raise ValueError("root_pid must be positive")
        if cgroup_id <= 0:
            raise ValueError("cgroup_id must be positive")
        ttl = max(1, min(int(ttl_seconds), MAX_TTL_SECONDS))
        register: dict[str, Any] = {
            "session_id": session_id,
            "root_pid": int(root_pid),
            "cgroup_id": int(cgroup_id),
            "ttl_seconds": ttl,
            "event_classes": list(event_classes),
        }
        if mission_id:
            register["mission_id"] = mission_id
        if trace_id:
            register["trace_id"] = trace_id
        return self._roundtrip(
            {
                "protocol_version": DAEMON_PROTOCOL_VERSION,
                "method": "register_session",
                "register_session": register,
            }
        )

    def end_session(self, *, session_id: str, trace_id: str | None = None) -> dict[str, Any]:
        if not session_id:
            raise ValueError("session_id is required")
        end: dict[str, Any] = {"session_id": session_id}
        if trace_id:
            end["trace_id"] = trace_id
        return self._roundtrip(
            {
                "protocol_version": DAEMON_PROTOCOL_VERSION,
                "method": "end_session",
                "end_session": end,
            }
        )


# ── cgroup v2 helpers ──────────────────────────────────────────────────────────


def cgroup_root() -> Path:
    return Path(os.environ.get(CGROUP_ROOT_ENV, DEFAULT_CGROUP_ROOT)).expanduser()


def cgroup_v2_available(root: Path | None = None) -> bool:
    """True when the unified (v2) cgroup hierarchy is mounted at ``root``.

    The unified hierarchy exposes ``cgroup.controllers`` at its root; the legacy
    v1 layout does not. This file is absent on macOS/Windows, so the check is
    naturally False off Linux without a platform special-case.
    """
    base = root or cgroup_root()
    try:
        return (base / "cgroup.controllers").exists()
    except OSError:
        return False


@dataclass
class CgroupHandle:
    """A per-run cgroup the launcher created and is responsible for cleaning up."""

    path: Path
    cgroup_id: int

    def adopt_self(self) -> None:
        """Move the *current* process into this cgroup.

        Intended for use as a ``subprocess.Popen(preexec_fn=...)`` callback so
        the agent starts life inside the cgroup, before ``exec``. Writing the
        literal pid ``0`` to ``cgroup.procs`` is the kernel idiom for "the
        writing process". Best-effort: a failure here must not abort the launch,
        so the caller wraps it.
        """
        procs = self.path / "cgroup.procs"
        with procs.open("w", encoding="ascii") as handle:
            handle.write(f"{os.getpid()}\n")

    def adopt_pid(self, pid: int) -> None:
        procs = self.path / "cgroup.procs"
        with procs.open("w", encoding="ascii") as handle:
            handle.write(f"{int(pid)}\n")

    def cleanup(self) -> None:
        """Remove the cgroup directory (best effort).

        cgroup v2 only allows ``rmdir`` once the cgroup has no member
        processes; by the time the launcher calls this the agent has exited, so
        the directory is empty. Any failure is swallowed: a leaked empty cgroup
        is harmless and self-clearing on reboot.
        """
        try:
            self.path.rmdir()
        except OSError:
            pass


def create_run_cgroup(session_id: str, *, root: Path | None = None) -> CgroupHandle | None:
    """Create a dedicated cgroup for a run and return a handle, or None.

    Returns ``None`` (never raises) when cgroup v2 is unavailable or the
    unprivileged launcher cannot create the directory — the graceful-degradation
    contract the rest of the bridge relies on.

    The cgroup id reported to the daemon is the directory's inode number. In
    cgroup v2 the kernel's cgroup id *is* the inode of the cgroup directory in
    cgroupfs, which is exactly what eBPF ``bpf_get_current_cgroup_id()`` returns,
    so this value correlates 1:1 with kernel-side events.
    """
    base = root or cgroup_root()
    if not cgroup_v2_available(base):
        return None
    # Sanitize the session id into a single safe path segment.
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in session_id)[:128]
    namespace = base / RUN_CGROUP_NAMESPACE
    target = namespace / f"sess-{safe}"
    try:
        namespace.mkdir(parents=True, exist_ok=True)
        target.mkdir(parents=False, exist_ok=True)
        cgroup_id = os.stat(target).st_ino
    except OSError:
        return None
    if cgroup_id <= 0:
        return None
    return CgroupHandle(path=target, cgroup_id=cgroup_id)


# ── orchestration result ───────────────────────────────────────────────────────


@dataclass
class CorrelationResult:
    """Outcome of attempting to wire a run's cgroup to the kernel daemon."""

    available: bool
    reason: str
    method: str = "none"
    cgroup_id: int | None = None
    cgroup_path: str | None = None
    daemon_socket: str | None = None
    daemon_status: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "reason": self.reason,
            "method": self.method,
            "cgroup_id": self.cgroup_id,
            "cgroup_path": self.cgroup_path,
            "daemon_socket": self.daemon_socket,
            "daemon_status": self.daemon_status,
            "details": dict(self.details),
        }

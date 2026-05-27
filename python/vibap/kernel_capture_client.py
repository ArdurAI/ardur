"""Client for the Ardur kernel-capture daemon Unix socket protocol.

Communicates with the local eBPF process-lifecycle capture daemon over a
Unix-domain socket using the JSON-line protocol (kernelcapture.daemon.v1).
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field


class KernelCaptureError(Exception):
    """Base error for kernel-capture client operations."""


class KernelCaptureConnectionError(KernelCaptureError):
    """Raised when the client cannot connect to the daemon socket."""


class KernelCaptureProtocolError(KernelCaptureError):
    """Raised when the daemon returns a protocol-level error."""


@dataclass
class KernelCaptureSessionInfo:
    session_id: str
    mission_id: str = ""
    root_pid: int = 0
    cgroup_id: int = 0
    status: str = ""
    ttl_seconds: int = 0


@dataclass
class KernelCaptureClient:
    """Client for the kernel-capture daemon Unix socket protocol.

    Communicates over a Unix-domain socket using the JSON-line protocol
    defined by the ``kernelcapture.daemon.v1`` contract. All methods are
    safe to call when the daemon is unreachable — they return ``None`` or
    raise typed errors rather than crashing the proxy.

    Parameters:
        socket_path: Absolute path to the daemon's Unix socket.
        timeout: Connection and read timeout in seconds.
    """

    socket_path: str
    timeout: float = 5.0
    _protocol_version: str = field(default="kernelcapture.daemon.v1", init=False)

    def _send_request(self, request: dict) -> dict:
        """Send a JSON-line request and return the decoded response."""
        payload = json.dumps(request, separators=(",", ":")) + "\n"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(payload.encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise KernelCaptureProtocolError(
                        "daemon closed connection before sending complete response"
                    )
                buf += chunk
            line, _, _ = buf.partition(b"\n")
            return json.loads(line.decode("utf-8"))
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            raise KernelCaptureConnectionError(
                f"cannot connect to kernel-capture daemon at {self.socket_path}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise KernelCaptureProtocolError(
                f"invalid JSON response from kernel-capture daemon: {exc}"
            ) from exc
        finally:
            sock.close()

    def health(self) -> dict | None:
        """Check daemon health. Returns the decoded response or raises on error."""
        try:
            resp = self._send_request({
                "protocol_version": self._protocol_version,
                "method": "health",
                "health": {},
            })
        except (KernelCaptureConnectionError, KernelCaptureProtocolError, OSError):
            return None
        if not resp.get("ok"):
            raise KernelCaptureProtocolError(
                f"daemon health check failed: {resp.get('error', 'unknown')}"
            )
        return resp

    def register_session(
        self,
        session_id: str,
        *,
        mission_id: str = "",
        trace_id: str = "",
        root_pid: int = 0,
        pid_namespace_id: int = 0,
        cgroup_id: int = 0,
        ttl_seconds: int = 86400,
        event_classes: list[str] | None = None,
    ) -> KernelCaptureSessionInfo | None:
        """Register a session with the kernel-capture daemon.

        Returns session info on success, ``None`` if the daemon is unreachable.
        Raises :class:`KernelCaptureProtocolError` for daemon-side errors.
        """
        if event_classes is None:
            event_classes = ["process_lifecycle"]
        try:
            resp = self._send_request({
                "protocol_version": self._protocol_version,
                "method": "register_session",
                "register_session": {
                    "session_id": session_id,
                    "mission_id": mission_id,
                    "trace_id": trace_id,
                    "root_pid": root_pid,
                    "pid_namespace_id": pid_namespace_id,
                    "cgroup_id": cgroup_id,
                    "event_classes": event_classes,
                    "ttl_seconds": ttl_seconds,
                },
            })
        except (KernelCaptureConnectionError, OSError):
            return None
        if not resp.get("ok"):
            raise KernelCaptureProtocolError(
                f"register_session failed: {resp.get('error', 'unknown')}"
            )
        return KernelCaptureSessionInfo(
            session_id=resp.get("session_id", session_id),
            status=resp.get("status", ""),
        )

    def end_session(self, session_id: str) -> bool:
        """End a kernel-capture session. Returns True if daemon acknowledged."""
        try:
            resp = self._send_request({
                "protocol_version": self._protocol_version,
                "method": "end_session",
                "end_session": {"session_id": session_id},
            })
        except (KernelCaptureConnectionError, OSError):
            return False
        return resp.get("ok", False)

    def session_status(self, session_id: str) -> KernelCaptureSessionInfo | None:
        """Query a session's status from the daemon."""
        try:
            resp = self._send_request({
                "protocol_version": self._protocol_version,
                "method": "session_status",
                "session_status": {"session_id": session_id},
            })
        except (KernelCaptureConnectionError, OSError):
            return None
        if not resp.get("ok"):
            return None
        return KernelCaptureSessionInfo(
            session_id=resp.get("session_id", session_id),
            status=resp.get("status", ""),
        )

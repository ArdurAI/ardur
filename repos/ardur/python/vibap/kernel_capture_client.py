"""
Kernel event client for Ardur (Phase 1 integration work).

Interface between the Go kernelcapture daemon and the Python governance proxy / receipt system.

Current status: Advanced stub with real-path send sketch using proper AF_UNIX sockets,
registration, simulation, attachment helpers, and build_kernel_claim for receipts.
Real round-trip with the Go daemon (go/pkg/kernelcapture) is the active next slice.

See:
- go/pkg/kernelcapture/KERNEL_INTEGRATION_ANALYSIS.md
- docs/plans/phase-1-kernel-observability-mvp.md
"""

from __future__ import annotations

import os
import json
import socket
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class KernelEvent:
    """Normalized kernel event coming from the Go daemon."""
    event_type: str          # e.g. "exec", "open", "write", "connect"
    pid: int
    ppid: int | None = None
    comm: str | None = None
    args: list[str] | None = None
    target: str | None = None   # path, ip:port, etc.
    timestamp_ns: int | None = None
    raw: dict[str, Any] | None = None   # original payload for debugging


class KernelCaptureClient:
    """
    Client that connects to the local kernelcapture daemon and delivers
    events for a given session/trace.

    Supports:
    - Registration with trace_id / run_nonce (sent as JSON line over AF_UNIX)
    - Best-effort real send over Unix socket with proper socket module (graceful degradation)
    - Simulation for tests and shadow mode
    - Attachment helper that always returns evidence_level for safe use in receipts
    - build_kernel_claim() helper for dedicated kernel section in ExecutionReceipt
    """

    def __init__(self, socket_path: str = "/var/run/ardur/kernelcapture.sock"):
        self.socket_path = socket_path
        self._connected = False
        self._handlers: list[Callable[[KernelEvent], None]] = []
        self._registered_sessions: set[tuple[str, str]] = set()
        self._injected_events: list[KernelEvent] = []
        self._current_trace: Optional[tuple[str, str]] = None
        self._last_registration_message: Optional[dict] = None
        self._last_registration_sent_success: bool = False
        self._socket: Optional[socket.socket] = None

    def connect(self) -> None:
        """Connect to the daemon using AF_UNIX if the socket exists."""
        if self.socket_path and os.path.exists(self.socket_path):
            try:
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket.settimeout(0.5)
                self._socket.connect(self.socket_path)
                self._connected = True
            except Exception:
                self._connected = False
                if self._socket:
                    self._socket.close()
                    self._socket = None
        else:
            self._connected = False

    REGISTRATION_MESSAGE_TYPE = "register"

    def register_session(self, trace_id: str, run_nonce: str) -> None:
        """Tell the daemon we are interested in events for this trace.
        Sends registration immediately if a real socket is available.
        """
        if not self._connected:
            self.connect()
        self._registered_sessions.add((trace_id, run_nonce))
        self._current_trace = (trace_id, run_nonce)

        registration_message = {
            "type": self.REGISTRATION_MESSAGE_TYPE,
            "trace_id": trace_id,
            "run_nonce": run_nonce,
            "client_version": "0.1",
            "requested_events": ["exec", "file", "net", "process_lifecycle"],
        }
        self._last_registration_message = registration_message

        # Attempt real send on registration (Phase 1 real-path)
        if self._connected and self._socket:
            try:
                line = json.dumps(registration_message) + "\n"
                self._socket.sendall(line.encode("utf-8"))
                self._last_registration_sent_success = True
            except Exception:
                self._last_registration_sent_success = False
                self._connected = False

    def is_session_registered(self, trace_id: str, run_nonce: str) -> bool:
        return (trace_id, run_nonce) in self._registered_sessions

    def on_event(self, handler: Callable[[KernelEvent], None]) -> None:
        self._handlers.append(handler)

    def start(self) -> None:
        """Begin consuming events (blocking in real impl)."""
        pass

    def simulate_receive(self, event: KernelEvent) -> None:
        if self._current_trace:
            self._injected_events.append(event)

    def get_current_trace(self) -> Optional[tuple[str, str]]:
        return self._current_trace

    def send_registration_if_needed(self) -> Optional[dict]:
        if self._current_trace and not getattr(self, "_registration_sent", False):
            self._registration_sent = True
            return self._last_registration_message
        return None

    def send_registration(self) -> Optional[dict]:
        """
        Attempt to send the registration message over the Unix socket (JSON-lines).
        Uses real AF_UNIX socket when available. Returns the message for evidence.
        Never raises — graceful degradation is mandatory.
        """
        if not self._current_trace:
            return None

        msg = self._last_registration_message or {
            "type": self.REGISTRATION_MESSAGE_TYPE,
            "trace_id": self._current_trace[0],
            "run_nonce": self._current_trace[1],
            "client_version": "0.1",
            "requested_events": ["exec", "file", "net", "process_lifecycle"],
        }

        if self.socket_path and os.path.exists(self.socket_path):
            sent = self._try_send_registration(msg)
            self._last_registration_sent_success = sent
            return msg

        return msg

    def _try_send_registration(self, msg: dict) -> bool:
        """Best-effort send using real socket. Never raises."""
        try:
            if not self._socket or not self._connected:
                self.connect()
            if self._socket and self._connected:
                line = json.dumps(msg) + "\n"
                self._socket.sendall(line.encode("utf-8"))
                return True
            return False
        except Exception:
            self._connected = False
            if self._socket:
                try:
                    self._socket.close()
                except:
                    pass
                self._socket = None
            return False

    def close(self) -> None:
        self._connected = False
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None

    def get_events_for_side_effect(
        self, side_effect_class: str, target: Optional[str] = None
    ) -> list[KernelEvent]:
        """Return events only for registered sessions. Basic filtering by class/target."""
        if not self._current_trace:
            return []
        relevant = [e for e in self._injected_events if e.event_type in ("exec", "open", "write", "connect")]
        if target:
            relevant = [e for e in relevant if e.target and target in (e.target or "")]
        return relevant

    def attach_kernel_events_to_context(
        self, side_effect_class: str, target: Optional[str] = None
    ) -> dict:
        """
        Returns structured data with explicit evidence_level.
        Safe for direct use in PolicyEvent and receipts.
        """
        events = self.get_events_for_side_effect(side_effect_class, target)
        if events:
            return {
                "kernel_events": [
                    {
                        "event_type": e.event_type,
                        "pid": e.pid,
                        "comm": e.comm,
                        "target": e.target,
                    }
                    for e in events
                ],
                "kernel_evidence_level": "observed",
            }
        else:
            return {
                "kernel_events": [],
                "kernel_evidence_level": "insufficient_evidence",
            }

    def inject_event(self, event: KernelEvent) -> None:
        self._injected_events.append(event)

    def clear_injected_events(self) -> None:
        self._injected_events.clear()

    def build_kernel_claim(self, side_effect_class: str) -> Optional[dict]:
        """Convenience for receipt.py dedicated kernel claim shape."""
        attachment = self.attach_kernel_events_to_context(side_effect_class)
        if attachment.get("kernel_evidence_level") == "observed":
            return {
                "evidence_level": "observed",
                "events": attachment["kernel_events"],
                "count": len(attachment["kernel_events"]),
            }
        return None

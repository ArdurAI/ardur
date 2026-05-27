"""Tests for the kernel-capture daemon client."""

from __future__ import annotations

import json
from unittest import mock

import pytest

from vibap.kernel_capture_client import (
    KernelCaptureClient,
    KernelCaptureProtocolError,
    KernelCaptureSessionInfo,
)


def _mock_response_socket(resp: dict) -> mock.MagicMock:
    """Create a mock socket that returns a JSON-line response."""
    data = (json.dumps(resp, separators=(",", ":")) + "\n").encode("utf-8")
    sock = mock.MagicMock()
    sock.recv.side_effect = [data, b""]
    return sock


class TestKernelCaptureClientInit:
    def test_defaults(self):
        client = KernelCaptureClient(socket_path="/run/ardur/kernel-capture.sock")
        assert client.socket_path == "/run/ardur/kernel-capture.sock"
        assert client.timeout == 5.0

    def test_custom_timeout(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock", timeout=10.0)
        assert client.timeout == 10.0


class TestHealth:
    def test_health_ok(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = _mock_response_socket({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": True,
            "method": "health",
            "status": "healthy, 3 active sessions",
        })
        with mock.patch("socket.socket", return_value=sock):
            resp = client.health()
            assert resp is not None
            assert resp["ok"] is True
            assert "healthy" in resp["status"]

    def test_health_connection_refused_returns_none(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = mock.MagicMock()
        sock.connect.side_effect = ConnectionRefusedError("no daemon")
        with mock.patch("socket.socket", return_value=sock):
            assert client.health() is None

    def test_health_file_not_found_returns_none(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = mock.MagicMock()
        sock.connect.side_effect = FileNotFoundError("no socket")
        with mock.patch("socket.socket", return_value=sock):
            assert client.health() is None

    def test_health_daemon_error_raises(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = _mock_response_socket({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": False,
            "method": "health",
            "error": "internal error",
        })
        with mock.patch("socket.socket", return_value=sock):
            with pytest.raises(KernelCaptureProtocolError, match="internal error"):
                client.health()


class TestRegisterSession:
    def test_register_session_ok(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = _mock_response_socket({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": True,
            "method": "register_session",
            "session_id": "sess-abc",
            "status": "registered",
        })
        with mock.patch("socket.socket", return_value=sock):
            info = client.register_session("sess-abc", mission_id="mission-1", root_pid=12345)
            assert info is not None
            assert info.session_id == "sess-abc"
            assert info.status == "registered"

    def test_register_session_default_event_classes(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        captured_request: dict = {}

        def record_send(data):
            captured_request["raw"] = data

        sock = mock.MagicMock()
        sock.sendall.side_effect = record_send
        resp_data = (json.dumps({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": True,
            "method": "register_session",
            "session_id": "sess-1",
            "status": "registered",
        }, separators=(",", ":")) + "\n").encode("utf-8")
        sock.recv.side_effect = [resp_data, b""]
        with mock.patch("socket.socket", return_value=sock):
            client.register_session("sess-1")
        sent = json.loads(captured_request["raw"].decode("utf-8").strip())
        assert sent["register_session"]["event_classes"] == ["process_lifecycle"]

    def test_register_session_connection_refused_returns_none(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = mock.MagicMock()
        sock.connect.side_effect = ConnectionRefusedError()
        with mock.patch("socket.socket", return_value=sock):
            assert client.register_session("sess-1") is None

    def test_register_session_daemon_error_raises(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = _mock_response_socket({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": False,
            "method": "register_session",
            "session_id": "sess-1",
            "error": "kernelcapture: ttl_seconds must be between 1 and 86400",
        })
        with mock.patch("socket.socket", return_value=sock):
            with pytest.raises(KernelCaptureProtocolError, match="ttl_seconds"):
                client.register_session("sess-1", ttl_seconds=-1)


class TestEndSession:
    def test_end_session_ok(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = _mock_response_socket({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": True,
            "method": "end_session",
            "session_id": "sess-1",
            "status": "ended",
        })
        with mock.patch("socket.socket", return_value=sock):
            assert client.end_session("sess-1") is True

    def test_end_session_connection_refused_returns_false(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = mock.MagicMock()
        sock.connect.side_effect = ConnectionRefusedError()
        with mock.patch("socket.socket", return_value=sock):
            assert client.end_session("sess-1") is False

    def test_end_session_not_found_still_ok(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = _mock_response_socket({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": True,
            "method": "end_session",
            "session_id": "nonexistent",
            "status": "ended",
        })
        with mock.patch("socket.socket", return_value=sock):
            assert client.end_session("nonexistent") is True


class TestSessionStatus:
    def test_session_status_found(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = _mock_response_socket({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": True,
            "method": "session_status",
            "session_id": "sess-1",
            "status": "active, root_pid=12345, ttl=3600s",
        })
        with mock.patch("socket.socket", return_value=sock):
            info = client.session_status("sess-1")
            assert info is not None
            assert info.session_id == "sess-1"
            assert "active" in info.status

    def test_session_status_not_found_returns_none(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = _mock_response_socket({
            "protocol_version": "kernelcapture.daemon.v1",
            "ok": False,
            "method": "session_status",
            "session_id": "nonexistent",
            "error": "kernelcapture: session not found",
        })
        with mock.patch("socket.socket", return_value=sock):
            assert client.session_status("nonexistent") is None

    def test_session_status_connection_refused_returns_none(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = mock.MagicMock()
        sock.connect.side_effect = ConnectionRefusedError()
        with mock.patch("socket.socket", return_value=sock):
            assert client.session_status("sess-1") is None


class TestSessionInfo:
    def test_session_info_defaults(self):
        info = KernelCaptureSessionInfo(session_id="s1")
        assert info.session_id == "s1"
        assert info.mission_id == ""
        assert info.root_pid == 0


class TestMalformedResponses:
    def test_empty_response_raises(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = mock.MagicMock()
        sock.recv.return_value = b""
        with mock.patch("socket.socket", return_value=sock):
            with pytest.raises(KernelCaptureProtocolError, match="closed connection"):
                client._send_request({"method": "health", "health": {}})

    def test_invalid_json_raises(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = mock.MagicMock()
        sock.recv.side_effect = [b"not json\n", b""]
        with mock.patch("socket.socket", return_value=sock):
            with pytest.raises(KernelCaptureProtocolError, match="invalid JSON"):
                client._send_request({"method": "health", "health": {}})

    def test_socket_closes_after_send(self):
        client = KernelCaptureClient(socket_path="/tmp/kc.sock")
        sock = mock.MagicMock()
        sock.recv.side_effect = [b'{"ok":true}\n', b""]
        with mock.patch("socket.socket", return_value=sock):
            client._send_request({"method": "health", "health": {}})
        sock.close.assert_called_once()

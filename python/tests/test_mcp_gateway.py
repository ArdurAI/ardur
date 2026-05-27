"""Tests for the MCP gateway."""

from __future__ import annotations

import json
import subprocess
import sys
from io import StringIO

import pytest

from vibap.mcp_gateway import (
    MCPGatewayConfig,
    _MCPSessionContext,
    _build_jsonrpc_error,
    _build_jsonrpc_response,
    _is_notification,
    _read_json_line,
    _send_json,
    run_mcp_gateway,
)


class TestJSONRPCHelpers:
    def test_build_response(self):
        resp = _build_jsonrpc_response("req-1", {"tools": []})
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == "req-1"
        assert resp["result"] == {"tools": []}

    def test_build_error(self):
        err = _build_jsonrpc_error("req-2", -32601, "Method not found")
        assert err["jsonrpc"] == "2.0"
        assert err["id"] == "req-2"
        assert err["error"]["code"] == -32601
        assert err["error"]["message"] == "Method not found"

    def test_is_notification_no_id(self):
        assert _is_notification({"method": "notifications/initialized", "params": {}})

    def test_is_notification_null_id(self):
        assert _is_notification({"jsonrpc": "2.0", "id": None, "method": "x"})

    def test_is_not_request(self):
        assert not _is_notification({"jsonrpc": "2.0", "id": "x", "method": "y"})


class TestSendAndRead:
    def test_send_json_to_stringio(self):
        buf = StringIO()
        _send_json({"key": "value"}, buf)
        output = buf.getvalue().strip()
        assert '"key":"value"' in output

    def test_read_json_line(self):
        stream = StringIO('{"method":"test","id":"1"}\n{"method":"test2","id":"2"}\n')
        msg1 = _read_json_line(stream)
        assert msg1 == {"method": "test", "id": "1"}
        msg2 = _read_json_line(stream)
        assert msg2 == {"method": "test2", "id": "2"}

    def test_read_empty_line(self):
        stream = StringIO("\n")
        assert _read_json_line(stream) is None

    def test_read_eof(self):
        stream = StringIO("")
        assert _read_json_line(stream) is None

    def test_read_invalid_json(self):
        stream = StringIO("not json\n")
        assert _read_json_line(stream) is None


class TestSessionContext:
    def test_default_context(self):
        ctx = _MCPSessionContext(session_id="s1", passport_token="t1")
        assert ctx.session_id == "s1"
        assert ctx.passport_token == "t1"
        assert ctx.tools_manifest == []


class TestConfig:
    def test_config_creation(self):
        config = MCPGatewayConfig(
            upstream_command=["echo", "test"],
            proxy=None,
            private_key=None,
        )
        assert config.upstream_command == ["echo", "test"]
        assert config.session_id is None
        assert config.content_safety_config is None


class TestRunGatewayErrors:
    def test_no_upstream_command_returns_1(self):
        from vibap.mcp_gateway import MCPGatewayConfig

        config = MCPGatewayConfig(
            upstream_command=[],
            proxy=None,
            private_key=None,
        )
        assert run_mcp_gateway(config) == 1

    def test_upstream_not_found_returns_1(self):
        config = MCPGatewayConfig(
            upstream_command=["/nonexistent/path/definitely/not/real"],
            proxy=None,
            private_key=None,
        )
        assert run_mcp_gateway(config) == 1

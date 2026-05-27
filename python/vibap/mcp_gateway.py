"""MCP gateway — transparent stdio proxy that enforces Ardur policy on MCP tool calls.

Sits between an MCP client (e.g. Claude Code) and an upstream MCP server,
intercepting JSON-RPC ``tools/call`` messages and evaluating each against
the governance proxy before forwarding.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from .content_safety import ContentSafetyConfig, scan
from .metrics import metrics

_logger = logging.getLogger(__name__)

JSONRPC_VERSION = "2.0"
INTERCEPT_METHODS = {"tools/call"}
PASSTHROUGH_NOTIFICATIONS = {
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/roots/list_changed",
}


@dataclass
class MCPGatewayConfig:
    """Configuration for the MCP gateway."""

    upstream_command: list[str]
    proxy: Any  # GovernanceProxy — avoids circular import
    private_key: Any  # ec.EllipticCurvePrivateKey
    session_id: str | None = None
    passport_token: str | None = None
    content_safety_config: ContentSafetyConfig | None = None


@dataclass
class _MCPSessionContext:
    session_id: str
    passport_token: str
    tools_manifest: list[dict[str, Any]] = field(default_factory=list)


def _build_jsonrpc_response(id_: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": id_, "result": result}


def _build_jsonrpc_error(id_: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": id_,
        "error": {"code": code, "message": message},
    }


def _send_json(data: dict[str, Any], target: Any = None) -> None:
    """Write a JSON-RPC message to stdout (fd 1)."""
    line = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    out = target if target is not None else sys.stdout
    out.write(line + "\n")
    out.flush()


def _read_json_line(stream: Any) -> dict[str, Any] | None:
    """Read one JSON object from a line-oriented stream."""
    line = stream.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        _logger.warning("MCP gateway: failed to parse JSON-RPC line: %s", exc)
        return None


def _is_notification(msg: dict[str, Any]) -> bool:
    return "id" not in msg or msg.get("id") is None


def _handle_tools_call(
    request: dict[str, Any],
    config: MCPGatewayConfig,
    ctx: _MCPSessionContext,
    upstream_stdin: Any,
    upstream_stdout: Any,
) -> None:
    """Intercept a tools/call request, evaluate against policy, forward if permitted."""
    params = request.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    req_id = request.get("id")

    if not tool_name:
        _send_json(_build_jsonrpc_error(req_id, -32602, "Missing tool name"))
        return

    # Content safety pre-scan on inputs
    if config.content_safety_config:
        cs_result = scan(arguments, config.content_safety_config)
        if cs_result.alerts:
            metrics.content_safety_alerts_total.inc(
                category="input", mode=config.content_safety_config.mode
            )
        if not cs_result.safe and config.content_safety_config.mode_for(
            cs_result.alerts[0].category
        ) == "deny":
            _send_json(
                _build_jsonrpc_error(
                    req_id,
                    -32000,
                    f"Content safety blocked: {[a.rule_name for a in cs_result.alerts]}",
                )
            )
            return
        # If redact mode, use redacted arguments for the upstream call
        if cs_result.redacted_text is not None:
            arguments = cs_result.redacted_text  # For string args, but we keep dict

    # Evaluate against policy
    try:
        decision, reason = config.proxy.evaluate_tool_call(
            ctx.session_id, tool_name, arguments
        )
        metrics.mcp_tools_evaluated_total.inc(decision=decision.name.lower())
    except Exception as exc:
        _logger.error("Policy evaluation error for tool %s: %s", tool_name, exc)
        _send_json(
            _build_jsonrpc_error(
                req_id, -32000, f"Policy evaluation failed: {exc}"
            )
        )
        return

    if hasattr(decision, "name"):
        decision_name = decision.name
    else:
        decision_name = str(decision)

    if decision_name != "PERMIT":
        _send_json(
            _build_jsonrpc_error(
                req_id,
                -32001,
                f"Tool call denied by policy: {reason}",
            )
        )
        return

    # Forward to upstream
    _send_json(request, upstream_stdin)
    response = _read_json_line(upstream_stdout)

    if response is None:
        _send_json(
            _build_jsonrpc_error(req_id, -32603, "Upstream server closed connection")
        )
        return

    # Content safety post-scan on output
    if config.content_safety_config and "result" in response:
        cs_result = scan(response["result"], config.content_safety_config)
        if cs_result.alerts:
            metrics.content_safety_alerts_total.inc(
                category="output", mode=config.content_safety_config.mode
            )
        if not cs_result.safe:
            deny_categories = [
                a.category
                for a in cs_result.alerts
                if config.content_safety_config.mode_for(a.category) == "deny"
            ]
            if deny_categories:
                _send_json(
                    _build_jsonrpc_error(
                        req_id,
                        -32000,
                        f"Content safety blocked output: categories={deny_categories}",
                    )
                )
                return

    _send_json(response)


def _handle_initialize(
    request: dict[str, Any],
    upstream_stdin: Any,
    upstream_stdout: Any,
) -> dict[str, Any] | None:
    """Forward initialize request and return server capabilities."""
    _send_json(request, upstream_stdin)
    response = _read_json_line(upstream_stdout)
    if response is not None:
        _send_json(response)
    return response


def _handle_tools_list(
    request: dict[str, Any],
    ctx: _MCPSessionContext,
    upstream_stdin: Any,
    upstream_stdout: Any,
) -> None:
    """Forward tools/list and cache the manifest."""
    _send_json(request, upstream_stdin)
    response = _read_json_line(upstream_stdout)
    if response is None:
        return
    result = response.get("result", {})
    tools = result.get("tools", [])
    ctx.tools_manifest = tools
    _send_json(response)


def _message_loop(
    config: MCPGatewayConfig,
    ctx: _MCPSessionContext,
    upstream_stdin: Any,
    upstream_stdout: Any,
    upstream_process: subprocess.Popen,
) -> int:
    """Read JSON-RPC from stdin, route to handler or upstream."""
    reader = sys.stdin
    metrics.mcp_connections_total.inc(transport="stdio")

    for msg_str in reader:
        msg_str = msg_str.strip()
        if not msg_str:
            continue
        try:
            msg = json.loads(msg_str)
        except json.JSONDecodeError:
            _logger.warning("MCP gateway: unparseable input line")
            continue

        method = msg.get("method", "")

        # Pass through notifications without blocking
        if _is_notification(msg):
            if method in PASSTHROUGH_NOTIFICATIONS:
                _send_json(msg, upstream_stdin)
            continue

        metrics.mcp_messages_total.inc(method=method)

        if method == "initialize":
            _handle_initialize(msg, upstream_stdin, upstream_stdout)
        elif method == "tools/list":
            _handle_tools_list(msg, ctx, upstream_stdin, upstream_stdout)
        elif method in INTERCEPT_METHODS:
            _handle_tools_call(msg, config, ctx, upstream_stdin, upstream_stdout)
        else:
            # Passthrough: forward request, read response, send back
            _send_json(msg, upstream_stdin)
            response = _read_json_line(upstream_stdout)
            if response is not None:
                _send_json(response)
            else:
                _send_json(
                    _build_jsonrpc_error(
                        msg.get("id", None),
                        -32603,
                        "Upstream server closed connection",
                    )
                )

    return 0


def run_mcp_gateway(config: MCPGatewayConfig) -> int:
    """Run the MCP gateway, proxying between a client and an upstream server."""
    if not config.upstream_command:
        _logger.error("MCP gateway: upstream command is required")
        return 1

    # Start governance session if a passport token was provided
    session_id = config.session_id
    passport_token = config.passport_token
    if config.proxy is not None and passport_token and not session_id:
        try:
            session = config.proxy.start_session(passport_token)
            session_id = session.jti if hasattr(session, "jti") else session.get("jti", "")
            _logger.info("MCP gateway: started session %s", session_id)
        except Exception as exc:
            _logger.error("MCP gateway: failed to start session: %s", exc)
            return 1

    ctx = _MCPSessionContext(
        session_id=session_id or "",
        passport_token=passport_token or "",
    )

    # Spawn upstream MCP server
    env = os.environ.copy()
    try:
        proc = subprocess.Popen(
            config.upstream_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
            env=env,
        )
    except FileNotFoundError as exc:
        _logger.error("MCP gateway: upstream command not found: %s", exc)
        return 1
    except OSError as exc:
        _logger.error("MCP gateway: failed to start upstream: %s", exc)
        return 1

    try:
        exit_code = _message_loop(
            config, ctx, proc.stdin, proc.stdout, proc
        )
    except KeyboardInterrupt:
        exit_code = 0
    except BrokenPipeError:
        _logger.warning("MCP gateway: client disconnected")
        exit_code = 0
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            proc.kill()
            try:
                proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                pass

    return exit_code

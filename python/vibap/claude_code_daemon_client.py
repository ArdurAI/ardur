"""Client-side helpers for Claude Code hook daemon dispatch.

This module is intentionally independent of ``claude_code_hook`` and
``claude_code_daemon`` so the hook can attempt daemon dispatch without creating
a static import cycle with the daemon server module.
"""

from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

DAEMON_ENABLE_ENV_VAR = "ARDUR_CC_HOOK_DAEMON"
DAEMON_SOCKET_ENV_VAR = "ARDUR_CC_HOOK_DAEMON_SOCKET"
DAEMON_TIMEOUT_MS_ENV_VAR = "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS"

_DEFAULT_DAEMON_TIMEOUT_MS = 5.0
_DEFAULT_SOCKET_BASENAME = "claude-code-hook-daemon.sock"
_DEFAULT_SOCKET_DIRNAME = "daemon"


class _DaemonDispatchOutcome(Enum):
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    INVALID_RESPONSE = "invalid_response"
    SUCCEEDED = "succeeded"


@dataclass(frozen=True)
class _DaemonDispatchResult:
    output: dict[str, Any] | None
    outcome: _DaemonDispatchOutcome


def _vibap_home_dir() -> Path:
    explicit = os.environ.get("VIBAP_HOME", "").strip()
    if explicit:
        return Path(explicit).expanduser()

    local_home = Path.cwd() / ".vibap"
    if local_home.exists():
        return local_home

    return Path.home() / ".vibap"


def resolve_daemon_socket_path(*, home: Path | None = None) -> Path:
    """Resolve the daemon Unix socket path from env/defaults."""
    explicit = os.environ.get(DAEMON_SOCKET_ENV_VAR, "").strip()
    if explicit:
        return Path(explicit).expanduser()
    resolved_home = (home or _vibap_home_dir()).expanduser()
    return resolved_home / _DEFAULT_SOCKET_DIRNAME / _DEFAULT_SOCKET_BASENAME


def daemon_enabled() -> bool:
    """Return whether daemon-first dispatch is enabled for the hook client."""
    raw = os.environ.get(DAEMON_ENABLE_ENV_VAR, "1").strip().lower()
    return raw not in {"0", "false", "off", "no"}


def _daemon_timeout_seconds() -> float:
    raw = os.environ.get(DAEMON_TIMEOUT_MS_ENV_VAR, "").strip()
    if not raw:
        return _DEFAULT_DAEMON_TIMEOUT_MS / 1000.0
    try:
        return max(0.001, float(raw) / 1000.0)
    except ValueError:
        return _DEFAULT_DAEMON_TIMEOUT_MS / 1000.0


def _read_json_line(conn: socket.socket, *, max_bytes: int = 1_000_000) -> dict[str, Any]:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = conn.recv(8192)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("daemon response exceeded max_bytes")
        if b"\n" in chunk:
            break

    payload = b"".join(chunks)
    line = payload.splitlines()[0] if payload else b""
    if not line:
        raise ValueError("daemon returned empty payload")

    parsed = json.loads(line.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise TypeError("daemon payload must be a JSON object")
    return parsed


def _write_json_line(conn: socket.socket, payload: dict[str, Any]) -> None:
    message = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    conn.sendall(message.encode("utf-8"))


def is_valid_pre_tool_use_output(payload: object) -> bool:
    """Return whether payload is a valid Claude Code PreToolUse hook output."""
    if not isinstance(payload, dict):
        return False
    if "continue" in payload and isinstance(payload.get("continue"), bool):
        return True
    hook_specific = payload.get("hookSpecificOutput")
    if not isinstance(hook_specific, dict):
        return False
    if hook_specific.get("hookEventName") != "PreToolUse":
        return False
    if "permissionDecision" not in hook_specific:
        return True
    return isinstance(hook_specific.get("permissionDecision"), str)


def extract_valid_pre_tool_use_output(response: dict[str, Any]) -> dict[str, Any] | None:
    """Parse daemon response and return only valid PreToolUse output dicts.

    Supports both daemon wire contracts:
    - passthrough output dict
    - envelope {"ok": true, "output": <hook output dict>}
    """
    if not isinstance(response, dict):
        return None
    if "ok" in response:
        if response.get("ok") is not True:
            return None
        output = response.get("output")
    else:
        output = response
    if not isinstance(output, dict):
        return None
    if not is_valid_pre_tool_use_output(output):
        return None
    return dict(output)


def _dispatch_pre_tool_use_with_result(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> _DaemonDispatchResult:
    """Try daemon-backed PreToolUse handling and retain the fallback reason.

    The structured result is internal observability for tests and diagnostics;
    callers should continue to use :func:`dispatch_pre_tool_use` so daemon
    failures remain a transparent local-fallback boundary.
    """
    if not daemon_enabled():
        return _DaemonDispatchResult(None, _DaemonDispatchOutcome.DISABLED)

    payload = {
        "phase": "pre",
        "hook_input": dict(hook_input or {}),
        "keys_dir": str(keys_dir) if keys_dir is not None else None,
    }

    socket_path = resolve_daemon_socket_path()
    timeout_s = _daemon_timeout_seconds()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout_s)
            conn.connect(str(socket_path))
            _write_json_line(conn, payload)
            response = _read_json_line(conn)
    except TimeoutError:
        return _DaemonDispatchResult(None, _DaemonDispatchOutcome.TIMED_OUT)
    except OSError:
        return _DaemonDispatchResult(None, _DaemonDispatchOutcome.UNAVAILABLE)
    except (ValueError, TypeError):
        return _DaemonDispatchResult(None, _DaemonDispatchOutcome.INVALID_RESPONSE)

    output = extract_valid_pre_tool_use_output(response)
    if output is None:
        return _DaemonDispatchResult(None, _DaemonDispatchOutcome.INVALID_RESPONSE)
    return _DaemonDispatchResult(output, _DaemonDispatchOutcome.SUCCEEDED)


def dispatch_pre_tool_use(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any] | None:
    """Try daemon-backed PreToolUse handling with transparent local fallback.

    Returns a hook output dict when daemon dispatch succeeds. Returns ``None``
    when daemon mode is disabled, unavailable, timed out, or yields an invalid
    response so callers can safely fall back to local handling.
    """

    return _dispatch_pre_tool_use_with_result(hook_input, keys_dir=keys_dir).output

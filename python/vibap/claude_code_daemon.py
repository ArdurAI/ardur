"""Daemon-first utilities for Claude Code PreToolUse hooks.

This module provides a minimal Unix-socket daemon contract for the
PreToolUse hook path plus a benchmark helper used by gated latency tests.

The CLI hook process can attempt daemon dispatch first and fall back to the
existing in-process handler when no daemon is running.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import socket
import stat
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

DAEMON_ENABLE_ENV_VAR = "ARDUR_CC_HOOK_DAEMON"
DAEMON_SOCKET_ENV_VAR = "ARDUR_CC_HOOK_DAEMON_SOCKET"
DAEMON_TIMEOUT_MS_ENV_VAR = "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS"

_DEFAULT_DAEMON_TIMEOUT_MS = 5.0
_DEFAULT_SOCKET_BASENAME = "claude-code-hook-daemon.sock"
_DEFAULT_SOCKET_DIRNAME = "daemon"
_PRIVATE_SOCKET_DIR_MODE = 0o700
_PRIVATE_SOCKET_MODE = 0o600

# Installed native fast path command for Claude Code PreToolUse hooks.
_NATIVE_PRE_TOOL_USE_COMMAND_BASENAME = "claude-code-pre_tool_use"
_NATIVE_PRE_TOOL_USE_COMMAND_MODE = 0o700


def _native_pre_tool_use_client_c_source() -> str:
    """Return C source for the low-latency Unix-socket hook client.

    The generated binary reads hook JSON from stdin, dispatches one request to
    the local daemon Unix socket, validates the response shape (passthrough
    output dict or ``{"ok": true, "output": ...}`` envelope), writes only the
    hook output dict to stdout, and exits non-zero on any malformed/error
    daemon payload so callers can safely fall back to local Python handling.
    """
    return r'''
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_PAYLOAD_BYTES 1048576
#define MAX_RESPONSE_BYTES 1048576

static const char *skip_ws(const char *p) {
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

static int token_matches_bool(const char *p, const char *token, size_t token_len) {
    if (strncmp(p, token, token_len) != 0) {
        return 0;
    }
    char next = p[token_len];
    return next == '\0' || next == ',' || next == '}' || isspace((unsigned char)next);
}

static int parse_json_string(const char *p, const char **end) {
    if (!p || *p != '"') {
        return 0;
    }
    p++;
    while (*p) {
        if (*p == '\\') {
            p++;
            if (!*p) {
                return 0;
            }
            p++;
            continue;
        }
        if (*p == '"') {
            if (end) {
                *end = p + 1;
            }
            return 1;
        }
        p++;
    }
    return 0;
}

static int find_matching_bracket(const char *start, char open, char close, const char **end) {
    if (!start || *start != open) {
        return 0;
    }

    int depth = 0;
    int in_string = 0;
    int escaped = 0;

    for (const char *p = start; *p; p++) {
        char c = *p;
        if (in_string) {
            if (escaped) {
                escaped = 0;
                continue;
            }
            if (c == '\\') {
                escaped = 1;
                continue;
            }
            if (c == '"') {
                in_string = 0;
            }
            continue;
        }

        if (c == '"') {
            in_string = 1;
            continue;
        }
        if (c == open) {
            depth++;
            continue;
        }
        if (c == close) {
            depth--;
            if (depth == 0) {
                if (end) {
                    *end = p + 1;
                }
                return 1;
            }
            continue;
        }
    }

    return 0;
}

static int skip_json_value(const char *p, const char **end) {
    if (!p || !*p) {
        return 0;
    }
    if (*p == '"') {
        return parse_json_string(p, end);
    }
    if (*p == '{') {
        return find_matching_bracket(p, '{', '}', end);
    }
    if (*p == '[') {
        return find_matching_bracket(p, '[', ']', end);
    }

    const char *q = p;
    while (*q && !isspace((unsigned char)*q) && *q != ',' && *q != '}' && *q != ']') {
        q++;
    }
    if (q == p) {
        return 0;
    }
    if (end) {
        *end = q;
    }
    return 1;
}

static int find_object_key_value(
    const char *object_start,
    const char *key,
    const char **value_start,
    const char **value_end
) {
    if (!object_start || *object_start != '{' || !key) {
        return 0;
    }

    const char *object_end = NULL;
    if (!find_matching_bracket(object_start, '{', '}', &object_end)) {
        return 0;
    }

    size_t key_len = strlen(key);
    const char *p = object_start + 1;
    while (1) {
        p = skip_ws(p);
        if (!*p || p >= object_end) {
            return 0;
        }
        if (*p == '}') {
            return 0;
        }

        const char *key_end = NULL;
        if (!parse_json_string(p, &key_end) || key_end > object_end) {
            return 0;
        }

        size_t parsed_key_len = (size_t)(key_end - p - 2);
        int key_match = parsed_key_len == key_len && strncmp(p + 1, key, key_len) == 0;

        p = skip_ws(key_end);
        if (*p != ':') {
            return 0;
        }
        p = skip_ws(p + 1);

        const char *val_end = NULL;
        if (!skip_json_value(p, &val_end) || val_end > object_end) {
            return 0;
        }

        if (key_match) {
            if (value_start) {
                *value_start = p;
            }
            if (value_end) {
                *value_end = val_end;
            }
            return 1;
        }

        p = skip_ws(val_end);
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p == '}') {
            return 0;
        }
        return 0;
    }
}

static int has_valid_hook_output(const char *s) {
    if (!s) {
        return 0;
    }

    const char *root = skip_ws(s);
    if (*root != '{') {
        return 0;
    }

    const char *root_end = NULL;
    if (!find_matching_bracket(root, '{', '}', &root_end)) {
        return 0;
    }
    if (*skip_ws(root_end) != '\0') {
        return 0;
    }

    const char *continue_value = NULL;
    const char *continue_end = NULL;
    if (find_object_key_value(root, "continue", &continue_value, &continue_end)) {
        if (token_matches_bool(continue_value, "true", 4) || token_matches_bool(continue_value, "false", 5)) {
            return 1;
        }
        return 0;
    }

    const char *hook_value = NULL;
    const char *hook_end = NULL;
    if (!find_object_key_value(root, "hookSpecificOutput", &hook_value, &hook_end)) {
        return 0;
    }
    if (*hook_value != '{') {
        return 0;
    }

    const char *event_value = NULL;
    const char *event_end = NULL;
    if (!find_object_key_value(hook_value, "hookEventName", &event_value, &event_end)) {
        return 0;
    }
    if ((size_t)(event_end - event_value) != 12 || strncmp(event_value, "\"PreToolUse\"", 12) != 0) {
        return 0;
    }

    const char *permission_value = NULL;
    const char *permission_end = NULL;
    if (!find_object_key_value(hook_value, "permissionDecision", &permission_value, &permission_end)) {
        return 1;
    }
    if (*permission_value != '"') {
        return 0;
    }
    const char *parsed_end = NULL;
    if (!parse_json_string(permission_value, &parsed_end)) {
        return 0;
    }
    return parsed_end == permission_end;
}

static int read_stdin_payload(char **buffer, size_t *payload_len) {
    char *buf = (char *)malloc(MAX_PAYLOAD_BYTES + 2);
    if (!buf) {
        return 3;
    }

    size_t length = 0;
    while (length < MAX_PAYLOAD_BYTES) {
        ssize_t n = read(STDIN_FILENO, buf + length, MAX_PAYLOAD_BYTES - length);
        if (n < 0) {
            free(buf);
            return 4;
        }
        if (n == 0) {
            break;
        }
        length += (size_t)n;
    }

    if (length == 0) {
        free(buf);
        return 5;
    }

    if (buf[length - 1] != '\n') {
        buf[length++] = '\n';
    }

    *buffer = buf;
    *payload_len = length;
    return 0;
}

static int connect_and_roundtrip(
    const char *socket_path,
    int timeout_ms,
    const char *payload,
    size_t payload_len,
    char **response,
    size_t *response_len
) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return 6;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close(fd);
        return 7;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 8;
    }

    size_t sent = 0;
    while (sent < payload_len) {
        ssize_t n = write(fd, payload + sent, payload_len - sent);
        if (n <= 0) {
            close(fd);
            return 9;
        }
        sent += (size_t)n;
    }

    char *buf = (char *)malloc(MAX_RESPONSE_BYTES + 1);
    if (!buf) {
        close(fd);
        return 10;
    }

    size_t out_len = 0;
    while (out_len < MAX_RESPONSE_BYTES) {
        ssize_t n = read(fd, buf + out_len, MAX_RESPONSE_BYTES - out_len);
        if (n < 0) {
            free(buf);
            close(fd);
            return 11;
        }
        if (n == 0) {
            break;
        }
        out_len += (size_t)n;
        if (memchr(buf, '\n', out_len)) {
            break;
        }
    }

    close(fd);

    if (out_len == 0) {
        free(buf);
        return 12;
    }

    size_t line_len = 0;
    while (line_len < out_len && buf[line_len] != '\n' && buf[line_len] != '\r') {
        line_len++;
    }
    buf[line_len] = '\0';

    *response = buf;
    *response_len = line_len;
    return 0;
}

static int extract_envelope_output(char *response, char **emit_ptr, size_t *emit_len) {
    const char *root = skip_ws(response);
    if (*root != '{') {
        return 13;
    }

    const char *root_end = NULL;
    if (!find_matching_bracket(root, '{', '}', &root_end)) {
        return 16;
    }
    if (*skip_ws(root_end) != '\0') {
        return 16;
    }

    const char *ok_value = NULL;
    const char *ok_end = NULL;
    if (!find_object_key_value(root, "ok", &ok_value, &ok_end)) {
        return 14;
    }
    if (!token_matches_bool(ok_value, "true", 4)) {
        return 17;
    }

    const char *output_value = NULL;
    const char *output_end = NULL;
    if (!find_object_key_value(root, "output", &output_value, &output_end)) {
        return 14;
    }
    if (*output_value != '{') {
        return 15;
    }

    *emit_ptr = (char *)output_value;
    *emit_len = (size_t)(output_end - output_value);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }

    const char *socket_path = argv[1];
    int timeout_ms = 5;
    if (argc >= 3) {
        timeout_ms = atoi(argv[2]);
        if (timeout_ms < 1) {
            timeout_ms = 1;
        }
    }

    char *payload = NULL;
    size_t payload_len = 0;
    int rc = read_stdin_payload(&payload, &payload_len);
    if (rc != 0) {
        return rc;
    }

    char *response = NULL;
    size_t response_len = 0;
    rc = connect_and_roundtrip(socket_path, timeout_ms, payload, payload_len, &response, &response_len);
    free(payload);
    if (rc != 0) {
        return rc;
    }

    const char *root = skip_ws(response);
    if (response_len == 0 || *root != '{') {
        free(response);
        return 13;
    }

    const char *root_end = NULL;
    if (!find_matching_bracket(root, '{', '}', &root_end)) {
        free(response);
        return 16;
    }
    if (*skip_ws(root_end) != '\0') {
        free(response);
        return 16;
    }

    const char *ok_value = NULL;
    const char *ok_end = NULL;
    int has_ok = find_object_key_value(root, "ok", &ok_value, &ok_end);

    char *emit = response;
    size_t emit_len = response_len;

    if (has_ok) {
        if (!token_matches_bool(ok_value, "true", 4)) {
            free(response);
            return 17;
        }
        rc = extract_envelope_output(response, &emit, &emit_len);
        if (rc != 0) {
            free(response);
            return rc;
        }
    }

    char saved = emit[emit_len];
    emit[emit_len] = '\0';
    int valid = has_valid_hook_output(emit);
    emit[emit_len] = saved;

    if (!valid) {
        free(response);
        return 18;
    }

    if (write(STDOUT_FILENO, emit, emit_len) < 0) {
        free(response);
        return 19;
    }
    if (write(STDOUT_FILENO, "\n", 1) < 0) {
        free(response);
        return 20;
    }

    free(response);
    return 0;
}
'''


def resolve_native_pre_tool_use_command_path(home: Path | None = None) -> Path:
    """Resolve the native PreToolUse command path under VIBAP_HOME."""
    resolved_home = (home or _vibap_home_dir()).expanduser()
    return resolved_home / _NATIVE_PRE_TOOL_USE_COMMAND_BASENAME


def _native_pre_tool_use_command_stamp_path(command_path: Path) -> Path:
    return command_path.parent / f"{command_path.name}.sha256"


def _native_pre_tool_use_source_digest(source_text: str) -> str:
    return hashlib.sha256(source_text.encode("utf-8")).hexdigest()


def _native_pre_tool_use_binary_digest(command_path: Path) -> str | None:
    try:
        payload = command_path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(payload).hexdigest()


def _native_pre_tool_use_stamp_payload(*, source_digest: str, binary_digest: str) -> str:
    return json.dumps(
        {
            "source_sha256": source_digest,
            "binary_sha256": binary_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _native_pre_tool_use_stamp_matches(command_path: Path, expected_source_digest: str) -> bool:
    stamp_path = _native_pre_tool_use_command_stamp_path(command_path)
    if not stamp_path.is_file():
        return False
    try:
        recorded = stamp_path.read_text(encoding="utf-8").strip()
    except OSError:
        return False

    try:
        manifest = json.loads(recorded)
    except json.JSONDecodeError:
        # Legacy source-only stamp format cannot prove executable provenance.
        return False
    if not isinstance(manifest, dict):
        return False

    source_digest = manifest.get("source_sha256")
    binary_digest = manifest.get("binary_sha256")
    if not isinstance(source_digest, str) or not isinstance(binary_digest, str):
        return False
    if source_digest != expected_source_digest:
        return False

    observed_binary_digest = _native_pre_tool_use_binary_digest(command_path)
    if observed_binary_digest is None:
        return False
    return observed_binary_digest == binary_digest


_KNOWN_CC_BASENAMES = frozenset({"cc", "clang", "gcc", "clang++", "g++"})


def _candidate_native_compilers() -> list[str]:
    candidates: list[str] = []
    explicit = os.environ.get("ARDUR_HOOK_CC", "").strip()
    if explicit:
        basename = os.path.basename(explicit.rstrip("/"))
        if basename in _KNOWN_CC_BASENAMES:
            candidates.append(explicit)
    candidates.extend(["cc", "clang", "gcc"])

    discovered: list[str] = []
    for candidate in candidates:
        if candidate in discovered:
            continue
        if os.path.isabs(candidate):
            if os.access(candidate, os.X_OK):
                discovered.append(candidate)
            continue
        resolved = shutil.which(candidate)
        if resolved:
            discovered.append(resolved)
    return discovered


def install_native_pre_tool_use_command(
    *,
    home: Path | None = None,
    force: bool = False,
) -> Path | None:
    """Build/install the native PreToolUse daemon client under ``VIBAP_HOME``.

    Returns the executable path when compilation succeeds. Returns ``None`` when
    no suitable C compiler is available or compilation fails.
    """
    target = resolve_native_pre_tool_use_command_path(home)
    source_text = _native_pre_tool_use_client_c_source()
    expected_digest = _native_pre_tool_use_source_digest(source_text)
    target_stamp = _native_pre_tool_use_command_stamp_path(target)

    if not force and target.is_file() and os.access(target, os.X_OK):
        if _native_pre_tool_use_stamp_matches(target, expected_digest):
            return target

    target.parent.mkdir(parents=True, exist_ok=True)

    for compiler in _candidate_native_compilers():
        with tempfile.TemporaryDirectory(prefix="ardur-hook-native-build-") as tmpdir:
            tmp_root = Path(tmpdir)
            src = tmp_root / "pre_tool_use_client.c"
            out = tmp_root / "pre_tool_use_client"
            stamp = tmp_root / "pre_tool_use_client.sha256"
            src.write_text(source_text, encoding="utf-8")

            cmd = [
                compiler,
                "-O3",
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-o",
                str(out),
                str(src),
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0 or not out.is_file():
                continue

            out.chmod(_NATIVE_PRE_TOOL_USE_COMMAND_MODE)
            binary_digest = _native_pre_tool_use_binary_digest(out)
            if binary_digest is None:
                continue
            stamp.write_text(
                _native_pre_tool_use_stamp_payload(
                    source_digest=expected_digest,
                    binary_digest=binary_digest,
                )
                + "\n",
                encoding="utf-8",
            )
            out.replace(target)
            target.chmod(_NATIVE_PRE_TOOL_USE_COMMAND_MODE)
            stamp.replace(target_stamp)
            return target

    return None


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
    if not is_valid_pre_tool_use_output(output):
        return None
    return dict(output)


def dispatch_pre_tool_use(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any] | None:
    """Try daemon-backed PreToolUse handling.

    Returns a hook output dict when daemon dispatch succeeds.
    Returns None when daemon mode is disabled, unavailable, or yields an
    invalid response so callers can safely fall back to local handling.
    """
    if not daemon_enabled():
        return None

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
    except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return None

    return extract_valid_pre_tool_use_output(response)


def _nearest_rank(values: list[float], percentile: int) -> float:
    ordered = sorted(values)
    rank = math.ceil((percentile / 100) * len(ordered))
    return ordered[min(max(rank - 1, 0), len(ordered) - 1)]


def benchmark_pre_tool_use_hot_path(
    *,
    hook_input: dict[str, Any],
    keys_dir: Path | None = None,
    iterations: int = 7,
) -> dict[str, Any]:
    """Benchmark the in-daemon PreToolUse hot path.

    Returns a dict containing ``durations_ms`` plus basic percentile summary.
    """
    from .claude_code_hook import handle_pre_tool_use

    n = max(1, int(iterations))
    base_input = dict(hook_input or {})

    durations_ms: list[float] = []
    for i in range(n):
        call_input = dict(base_input)
        call_input.setdefault("session_id", "claude-code-daemon-bench")
        call_input.setdefault("hook_event_name", "PreToolUse")
        call_input.setdefault("tool_name", "Read")
        call_input.setdefault("tool_input", {"file_path": f"/tmp/ardur-daemon-bench-{i}.txt"})
        call_input["tool_use_id"] = f"ardur-daemon-bench-{i}"

        started = time.perf_counter()
        handle_pre_tool_use(call_input, keys_dir=keys_dir)
        durations_ms.append((time.perf_counter() - started) * 1000.0)

    return {
        "durations_ms": durations_ms,
        "median_ms": statistics.median(durations_ms),
        "p95_ms": _nearest_rank(durations_ms, 95),
        "p99_ms": _nearest_rank(durations_ms, 99),
    }


def _unlink_only_if_socket(path: Path) -> None:
    """Unlink a stale Unix socket, failing closed for any other file type.

    The daemon may need to clean up a socket left behind by a prior crashed
    process, but the socket path is still a filesystem boundary. Never remove a
    regular file, directory, FIFO, symlink, or any other non-socket object that
    happens to occupy the configured path.
    """
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(mode):
        raise RuntimeError(f"refusing to unlink non-socket daemon path: {path}")
    path.unlink()


def _ensure_private_socket_parent(path: Path) -> None:
    """Ensure the daemon socket parent directory is private to this user."""
    parent = path.parent
    created_parent = False
    try:
        parent.mkdir(parents=True, exist_ok=False, mode=_PRIVATE_SOCKET_DIR_MODE)
        created_parent = True
    except FileExistsError:
        created_parent = False
    except OSError as exc:
        raise RuntimeError(f"failed to create daemon socket parent directory {parent}: {exc}") from exc

    if created_parent:
        try:
            os.chmod(parent, _PRIVATE_SOCKET_DIR_MODE)
        except OSError as exc:
            raise RuntimeError(
                "failed to enforce private daemon socket directory permissions "
                f"for newly created parent {parent}: {exc}"
            ) from exc

    if not parent.is_dir():
        raise RuntimeError(f"daemon socket parent is not a directory: {parent}")

    mode = stat.S_IMODE(parent.stat().st_mode)
    if mode != _PRIVATE_SOCKET_DIR_MODE:
        raise RuntimeError(
            "daemon socket parent must already be private "
            f"(expected {oct(_PRIVATE_SOCKET_DIR_MODE)}, got {oct(mode)} for {parent}); "
            "refusing to chmod a pre-existing parent directory"
        )


def _socket_path_is_active(path: Path, *, timeout_s: float) -> bool:
    """Return True when a Unix socket path is currently accepting connections."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(max(timeout_s, 0.001))
        try:
            probe.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError):
            return False
        except TimeoutError:
            # Treat timeout as active/contended to avoid unlinking a live socket.
            return True
        except OSError:
            return False
    return True


def _cleanup_stale_socket(path: Path, *, timeout_s: float) -> None:
    """Unlink only dead Unix sockets; refuse to clobber active daemon sockets."""
    if not (path.exists() or path.is_symlink()):
        return
    if _socket_path_is_active(path, timeout_s=timeout_s):
        raise RuntimeError(f"refusing to replace active daemon socket: {path}")
    _unlink_only_if_socket(path)


def _handle_daemon_request(request: dict[str, Any], *, default_keys_dir: Path | None = None) -> dict[str, Any]:
    from .claude_code_hook import handle_pre_tool_use

    # Passthrough protocol: the request itself is the hook input payload.
    # This is used by lightweight shell clients (the Claude wrapper hook)
    # to avoid JSON envelope construction overhead on the hot path.
    raw_phase = request.get("phase")
    if raw_phase is None:
        hook_input = dict(request or {})
        if not hook_input.get("tool_name") or not hook_input.get("tool_input"):
            raise RuntimeError("passthrough request missing required hook fields (tool_name, tool_input)")
        output = handle_pre_tool_use(hook_input, keys_dir=default_keys_dir)
        if not is_valid_pre_tool_use_output(output):
            raise RuntimeError("pre hook handler returned invalid passthrough output")
        return output

    # Envelope protocol: richer request/response contract used by the Python
    # client helper dispatch_pre_tool_use().
    phase = str(raw_phase).strip()
    if phase != "pre":
        return {"ok": False, "error": f"unsupported phase: {phase or '<empty>'}"}

    hook_input = dict(request.get("hook_input", {}) or {})
    request_keys_dir = request.get("keys_dir")
    keys_dir: Path | None
    if request_keys_dir:
        keys_dir = Path(str(request_keys_dir)).expanduser()
    else:
        keys_dir = default_keys_dir

    output = handle_pre_tool_use(hook_input, keys_dir=keys_dir)
    if not is_valid_pre_tool_use_output(output):
        return {"ok": False, "error": "invalid pre hook output"}
    return {"ok": True, "output": output}


def serve_pre_tool_use_daemon(
    *,
    socket_path: Path | None = None,
    keys_dir: Path | None = None,
    max_requests: int | None = None,
) -> int:
    """Serve PreToolUse requests over a local Unix socket.

    The daemon is intentionally minimal:
    - one JSON request per connection
    - one JSON response per connection
    - pre-phase only
    """
    resolved_socket = (socket_path or resolve_daemon_socket_path()).expanduser()
    timeout_s = _daemon_timeout_seconds()

    _ensure_private_socket_parent(resolved_socket)
    _cleanup_stale_socket(resolved_socket, timeout_s=timeout_s)

    requests_handled = 0

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        old_umask = os.umask(0o177)
        try:
            server.bind(str(resolved_socket))
        finally:
            os.umask(old_umask)
        os.chmod(resolved_socket, _PRIVATE_SOCKET_MODE)
        server.listen(64)
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(timeout_s)
                try:
                    request = _read_json_line(conn)
                    response = _handle_daemon_request(request, default_keys_dir=keys_dir)
                except Exception as exc:  # noqa: BLE001 - daemon boundary
                    response = {"ok": False, "error": f"daemon request failed: {type(exc).__name__}: {exc}"}
                try:
                    _write_json_line(conn, response)
                except OSError:
                    # Hook clients can timeout and close early; dropped response
                    # writes should not crash the daemon.
                    pass

            requests_handled += 1
            if max_requests is not None and requests_handled >= max_requests:
                break

    return requests_handled


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="vibap.claude_code_daemon")
    parser.add_argument(
        "--socket-path",
        type=Path,
        default=None,
        help=f"unix socket path (default: ${DAEMON_SOCKET_ENV_VAR} or derived VIBAP_HOME path)",
    )
    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=None,
        help="keys directory passed to hook handler (default: hook resolver)",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=None,
        help="optional request cap for tests/smoke runs",
    )
    args = parser.parse_args(argv)

    serve_pre_tool_use_daemon(
        socket_path=args.socket_path,
        keys_dir=args.keys_dir,
        max_requests=args.max_requests,
    )
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))

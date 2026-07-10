#!/usr/bin/env python3
"""Run a local-only, no-key Ardur governance demonstration.

The child proxy is intentionally bound to 127.0.0.1 with TLS and bearer auth
disabled. It uses ephemeral signing keys and state, then verifies the signed
attestation before deleting all temporary material. This is a first-run demo,
not a production launch mode.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    from vibap.attestation import verify_attestation
    from vibap.passport import load_existing_public_key
except ImportError as exc:  # pragma: no cover - exercised by the user-facing guard
    raise SystemExit(
        "Ardur is not installed for this Python interpreter. "
        "Run 'python -m pip install -e python/' first."
    ) from exc


STARTUP_TIMEOUT_S = 20.0
REQUEST_TIMEOUT_S = 3.0
LOOPBACK_HOST = "127.0.0.1"


class DemoError(RuntimeError):
    """A concise failure that is safe to show to a first-time tester."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Ardur's local-only no-key MVP demonstration."
    )
    parser.add_argument(
        "--port",
        type=int,
        help="loopback port to use; defaults to an available local port",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=STARTUP_TIMEOUT_S,
        help=f"startup deadline in seconds (default: {STARTUP_TIMEOUT_S:g})",
    )
    args = parser.parse_args(argv)
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.timeout_s <= 0:
        parser.error("--timeout-s must be positive")
    return args


def find_available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((LOOPBACK_HOST, 0))
        return int(listener.getsockname()[1])


def resolve_ardur_binary() -> str:
    venv_binary = Path(sys.executable).with_name("ardur")
    if venv_binary.is_file():
        return str(venv_binary)
    path_binary = shutil.which("ardur")
    if path_binary:
        return path_binary
    raise DemoError(
        "The installed 'ardur' command was not found for this Python interpreter. "
        "Run 'python -m pip install -e python/' first."
    )


def post_json(base_url: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_S) as response:
            if response.status != 200:
                raise DemoError(f"{path} returned HTTP {response.status}")
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise DemoError(f"{path} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise DemoError(f"{path} could not reach the local proxy") from exc
    except json.JSONDecodeError as exc:
        raise DemoError(f"{path} returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise DemoError(f"{path} returned a non-object JSON response")
    return result


def require_string(payload: dict[str, Any], field_name: str, path: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise DemoError(f"{path} did not return a non-empty {field_name}")
    return value


def wait_for_health(
    base_url: str, process: subprocess.Popen[str], deadline: float
) -> None:
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise DemoError(
                f"the local proxy exited before becoming healthy (exit {process.returncode})"
            )
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=0.5) as response:
                payload = json.loads(response.read().decode("utf-8"))
                if response.status == 200 and payload.get("status") == "ok":
                    return
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            # Startup races are expected; the bounded loop raises at the deadline.
            pass
        time.sleep(0.1)
    raise DemoError(
        "the local proxy did not become healthy before the startup deadline"
    )


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def assert_decision(response: dict[str, Any], expected: str) -> None:
    actual = response.get("decision")
    if actual != expected:
        raise DemoError(f"expected {expected} but the local proxy returned {actual!r}")


def run_demo(*, port: int, timeout_s: float) -> float:
    started = time.monotonic()
    base_url = f"http://{LOOPBACK_HOST}:{port}"
    ardur_binary = resolve_ardur_binary()

    with tempfile.TemporaryDirectory(prefix="ardur-no-key-mvp-") as temp_root_text:
        temp_root = Path(temp_root_text)
        keys_dir = temp_root / "keys"
        state_dir = temp_root / "state"
        log_path = temp_root / "audit.jsonl"
        child_env = os.environ.copy()
        child_env.pop("VIBAP_API_TOKEN", None)
        command = [
            ardur_binary,
            "start",
            "--host",
            LOOPBACK_HOST,
            "--port",
            str(port),
            "--keys-dir",
            str(keys_dir),
            "--state-dir",
            str(state_dir),
            "--log-path",
            str(log_path),
            "--no-tls",
            "--no-require-auth",
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=child_env,
        )
        try:
            wait_for_health(base_url, process, started + timeout_s)
            print("PASS  local proxy started on loopback without bearer auth")

            issue = post_json(
                base_url,
                "/issue",
                {
                    "mission": {
                        "agent_id": "no-key-mvp-demo",
                        "mission": "demonstrate local governance decisions",
                        "allowed_tools": ["read_file", "delete_file"],
                        "forbidden_tools": ["delete_file"],
                        "max_tool_calls": 2,
                    }
                },
            )
            passport = require_string(issue, "token", "/issue")
            print("PASS  issued a local mission passport")

            session = post_json(base_url, "/session/start", {"token": passport})
            session_id = require_string(session, "session_id", "/session/start")
            print("PASS  started a governed session")

            permit = post_json(
                base_url,
                "/evaluate",
                {
                    "session_id": session_id,
                    "tool_name": "read_file",
                    "arguments": {"path": "/tmp/ardur-no-key-demo.txt"},
                },
            )
            assert_decision(permit, "PERMIT")
            print("PASS  read_file returned PERMIT")

            deny = post_json(
                base_url,
                "/evaluate",
                {
                    "session_id": session_id,
                    "tool_name": "delete_file",
                    "arguments": {"path": "/tmp/ardur-no-key-demo.txt"},
                },
            )
            assert_decision(deny, "DENY")
            print("PASS  delete_file returned DENY")

            ended = post_json(base_url, "/session/end", {"session_id": session_id})
            attestation = require_string(ended, "attestation_token", "/session/end")
            claims = verify_attestation(attestation, load_existing_public_key(keys_dir))
            if claims.get("permits") != 1 or claims.get("denials") != 1:
                raise DemoError(
                    "the signed attestation did not record one PERMIT and one DENY"
                )
            print("PASS  signed attestation verified with the temporary public key")
        finally:
            stop_process(process)

    return time.monotonic() - started


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    port = args.port if args.port is not None else find_available_loopback_port()
    print("=== Ardur no-key local MVP demo ===")
    print("Loopback only. Authentication and TLS are disabled for this temporary demo.")
    try:
        elapsed_s = run_demo(port=port, timeout_s=args.timeout_s)
    except DemoError as exc:
        print(f"FAIL  {exc}")
        return 1
    print(
        f"Completed in {elapsed_s:.1f}s. Temporary keys, state, and audit data were removed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
